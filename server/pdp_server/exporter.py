"""Alert export to the customer's SOC: syslog (CEF over UDP/TCP/TLS) and/or an HTTPS JSON webhook.

Runs as its own service (compose profile `export`), because it is the only server component that needs network
egress. It forwards every alert once, in id order, keeping its cursor in the platform database (`kv` table), so a
restart neither loses nor duplicates alerts (at-least-once: a batch whose delivery failed is retried).

Configuration (environment):
  PDP_EXPORT_SYSLOG          udp://host:514 | tcp://host:514 | tls://host:6514     (CEF, one message per alert)
  PDP_EXPORT_SYSLOG_CA       CA bundle for tls:// (default: system trust store)
  PDP_EXPORT_WEBHOOK         https://siem.example/ingest                            (JSON array of alerts per POST)
  PDP_EXPORT_WEBHOOK_TOKEN   sent as "Authorization: Bearer <token>"
  PDP_EXPORT_WEBHOOK_CA      CA bundle for the webhook (default: system trust store)
  PDP_EXPORT_FROM            "now" (default: only alerts created after the first start) or "all"
  PDP_EXPORT_INTERVAL        poll seconds (default 5)
Console URL used in the alert link: PDP_CONSOLE_URL (default https://localhost).

Run: python -m pdp_server.exporter
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import db

CURSOR_KEY = "export_cursor"
BATCH = 500


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, flush=True)


# ---------------------------------------------------------------------------------------------------- formats
def _cef_escape(v: str, header: bool = False) -> str:
    v = str(v).replace("\\", "\\\\")
    if header:
        return v.replace("|", "\\|")
    return v.replace("=", "\\=").replace("\n", " ").replace("\r", " ")


def severity(fused: float, layer: str | None = None) -> int:
    """CEF severity 0-10. Deterministic detections (novel program, information-flow rule) are high severity by
    construction; learned-only alerts are graded by the fused score (threshold units: 1.0 = alert threshold)."""
    if layer == "rules":
        return max(8, _sev(fused))
    if layer in ("novelty", "corroborated"):
        return max(7, _sev(fused))
    return _sev(fused)


def _sev(fused: float) -> int:
    if fused >= 4:
        return 9
    if fused >= 2:
        return 7
    if fused >= 1.5:
        return 6
    return 5


def to_cef(a: dict, console: str) -> str:
    kind = {"subject": "process", "file": "file", "netflow": "socket"}.get(a["ntype"], a["ntype"])
    layer = a.get("layer") or "learned"
    name = a.get("reason") or f"Anomalous {kind} in provenance graph"
    ts = int(a["window_start_ns"] // 1_000_000)
    ext = {
        "rt": ts, "dvchost": a.get("hostname") or "", "deviceExternalId": a["endpoint_id"], "cs1Label": "endpoint", "cs1": a["endpoint"],
        "cs2Label": "entity", "cs2": a["label"][:1023], "cs3Label": "entityType", "cs3": kind,
        "cn1Label": "fusedScore", "cn1": round(float(a["fused"]), 3), "cn2Label": "detector1", "cn2": round(float(a["r1"]), 3),
        "cn3Label": "detector2", "cn3": round(float(a["r2"]), 3), "externalId": a["id"], "cs4Label": "status", "cs4": a["status"],
        "cs5Label": "link", "cs5": f"{console}/#/alerts/{a['id']}", "cs6Label": "layer", "cs6": f"{layer}/{a.get('rule') or ''}",
    }
    if kind == "process":
        ext["sproc"] = a["label"].split(" ", 1)[-1][:255]
    elif kind == "file":
        ext["filePath"] = a["label"].split(" ", 1)[-1][:1023]
    elif kind == "socket":
        parts = a["label"].split()
        if len(parts) >= 3:
            ext["dst"], ext["dpt"] = parts[1], parts[2]
    body = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items())
    return (f"CEF:0|PDP|Provenance Detection Platform|0.3|pdp-alert-{kind}|{_cef_escape(name, True)}|{severity(float(a['fused']), layer)}|{body}")


def to_json(a: dict, console: str) -> dict:
    return {"id": a["id"], "endpoint_id": a["endpoint_id"], "endpoint": a["endpoint"], "hostname": a.get("hostname"),
            "window_start": datetime.fromtimestamp(a["window_start_ns"] / 1e9, tz=timezone.utc).isoformat(),
            "window_start_ns": a["window_start_ns"], "entity": {"uuid": a["node_uuid"], "type": a["ntype"], "label": a["label"]},
            "layer": a.get("layer") or "learned", "rule": a.get("rule"), "reason": a.get("reason"),
            "scores": {"fused": a["fused"], "detector1": a["r1"], "detector2": a["r2"]}, "severity": severity(float(a["fused"]), a.get("layer")),
            "status": a["status"], "link": f"{console}/#/alerts/{a['id']}"}


# ---------------------------------------------------------------------------------------------------- sinks
class SyslogSink:
    def __init__(self, url: str, ca: str | None = None):
        u = urlparse(url)
        if u.scheme not in ("udp", "tcp", "tls") or not u.hostname:
            raise ValueError(f"PDP_EXPORT_SYSLOG must be udp://, tcp:// or tls://host:port, got {url!r}")
        self.scheme, self.host, self.port, self.ca = u.scheme, u.hostname, u.port or (6514 if u.scheme == "tls" else 514), ca
        self.sock = None
        self.me = socket.gethostname()

    def _connect(self):
        if self.scheme == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return
        s = socket.create_connection((self.host, self.port), timeout=10)
        if self.scheme == "tls":
            ctx = ssl.create_default_context(cafile=self.ca) if self.ca else ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=self.host)
        self.sock = s

    def send(self, alerts: list[dict], console: str):
        if self.sock is None:
            self._connect()
        try:
            for a in alerts:
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                msg = f"<{8 * 13 + (2 if float(a['fused']) >= 2 else 4)}>1 {ts} {self.me} pdp - alert - {to_cef(a, console)}"   # RFC 5424, facility 13 (log audit)
                data = msg.encode()
                if self.scheme == "udp":
                    self.sock.sendto(data[:65000], (self.host, self.port))
                else:
                    self.sock.sendall(f"{len(data)} ".encode() + data)           # RFC 6587 octet counting
        except OSError:
            try:
                self.sock.close()
            finally:
                self.sock = None
            raise


class WebhookSink:
    def __init__(self, url: str, token: str | None = None, ca: str | None = None):
        if not url.startswith(("https://", "http://")):
            raise ValueError("PDP_EXPORT_WEBHOOK must be an http(s) URL")
        self.url, self.token = url, token
        self.ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()

    def send(self, alerts: list[dict], console: str):
        body = json.dumps({"source": "pdp", "alerts": [to_json(a, console) for a in alerts]}, default=str).encode()
        h = {"Content-Type": "application/json", "User-Agent": "pdp-exporter/0.2"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.url, data=body, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=30, context=self.ctx if self.url.startswith("https") else None) as r:
            if r.status >= 300:
                raise OSError(f"webhook HTTP {r.status}")


def sinks_from_env() -> list:
    out = []
    if os.environ.get("PDP_EXPORT_SYSLOG"):
        out.append(SyslogSink(os.environ["PDP_EXPORT_SYSLOG"], os.environ.get("PDP_EXPORT_SYSLOG_CA")))
    if os.environ.get("PDP_EXPORT_WEBHOOK"):
        out.append(WebhookSink(os.environ["PDP_EXPORT_WEBHOOK"], os.environ.get("PDP_EXPORT_WEBHOOK_TOKEN"), os.environ.get("PDP_EXPORT_WEBHOOK_CA")))
    return out


# ---------------------------------------------------------------------------------------------------- loop
def get_cursor() -> int | None:
    with db.conn() as c:
        r = db.q(c, "SELECT v FROM kv WHERE k=%s", (CURSOR_KEY,), one=True)
    return int(r["v"]) if r else None


def set_cursor(v: int) -> None:
    with db.conn() as c:
        db.q(c, "INSERT INTO kv (k, v, updated_at) VALUES (%s, %s, now()) ON CONFLICT (k) DO UPDATE SET v=excluded.v, updated_at=now()", (CURSOR_KEY, json.dumps(v)))


def fetch(after: int, limit: int = BATCH) -> list[dict]:
    with db.conn() as c:
        rows = db.q(c, "SELECT a.id, a.endpoint_id, e.name AS endpoint, e.hostname, a.window_start_ns, a.node_uuid, a.ntype, a.label, "
                       "a.fused, a.r1, a.r2, a.status, a.layer, a.rule, a.reason FROM alerts a JOIN endpoints e ON e.id=a.endpoint_id WHERE a.id > %s ORDER BY a.id LIMIT %s", (after, limit))
    for r in rows:
        r["endpoint_id"] = str(r["endpoint_id"])
    return rows


def run_once(sinks: list, console: str) -> int:
    cur = get_cursor()
    if cur is None:
        if os.environ.get("PDP_EXPORT_FROM", "now") == "all":
            cur = 0
        else:
            with db.conn() as c:
                cur = int(db.q(c, "SELECT coalesce(max(id), 0) AS m FROM alerts", one=True)["m"])
        set_cursor(cur)
    rows = fetch(cur)
    if not rows:
        return 0
    for s in sinks:
        s.send(rows, console)
    set_cursor(rows[-1]["id"])
    return len(rows)


def main():
    sinks = sinks_from_env()
    console = os.environ.get("PDP_CONSOLE_URL", "https://localhost").rstrip("/")
    interval = float(os.environ.get("PDP_EXPORT_INTERVAL", 5))
    if not sinks:
        log("exporter: no sink configured (PDP_EXPORT_SYSLOG / PDP_EXPORT_WEBHOOK); idle")
    else:
        log(f"exporter: {[type(s).__name__ for s in sinks]}")
    delay = interval
    while True:
        if sinks:
            try:
                n = run_once(sinks, console)
                if n:
                    log(f"exported {n} alerts")
                delay = interval if n < BATCH else 0
            except Exception as e:  # noqa - a sink outage must not stop the loop; the batch is retried
                log(f"export failed, will retry: {e}")
                delay = min(max(delay * 2, interval), 300)
        time.sleep(delay)


if __name__ == "__main__":
    main()
