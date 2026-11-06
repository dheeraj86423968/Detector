"""Notifications: each organisation's admins configure channels in the console; the notifier service delivers.

Channels (table notify_channels, org-scoped):
  email     comma-separated addresses; sent through the operator's SMTP relay (PDP_SMTP_URL, PDP_SMTP_FROM)
  slack     Slack incoming-webhook URL
  teams     Microsoft Teams incoming-webhook / workflow URL
  webhook   any HTTPS endpoint; JSON body signed with HMAC-SHA256 (X-PDP-Signature) when a secret is set
  syslog    udp:// | tcp:// | tls://host:port, CEF (the SOC's SIEM)

Events: `incident` (a new incident at or above the channel's minimum severity, or an incident escalating to it),
`agent_offline` (an endpoint stops reporting for PDP_NOTIFY_OFFLINE_MIN minutes, and when it is back),
`agent_health` (the collector lost events, the spool size cap dropped events). With `every_alert` a webhook or
syslog channel also receives every single alert (SIEM feed, at least once, in order; replaces the server-wide
exporter for that organisation).
0.6 security events (pdp_server.posture): `detection_weakened` (a setting or allow-list change that weakens detection,
with who and the reason given; an endpoint's detection posture worsening; a notification channel silenced) and
`response_action` (a process stopped, an endpoint isolated or released). Severity high, sent regardless of the
channel's minimum severity, to every channel subscribed to them or to `incident`.

Delivery never floods: at most PDP_NOTIFY_MAX_PER_HOUR messages per channel and hour; the rest are logged as
suppressed and summarised in one digest per hour. Every send is logged once per (channel, key) in notify_log.

Hosted service safety: channel URLs are resolved before every send and refused when they point to a private,
loopback, link-local or otherwise internal address (the server must not become a way into its own network);
PDP_NOTIFY_ALLOW_PRIVATE=1 lifts that for on-premises installs and tests. Plain http:// needs PDP_NOTIFY_ALLOW_HTTP=1.

Service: python -m pdp_server.notify   (compose service "notifier", the only backend service with egress)
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import re
import smtplib
import socket
import ssl
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlparse, unquote

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from . import db
from .access import admin

router = APIRouter()

KINDS = ("email", "slack", "teams", "webhook", "syslog")
EVENTS = ("incident", "agent_offline", "agent_health", "weekly", "platform")   # platform: operator alerts (internal organisation)
EVENTS += ("detection_weakened", "response_action")    # 0.6: security events (pdp_server.posture)
SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
MAX_PER_HOUR = int(os.environ.get("PDP_NOTIFY_MAX_PER_HOUR", "20"))
OFFLINE_MIN = float(os.environ.get("PDP_NOTIFY_OFFLINE_MIN", "10"))
INTERVAL = float(os.environ.get("PDP_NOTIFY_INTERVAL", "10"))


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, flush=True)


def console_url() -> str:
    u = os.environ.get("PDP_CONSOLE_URL")
    if u:
        return u.rstrip("/")
    h = os.environ.get("PDP_PUBLIC_HOSTNAME")
    return f"https://{h}" if h else "https://localhost"


# ================================================================================================ target safety
class TargetError(ValueError):
    pass


def _allow_private() -> bool:
    return os.environ.get("PDP_NOTIFY_ALLOW_PRIVATE") == "1"


def resolve_public(host: str, port: int) -> list[str]:
    """Addresses of `host`, refusing any that is not a public unicast address (unless private targets are allowed)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise TargetError(f"cannot resolve {host}: {e.strerror or e}")
    addrs = sorted({i[4][0] for i in infos})
    if not addrs:
        raise TargetError(f"cannot resolve {host}")
    if not _allow_private():
        for a in addrs:
            ip = ipaddress.ip_address(a.split("%")[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                raise TargetError(f"{host} resolves to an internal address ({a}); only public destinations are allowed")
    return addrs


def validate(kind: str, target: str) -> str:
    """Normalised target, or TargetError. Network reachability is checked again before every send."""
    target = (target or "").strip()
    if kind == "email":
        addrs = [a.strip() for a in re.split(r"[,;\s]+", target) if a.strip()]
        if not addrs or len(addrs) > 10 or not all(EMAIL_RE.match(a) for a in addrs):
            raise TargetError("enter one to ten e-mail addresses, separated by commas")
        return ", ".join(addrs)
    if kind == "syslog":
        u = urlparse(target)
        if u.scheme not in ("udp", "tcp", "tls") or not u.hostname:
            raise TargetError("syslog target must look like tls://siem.example.com:6514 (udp://, tcp:// or tls://)")
        return target
    u = urlparse(target)
    if u.scheme != "https" and not (u.scheme == "http" and os.environ.get("PDP_NOTIFY_ALLOW_HTTP") == "1"):
        raise TargetError("the URL must start with https://")
    if not u.hostname or u.username or u.password:
        raise TargetError("enter a full URL without user name or password")
    if len(target) > 2000:
        raise TargetError("URL too long")
    return target


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to a pre-resolved (checked) address, certificate and SNI still for the host name: a DNS answer that
    changes between the check and the connection (rebinding) cannot redirect the request."""

    def __init__(self, host, port, ip, **kw):
        super().__init__(host, port, **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, **kw):
        super().__init__(host, port, **kw)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


def post_json(url: str, payload: dict, headers: dict | None = None, timeout: float = 15) -> int:
    u = urlparse(validate("webhook", url))
    port = u.port or (443 if u.scheme == "https" else 80)
    ip = resolve_public(u.hostname, port)[0]
    body = json.dumps(payload, default=str).encode()
    h = {"Content-Type": "application/json", "User-Agent": "pdp-notifier/1", **(headers or {})}
    if callable(h.get("X-PDP-Signature")):
        h["X-PDP-Signature"] = h["X-PDP-Signature"](body)
    if u.scheme == "https":
        conn = _PinnedHTTPS(u.hostname, port, ip, timeout=timeout, context=ssl.create_default_context())
    else:
        conn = _PinnedHTTP(u.hostname, port, ip, timeout=timeout)
    try:
        conn.request("POST", (u.path or "/") + (f"?{u.query}" if u.query else ""), body=body, headers=h)
        r = conn.getresponse()
        r.read(2000)
        if r.status >= 300:
            raise OSError(f"HTTP {r.status} from {u.hostname}")
        return r.status
    finally:
        conn.close()


# ================================================================================================ messages
SEV_COLOR = {"critical": "B3261E", "high": "D9480F", "medium": "E8A317", "low": "6B7280"}


def incident_message(inc: dict, escalated_from: str | None = None) -> dict:
    link = f"{console_url()}/#/incidents/{inc['id']}"
    sev = inc["severity"].capitalize()
    first = datetime.fromtimestamp(inc["first_ns"] / 1e9, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    what = ", ".join(b["label"] for b in inc.get("behaviours") or []) or ", ".join(inc.get("tactics") or [])
    lines = [f"{inc['title']}", "", f"Severity: {sev}" + (f" (was {escalated_from})" if escalated_from else ""),
             f"Endpoint: {inc['endpoint_name']}", f"First seen: {first}", f"Alerts: {inc['alerts']}"]
    if what:
        lines.append(f"Recognised: {what}")
    lines += ["", f"Open in the console: {link}"]
    return {"event": "incident", "subject": f"[M.D Lab] {sev}: {inc['title']} ({inc['endpoint_name']})", "text": "\n".join(lines),
            "title": inc["title"], "severity": inc["severity"], "link": link,
            "data": {"type": "incident", "incident_id": inc["id"], "severity": inc["severity"], "escalated_from": escalated_from,
                     "title": inc["title"], "endpoint": {"id": inc["endpoint_id"], "name": inc["endpoint_name"]}, "first_seen": first,
                     "alerts": inc["alerts"], "behaviours": [b["label"] for b in inc.get("behaviours") or []],
                     "tactics": inc.get("tactics") or [], "status": inc.get("status"), "link": link}}


def endpoint_message(event: str, ep: dict, what: str, severity: str = "high") -> dict:
    link = f"{console_url()}/#/endpoints/{ep['id']}"
    title = f"{ep['name']}: {what}"
    return {"event": event, "subject": f"[M.D Lab] {title}", "text": f"{title}\n\nOpen in the console: {link}", "title": title,
            "severity": severity, "link": link,
            "data": {"type": event, "endpoint": {"id": str(ep["id"]), "name": ep["name"], "hostname": ep.get("hostname")}, "detail": what, "link": link}}


# ================================================================================================ delivery
def _smtp_send(to: str, subject: str, text: str) -> None:
    url = os.environ.get("PDP_SMTP_URL")
    if not url:
        raise OSError("e-mail is not set up on this server (PDP_SMTP_URL)")
    u = urlparse(url)
    sender = os.environ.get("PDP_SMTP_FROM") or f"PDP <pdp@{os.environ.get('PDP_PUBLIC_HOSTNAME', 'localhost')}>"
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to, subject
    msg.set_content(text)
    ctx = ssl.create_default_context()
    if u.scheme == "smtps":
        s = smtplib.SMTP_SSL(u.hostname, u.port or 465, timeout=20, context=ctx)
    else:
        s = smtplib.SMTP(u.hostname, u.port or 587, timeout=20)
        if u.scheme != "smtp+plain":      # STARTTLS unless explicitly plain (local relay / tests)
            s.starttls(context=ctx)
    try:
        if u.username:
            s.login(unquote(u.username), unquote(u.password or ""))
        s.send_message(msg)
    finally:
        try:
            s.quit()
        except Exception:  # noqa
            pass


def _syslog_send(target: str, lines: list[str]) -> None:
    from .exporter import SyslogSink
    u = urlparse(target)
    resolve_public(u.hostname, u.port or 514)
    sink = SyslogSink(target)
    sink._connect()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    try:
        for line in lines:
            data = f"<{8 * 13 + 4}>1 {ts} {sink.me} pdp - event - {line}".encode()
            if sink.scheme == "udp":
                sink.sock.sendto(data[:65000], (sink.host, sink.port))
            else:
                sink.sock.sendall(f"{len(data)} ".encode() + data)
    finally:
        try:
            sink.sock.close()
        except Exception:  # noqa
            pass


def _cef_event(m: dict) -> str:
    from .exporter import _cef_escape
    sev = {"low": 3, "medium": 5, "high": 8, "critical": 10}.get(m.get("severity", "high"), 8)
    d = m["data"]
    ext = {"rt": int(time.time() * 1000), "cs1Label": "endpoint", "cs1": (d.get("endpoint") or {}).get("name", ""),
           "deviceExternalId": (d.get("endpoint") or {}).get("id", ""), "cs5Label": "link", "cs5": m["link"], "msg": m["text"][:1000]}
    if d.get("incident_id"):
        ext["externalId"] = d["incident_id"]
    body = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items())
    return f"CEF:0|M.D Lab|M.D Lab Detector|0.3|pdp-{m['event']}|{_cef_escape(m['title'], True)}|{sev}|{body}"


def deliver(ch: dict, m: dict) -> None:
    """Send one message on one channel; raises on failure."""
    k = ch["kind"]
    if k == "email":
        _smtp_send(ch["target"], m["subject"], m["text"])
    elif k == "slack":
        icon = {"critical": ":red_circle:", "high": ":large_orange_circle:", "medium": ":large_yellow_circle:"}.get(m["severity"], ":white_circle:")
        post_json(ch["target"], {"text": f"{icon} *{m['severity'].capitalize()}* {m['title']}\n<{m['link']}|Open in the M.D Lab Detector console>"})
    elif k == "teams":
        post_json(ch["target"], {"@type": "MessageCard", "@context": "http://schema.org/extensions", "summary": m["subject"],
                                 "themeColor": SEV_COLOR.get(m["severity"], "6B7280"), "title": m["subject"],
                                 "text": m["text"].replace("\n", "<br>"),
                                 "potentialAction": [{"@type": "OpenUri", "name": "Open in the M.D Lab Detector console",
                                                      "targets": [{"os": "default", "uri": m["link"]}]}]})
    elif k == "webhook":
        post_json(ch["target"], {"source": "pdp", "event": m["event"], **m["data"]}, _signed(ch, m["event"]))
    elif k == "syslog":
        _syslog_send(ch["target"], [_cef_event(m)])
    else:
        raise OSError(f"unknown channel kind {k}")


def _signed(ch: dict, event: str) -> dict:
    ts = str(int(time.time()))
    h = {"X-PDP-Event": event, "X-PDP-Timestamp": ts}
    if ch.get("secret"):
        key = ch["secret"].encode()
        h["X-PDP-Signature"] = lambda body: "sha256=" + hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return h


def deliver_alerts(ch: dict, alerts: list[dict]) -> None:
    """SIEM feed (every_alert): the exporter's formats."""
    from .exporter import to_cef, to_json
    con = console_url()
    if ch["kind"] == "syslog":
        _syslog_send(ch["target"], [to_cef(a, con) for a in alerts])
    elif ch["kind"] == "webhook":
        post_json(ch["target"], {"source": "pdp", "event": "alerts", "alerts": [to_json(a, con) for a in alerts]}, _signed(ch, "alerts"))


# ================================================================================================ what to send
def org_endpoints(c, org_id) -> list[dict]:
    return db.q(c, "SELECT id, name, hostname, phase, kind, last_seen, health, agent_version, current_bundle FROM endpoints WHERE org_id=%s AND kind='live' "
                   "AND phase <> 'retired'", (org_id,))


def pending_messages(c, ch: dict, eps: list[dict], incidents: list[dict]) -> list[tuple[str, dict]]:
    """(key, message) the channel should receive now; keys already in notify_log are filtered by the caller."""
    events = set(ch["events"] or [])
    from .updates import target_version
    org = db.q(c, "SELECT agent_update FROM orgs WHERE id=%s", (ch["org_id"],), one=True)
    target = target_version(org["agent_update"] if org else "auto")
    out = []
    if "incident" in events:
        floor = SEV_RANK.get(ch["min_severity"], 2)
        for inc in incidents:
            if SEV_RANK.get(inc["severity"], 0) < floor or inc["max_alert_id"] <= ch["since_alert_id"]:
                continue
            out.append((f"incident:{inc['id']}:{inc['severity']}", (inc, None)))
    if "weekly" in events:
        nowdt = datetime.now(timezone.utc)
        if nowdt.weekday() == 0 and nowdt.hour >= 7:          # Monday morning (UTC)
            from .reports import weekly, weekly_text
            org_row = db.q(c, "SELECT name FROM orgs WHERE id=%s", (ch["org_id"],), one=True)
            w = weekly(c, ch["org_id"], nowdt)
            iso = nowdt.isocalendar()
            title = f"Weekly summary: {w['incidents_new']} new incidents, {w['incidents_open']} open"
            out.append((f"weekly:{iso[0]}-{iso[1]:02d}", {"event": "weekly", "subject": f"[M.D Lab] {title} ({org_row['name'] if org_row else ''})",
                                                          "text": weekly_text(w, org_row["name"] if org_row else "", console_url()), "title": title,
                                                          "severity": "low", "link": f"{console_url()}/#/reports/weekly", "data": {"type": "weekly", **w}}))
    if "platform" in events:
        org_row = db.q(c, "SELECT internal FROM orgs WHERE id=%s", (ch["org_id"],), one=True)
        if org_row and org_row["internal"]:
            from .metrics import platform_problems
            day = time.strftime("%Y-%m-%d", time.gmtime())
            for p in platform_problems(c):
                title = f"Platform: {p['text']}"
                out.append((f"platform:{p['key']}:{day}", {"event": "platform", "subject": f"[M.D Lab] {title}", "text": title, "title": title,
                                                         "severity": "high" if p["level"] == "error" else "medium", "link": f"{console_url()}/#/operator",
                                                         "data": {"type": "platform", "problem": p["key"], "detail": p["text"]}}))
    from .posture import security_messages
    out += security_messages(c, ch, console_url())
    now = time.time()
    for ep in eps:
        if "agent_offline" in events and ep["last_seen"] is not None and ep["phase"] in ("baseline", "training", "protected"):
            seen = ep["last_seen"].timestamp()
            if now - seen > OFFLINE_MIN * 60 and now - seen < 30 * 86400:
                mins = int((now - seen) // 60)
                out.append((f"offline:{ep['id']}:{int(seen)}", endpoint_message("agent_offline", ep, f"agent has not reported for {mins} minutes")))
            elif now - seen < 120:
                last_off = db.q(c, "SELECT key FROM notify_log WHERE channel_id=%s AND key LIKE %s AND state='sent' ORDER BY at DESC LIMIT 1",
                                (ch["id"], f"offline:{ep['id']}:%"), one=True)
                if last_off:
                    out.append((f"online:{ep['id']}:{last_off['key'].rsplit(':', 1)[1]}",
                                endpoint_message("agent_offline", ep, "agent is reporting again", "low")))
        if "agent_health" in events and ep["health"]:
            from .health import problems
            day = time.strftime("%Y-%m-%d", time.gmtime())
            h = ep["health"]
            for p in problems(ep, target):
                k = p["key"]
                if k == "collector_lost":
                    k += f":{10 ** int(math.log10(max(1, int(h.get('collector_lost') or 1))))}"
                elif k == "spool_dropped":
                    n = int(h.get("spool_dropped_unuploaded") or 0) + int(h.get("spool_dropped_unscored") or 0)
                    k += f":{10 ** int(math.log10(max(1, n)))}"
                elif k in ("disk", "behind", "queue", "no_updater"):
                    k += f":{day}"           # at most once a day while it lasts
                out.append((f"health:{ep['id']}:{k}", endpoint_message("agent_health", ep, p["text"][0].lower() + p["text"][1:],
                                                                       "high" if p["level"] == "error" else "medium")))
    return out


def org_incidents(c, eps: list[dict], after_alert_id: int = 0) -> list[dict]:
    """The organisation's incidents with an alert newer than `after_alert_id` (older ones cannot notify)."""
    from . import incidents as inc
    ids = sorted(str(e["id"]) for e in eps)
    if not ids:
        return []
    out = []
    for g in inc.grouped(c, ids):
        mx = max(a["id"] for a in g)
        if mx <= after_alert_id:
            continue
        s = inc.summarise(g)
        s["max_alert_id"] = mx
        out.append(s)
    return out


def _log(c, ch_id: int, key: str, subject: str, state: str, detail: str | None = None) -> bool:
    """Record (channel, key) once; False if it was already recorded."""
    r = db.q(c, "INSERT INTO notify_log (channel_id, key, subject, state, detail) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (channel_id, key) DO NOTHING RETURNING id",
             (ch_id, key, (subject or "")[:300], state, (detail or "")[:500] or None), one=True)
    return r is not None


def run_channel(c, ch: dict, eps: list[dict], incidents: list[dict]) -> dict:
    stats = {"sent": 0, "failed": 0, "suppressed": 0}
    todo = pending_messages(c, ch, eps, incidents)
    keys = [k for k, _ in todo]
    done = {r["key"] for r in db.q(c, "SELECT key FROM notify_log WHERE channel_id=%s AND key = ANY(%s) AND state <> 'failed'", (ch["id"], keys))} if keys else set()
    sent_hour = db.q(c, "SELECT count(*) AS n FROM notify_log WHERE channel_id=%s AND state IN ('sent','digest') AND at > now() - interval '1 hour' "
                        "AND key NOT LIKE 'test:%%'", (ch["id"],), one=True)["n"]      # test messages do not count
    for key, m in todo:
        if key in done:
            continue
        if isinstance(m, tuple):     # incident: escalation note when a lower severity was sent before
            inc, _ = m
            prev = db.q(c, "SELECT key FROM notify_log WHERE channel_id=%s AND key LIKE %s AND state='sent' ORDER BY at DESC LIMIT 1",
                        (ch["id"], f"incident:{inc['id']}:%"), one=True)
            m = incident_message(inc, prev["key"].rsplit(":", 1)[1] if prev else None)
        if sent_hour >= MAX_PER_HOUR:
            if _log(c, ch["id"], key, m["subject"], "suppressed", "hourly limit"):
                stats["suppressed"] += 1
            continue
        try:
            deliver(ch, m)
        except Exception as e:  # noqa - one channel's outage must not stop the others; retried next round
            _fail(c, ch, str(e))
            db.q(c, "INSERT INTO notify_log (channel_id, key, subject, state, detail) VALUES (%s,%s,%s,'failed',%s) "
                    "ON CONFLICT (channel_id, key) DO UPDATE SET state='failed', detail=excluded.detail, at=now()", (ch["id"], key, m["subject"][:300], str(e)[:500]))
            stats["failed"] += 1
            break
        db.q(c, "INSERT INTO notify_log (channel_id, key, subject, state) VALUES (%s,%s,%s,'sent') "
                "ON CONFLICT (channel_id, key) DO UPDATE SET state='sent', detail=NULL, at=now()", (ch["id"], key, m["subject"][:300]))
        _ok(c, ch)
        sent_hour += 1
        stats["sent"] += 1
    _tests(c, ch)
    _digest(c, ch)
    return stats


def _tests(c, ch: dict) -> None:
    """Test messages queued from the console (any channel, also disabled ones; not counted against the limit)."""
    for r in db.q(c, "SELECT key FROM notify_log WHERE channel_id=%s AND state='queued' ORDER BY at", (ch["id"],)):
        org = db.q(c, "SELECT name FROM orgs WHERE id=%s", (ch["org_id"],), one=True)
        m = {"event": "test", "subject": "[M.D Lab] Test notification", "title": "Test notification from M.D Lab Detector", "severity": "low",
             "link": f"{console_url()}/#/settings/notifications",
             "text": f"This is a test of the notification channel \"{ch['name']}\" of {org['name'] if org else 'your organisation'}. "
                     f"Incidents and agent problems will arrive here.", "data": {"type": "test", "channel": ch["name"]}}
        try:
            deliver(ch, m)
            db.q(c, "UPDATE notify_log SET state='sent', at=now() WHERE channel_id=%s AND key=%s", (ch["id"], r["key"]))
            _ok(c, ch)
        except Exception as e:  # noqa
            db.q(c, "UPDATE notify_log SET state='failed', detail=%s, at=now() WHERE channel_id=%s AND key=%s", (str(e)[:500], ch["id"], r["key"]))
            _fail(c, ch, str(e))


def _digest(c, ch: dict) -> None:
    """Once an hour: one message listing what the hourly limit held back."""
    hour = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
    rows = db.q(c, "SELECT subject FROM notify_log WHERE channel_id=%s AND state='suppressed' AND at > now() - interval '1 hour' "
                   "AND at > coalesce((SELECT max(at) FROM notify_log WHERE channel_id=%s AND state='digest'), 'epoch') ORDER BY at", (ch["id"], ch["id"]))
    if not rows or db.q(c, "SELECT 1 FROM notify_log WHERE channel_id=%s AND key=%s", (ch["id"], f"digest:{hour}"), one=True):
        return
    if db.q(c, "SELECT 1 FROM notify_log WHERE channel_id=%s AND state='digest' AND at > now() - interval '1 hour'", (ch["id"],), one=True):
        return
    items = [r["subject"] for r in rows]
    text = f"{len(items)} more notifications in the last hour were held back to avoid flooding this channel:\n\n" + \
           "\n".join(f"- {s}" for s in items[:30]) + ("\n..." if len(items) > 30 else "") + f"\n\nAll of them: {console_url()}/#/incidents"
    m = {"event": "digest", "subject": f"[M.D Lab] {len(items)} more notifications in the last hour", "text": text, "title": f"{len(items)} more notifications",
         "severity": "medium", "link": f"{console_url()}/#/incidents", "data": {"type": "digest", "count": len(items), "subjects": items[:100]}}
    try:
        deliver(ch, m)
        _log(c, ch["id"], f"digest:{hour}", m["subject"], "digest")
    except Exception as e:  # noqa
        _fail(c, ch, str(e))


def _ok(c, ch):
    db.q(c, "UPDATE notify_channels SET last_ok_at=now(), last_error=NULL WHERE id=%s", (ch["id"],))


def _fail(c, ch, err):
    db.q(c, "UPDATE notify_channels SET last_error=%s, last_error_at=now() WHERE id=%s", (err[:500], ch["id"]))


def run_alert_feed(c, ch: dict, eps: list[dict]) -> int:
    ids = [str(e["id"]) for e in db.q(c, "SELECT id FROM endpoints WHERE org_id=%s", (ch["org_id"],))]
    if not ids:
        return 0
    rows = db.q(c, "SELECT a.id, a.endpoint_id, e.name AS endpoint, e.hostname, a.window_start_ns, a.node_uuid, a.ntype, a.label, "
                   "a.fused, a.r1, a.r2, a.status, a.layer, a.rule, a.reason FROM alerts a JOIN endpoints e ON e.id=a.endpoint_id "
                   "WHERE a.id > %s AND a.endpoint_id = ANY(%s::uuid[]) AND a.allowed_by IS NULL ORDER BY a.id LIMIT 500",
                (max(ch["alert_cursor"], ch["since_alert_id"]), ids))
    if not rows:
        return 0
    for r in rows:
        r["endpoint_id"] = str(r["endpoint_id"])
    try:
        deliver_alerts(ch, rows)
    except Exception as e:  # noqa
        _fail(c, ch, str(e))
        return 0
    db.q(c, "UPDATE notify_channels SET alert_cursor=%s, last_ok_at=now(), last_error=NULL WHERE id=%s", (rows[-1]["id"], ch["id"]))
    return len(rows)


def run_once(org_ids: list[str] | None = None) -> dict:
    """One delivery round over all organisations' channels (org_ids: only these; tests)."""
    total = {"sent": 0, "failed": 0, "suppressed": 0, "alerts": 0}
    with db.conn() as c:
        chans = db.q(c, "SELECT n.* FROM notify_channels n JOIN orgs o ON o.id=n.org_id WHERE (n.enabled OR EXISTS "
                        "(SELECT 1 FROM notify_log l WHERE l.channel_id=n.id AND l.state='queued')) AND NOT o.disabled "
                        "AND (%s::uuid[] IS NULL OR n.org_id = ANY(%s::uuid[])) ORDER BY n.org_id, n.id", (org_ids, org_ids))
        by_org: dict = {}
        for ch in chans:
            by_org.setdefault(str(ch["org_id"]), []).append(ch)
        for org, chs in by_org.items():
            eps = org_endpoints(c, org)
            inc_chs = [ch for ch in chs if ch["enabled"] and "incident" in (ch["events"] or [])]
            incs = org_incidents(c, eps, min(ch["since_alert_id"] for ch in inc_chs)) if inc_chs else []
            for ch in chs:
                if not ch["enabled"]:
                    _tests(c, ch)
                    continue
                st = run_channel(c, ch, eps, incs)
                for k, v in st.items():
                    total[k] += v
                if ch["every_alert"] and ch["kind"] in ("webhook", "syslog"):
                    total["alerts"] += run_alert_feed(c, ch, eps)
    return total


def env_channels() -> None:
    """The server-wide exporter settings (PDP_EXPORT_SYSLOG / PDP_EXPORT_WEBHOOK) as alert-feed channels of the
    internal organisation, so existing installs keep their SIEM feed."""
    from .orgs import internal_org
    with db.conn() as c:
        org = internal_org(c)
        cur = db.q(c, "SELECT v FROM kv WHERE k='export_cursor'", one=True)
        start = int(cur["v"]) if cur else int(db.q(c, "SELECT coalesce(max(id), 0) AS m FROM alerts", one=True)["m"])
        for kind, var, sec in (("syslog", "PDP_EXPORT_SYSLOG", None), ("webhook", "PDP_EXPORT_WEBHOOK", "PDP_EXPORT_WEBHOOK_TOKEN")):
            t = os.environ.get(var)
            if t and not db.q(c, "SELECT 1 FROM notify_channels WHERE org_id=%s AND kind=%s AND target=%s", (org, kind, t), one=True):
                db.q(c, "INSERT INTO notify_channels (org_id, name, kind, target, secret, events, every_alert, since_alert_id, alert_cursor, created_by) "
                        "VALUES (%s,%s,%s,%s,%s,'[]',true,%s,%s,'server configuration')",
                     (org, f"SIEM feed ({var})", kind, t, os.environ.get(sec) if sec else None, start, start))
                log(f"notifier: {var} set up as an alert feed of the internal organisation")


def main():
    log(f"notifier up (every {INTERVAL:.0f}s, at most {MAX_PER_HOUR} messages per channel and hour, "
        f"private targets {'allowed' if _allow_private() else 'refused'})")
    try:
        env_channels()
    except Exception as e:  # noqa
        log(f"notifier: server-wide export settings not applied: {e}")
    while True:
        try:
            with db.conn() as c:      # what the console shows (the API has neither the SMTP settings nor internet access)
                db.q(c, "INSERT INTO kv (k, v, updated_at) VALUES ('notifier', %s, now()) ON CONFLICT (k) DO UPDATE SET v=excluded.v, updated_at=now()",
                     (json.dumps({"email": bool(os.environ.get("PDP_SMTP_URL")), "allow_private": _allow_private(), "at": time.time()}),))
            try:      # detection posture of every endpoint; a worsening becomes a security event (sent below)
                from .posture import refresh_all
                refresh_all()
            except Exception as e:  # noqa
                log(f"posture refresh failed: {e}")
            t = run_once()
            if any(t.values()):
                log(f"notifications: {t}")
        except Exception as e:  # noqa - keep the loop alive (database restarts etc.)
            log(f"notifier round failed: {e}")
        time.sleep(INTERVAL)


# ================================================================================================ console API
class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: str
    target: str = Field(min_length=1, max_length=2000)
    secret: str | None = Field(default=None, max_length=200)
    min_severity: str = "high"
    events: list[str] = Field(default_factory=lambda: ["incident", "agent_offline", "agent_health", "weekly", "detection_weakened", "response_action"])
    every_alert: bool = False
    enabled: bool = True


class ChannelPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    target: str | None = Field(default=None, min_length=1, max_length=2000)
    secret: str | None = Field(default=None, max_length=200)
    min_severity: str | None = None
    events: list[str] | None = None
    every_alert: bool | None = None
    enabled: bool | None = None


def _out(r: dict) -> dict:
    return {"id": r["id"], "name": r["name"], "kind": r["kind"], "target": r["target"], "has_secret": bool(r.get("secret")),
            "min_severity": r["min_severity"], "events": r["events"], "every_alert": r["every_alert"], "enabled": r["enabled"],
            "created_by": r.get("created_by"), "created_at": r["created_at"], "last_ok_at": r.get("last_ok_at"),
            "last_error": r.get("last_error"), "last_error_at": r.get("last_error_at")}


def _check(kind: str, target: str, min_severity: str, events: list[str], every_alert: bool) -> str:
    if kind not in KINDS:
        raise HTTPException(400, f"kind must be one of {', '.join(KINDS)}")
    if min_severity not in SEVERITIES:
        raise HTTPException(400, "min_severity must be low, medium, high or critical")
    if any(e not in EVENTS for e in events):
        raise HTTPException(400, f"events must be among {', '.join(EVENTS)}")
    if every_alert and kind not in ("webhook", "syslog"):
        raise HTTPException(400, "every-alert feeds are for webhook and syslog channels")
    try:
        t = validate(kind, target)
    except TargetError as e:
        raise HTTPException(400, str(e))
    if kind == "email":
        with db.conn() as c:
            st = db.q(c, "SELECT v FROM kv WHERE k='notifier'", one=True)
        if not (st and st["v"].get("email")):
            raise HTTPException(400, "E-mail is not set up on this server; use Slack, Teams or a webhook")
    if kind != "email" and not _allow_private():
        # the API has no internet access (no DNS for outside names): literal internal addresses are refused here,
        # names are resolved and checked by the notifier before every send
        h = (urlparse(t).hostname or "").strip("[]").lower()
        try:
            ip = ipaddress.ip_address(h)
            if not ip.is_global:
                raise HTTPException(400, f"{h} is an internal address; only public destinations are allowed")
        except ValueError:
            if h == "localhost" or h.endswith((".localhost", ".local", ".internal")) or "." not in h:
                raise HTTPException(400, f"{h} is not a public host name")
    return t


@router.get("/api/notifications/channels")
def list_channels(s=Depends(admin)):
    with db.conn() as c:
        rows = db.q(c, "SELECT * FROM notify_channels WHERE org_id=%s ORDER BY id", (s["org"],))
        st = db.q(c, "SELECT v FROM kv WHERE k='notifier'", one=True)
    st = st["v"] if st else {}
    return {"ok": True, "channels": [_out(r) for r in rows], "email_available": bool(st.get("email")),
            "notifier_running": bool(st.get("at")) and time.time() - float(st["at"]) < 120,
            "kinds": list(KINDS), "events": list(EVENTS), "severities": list(SEVERITIES)}


@router.post("/api/notifications/channels")
def create_channel(req: ChannelIn, s=Depends(admin)):
    t = _check(req.kind, req.target, req.min_severity, req.events, req.every_alert)
    with db.conn() as c:
        if db.q(c, "SELECT count(*) AS n FROM notify_channels WHERE org_id=%s", (s["org"],), one=True)["n"] >= 20:
            raise HTTPException(400, "At most 20 channels per organisation")
        start = int(db.q(c, "SELECT coalesce(max(id), 0) AS m FROM alerts", one=True)["m"])    # nothing from before
        who = db.q(c, "SELECT coalesce(display_name, username) AS n FROM users WHERE id=%s", (s["u"],), one=True)
        r = db.q(c, "INSERT INTO notify_channels (org_id, name, kind, target, secret, min_severity, events, every_alert, enabled, since_alert_id, alert_cursor, created_by) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                 (s["org"], req.name.strip(), req.kind, t, req.secret or None, req.min_severity, json.dumps(req.events), req.every_alert,
                  req.enabled, start, start, who["n"] if who else None), one=True)
        from .posture import audit_change
        audit_change(c, s, "notification channel added", f"channel_id={r['id']}", before=None, after=_out(r))
    return {"ok": True, "channel": _out(r)}


@router.patch("/api/notifications/channels/{cid}")
def patch_channel(cid: int, req: ChannelPatch, s=Depends(admin)):
    with db.conn() as c:
        r = db.q(c, "SELECT * FROM notify_channels WHERE id=%s AND org_id=%s", (cid, s["org"]), one=True)
        if not r:
            raise HTTPException(404, "not found")
        new = {k: v for k, v in req.dict().items() if v is not None}
        t = _check(r["kind"], new.get("target", r["target"]), new.get("min_severity", r["min_severity"]), new.get("events", r["events"]),
                   new.get("every_alert", r["every_alert"]))
        sets, vals = [], []
        for k in ("name", "secret", "min_severity", "every_alert", "enabled"):
            if k in new:
                sets.append(f"{k}=%s"); vals.append(new[k] if k != "secret" else (new[k] or None))
        if "events" in new:
            sets.append("events=%s"); vals.append(json.dumps(new["events"]))
        if "target" in new:
            sets.append("target=%s"); vals.append(t)
        if sets:
            old = r
            r = db.q(c, f"UPDATE notify_channels SET {', '.join(sets)} WHERE id=%s RETURNING *", (*vals, cid), one=True)
            from .posture import channel_silenced
            channel_silenced(c, s, _out(old), _out(r))
    return {"ok": True, "channel": _out(r)}


@router.delete("/api/notifications/channels/{cid}")
def delete_channel(cid: int, s=Depends(admin)):
    with db.conn() as c:
        r = db.q(c, "DELETE FROM notify_channels WHERE id=%s AND org_id=%s RETURNING *", (cid, s["org"]), one=True)
        if not r:
            raise HTTPException(404, "not found")
        from .posture import channel_silenced
        channel_silenced(c, s, _out(r), None)
    return {"ok": True}


@router.post("/api/notifications/channels/{cid}/test")
def test_channel(cid: int, s=Depends(admin)):
    """Queue a test message; the notifier (the only service with internet access) sends it within seconds."""
    with db.conn() as c:
        r = db.q(c, "SELECT * FROM notify_channels WHERE id=%s AND org_id=%s", (cid, s["org"]), one=True)
        if not r:
            raise HTTPException(404, "not found")
        key = f"test:{int(time.time() * 1000)}"
        db.q(c, "INSERT INTO notify_log (channel_id, key, subject, state) VALUES (%s,%s,%s,'queued')", (cid, key, "[M.D Lab] Test notification"))
    return {"ok": True, "queued": key}


@router.get("/api/notifications/log")
def channel_log(channel_id: int, limit: int = 50, s=Depends(admin)):
    with db.conn() as c:
        if not db.q(c, "SELECT 1 FROM notify_channels WHERE id=%s AND org_id=%s", (channel_id, s["org"]), one=True):
            raise HTTPException(404, "not found")
        rows = db.q(c, "SELECT key, subject, state, detail, at FROM notify_log WHERE channel_id=%s ORDER BY at DESC LIMIT %s",
                    (channel_id, max(1, min(int(limit), 500))))
    return {"ok": True, "log": rows}


if __name__ == "__main__":
    main()
