"""Endpoint agent: collect -> (baseline upload | local detection) -> report.

Phases (mirrors the server's view):
  enroll     one-time token -> client certificate (key generated locally)
  baseline   events are spooled and uploaded day by day; a day is reported complete when the next day starts
  training   nothing leaves the host; events keep spooling
  protected  the signed bundle is installed; the backlog and then the live stream are scored locally; only window
             summaries and alerts (flagged nodes + window-local context) are reported
"""
from __future__ import annotations

import io
import json
import os
import tarfile
import time
import uuid as uuidlib
from datetime import datetime, timezone

import numpy as np

from pdp_engine.bundle import verify_signature
from pdp_engine.runtime import Runtime, WindowResult
from pdp_engine.schema import EDGE_TYPE_ID, EDGE_TYPES, Entity, Event, Registry
from pdp_engine.windows import Window, WindowBuilder

from .config import Config
from .state import State
from .transport import Transport, TransportError

VERSION = "0.3.0"
DAY_GRACE_S = 300        # a live day is declared complete this long after midnight (late spool writes settle)


_TZ = {}


def _zone(tz: str):
    if tz not in _TZ:
        from zoneinfo import ZoneInfo
        _TZ[tz] = ZoneInfo(tz)
    return _TZ[tz]


def day_of(ts_ns: int, tz: str = "UTC") -> str:
    return datetime.fromtimestamp(ts_ns / 1e9, tz=_zone(tz)).strftime("%Y-%m-%d")


def day_end_ns(day: str, tz: str = "UTC") -> int:
    """First nanosecond after calendar day `day` in timezone `tz`."""
    from datetime import timedelta
    d0 = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=_zone(tz))
    return int((d0 + timedelta(days=1)).timestamp() * 1e9)


def ca_fingerprint(pem: bytes) -> str:
    """Hex sha256 of the certificate's DER encoding (what `openssl x509 -fingerprint -sha256` prints)."""
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    return hashlib.sha256(x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)).hexdigest()


def _norm_fp(fp: str) -> str:
    return fp.replace(":", "").strip().lower()


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, flush=True)


class Agent:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = State(os.path.join(cfg.data_dir, "state.sqlite"))
        self.reg = self.state.load_registry()
        self.runtime: Runtime | None = None
        self.builder = WindowBuilder()
        self.tr: Transport | None = None
        self.stop = False
        # wall-clock sources complete a day once it is over; replays/sandbox declare their days (set again in run())
        self.chronological = cfg.source.get("kind") in ("auditd", "ebpf", "strace", "etw")
        self._cpu0 = (time.time(), os.times())
        self._last_window_end = 0

    # ------------------------------------------------------------------ enrolment
    def enroll(self, token: str, ca_sha256: str | None = None, attempts: int = 30):
        """One-time token -> client certificate. Idempotent (an enrolled agent returns immediately). The server CA
        is fetched once and pinned; with `ca_sha256` (shown in the console next to the token) it is verified before
        anything is sent, otherwise trust-on-first-use with the fingerprint logged for the operator."""
        if self.state.get("endpoint_id") and os.path.exists(self.cfg.cert_path):
            log(f"already enrolled as endpoint {self.state.get('endpoint_id')}")
            return
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        ca_sha256 = ca_sha256 or os.environ.get("PDP_CA_SHA256") or getattr(self.cfg, "ca_sha256", None)
        os.makedirs(self.cfg.pki_dir, exist_ok=True)
        for i in range(attempts):
            try:
                if not os.path.exists(self.cfg.server_ca):
                    import http.client, ssl
                    from urllib.parse import urlparse
                    u = urlparse(self.cfg.server_url)
                    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    c = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=30)
                    c.request("GET", "/dl/ca.pem"); resp = c.getresponse(); pem = resp.read(); c.close()
                    if resp.status != 200 or b"BEGIN CERTIFICATE" not in pem:
                        raise OSError(f"CA download failed (HTTP {resp.status})")
                    fp = ca_fingerprint(pem)
                    if ca_sha256 and _norm_fp(ca_sha256) != fp:
                        raise SystemExit(f"server CA fingerprint {fp} does not match the expected {_norm_fp(ca_sha256)}; refusing to enrol")
                    open(self.cfg.server_ca, "wb").write(pem)
                    log(f"pinned server CA, sha256 {fp}" + (" (verified)" if ca_sha256 else " (trust on first use; compare with the console)"))
                key = ec.generate_private_key(ec.SECP256R1())
                csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pending")])).sign(key, hashes.SHA256())
                t = Transport(self.cfg.server_url, self.cfg.server_ca)
                import platform as pf
                r = t.request("POST", "/v1/enroll", {"token": token, "hostname": pf.node(), "os": pf.system().lower(), "arch": pf.machine(),
                                                     "agent_version": VERSION, "tz": self.cfg.day_tz, "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()})
                break
            except TransportError:
                raise                                  # the server answered: bad/expired token etc. — not retryable
            except OSError as e:
                if i == attempts - 1:
                    raise
                log(f"enrolment: server not reachable yet ({e}); retrying")
                time.sleep(min(5 * (i + 1), 30))
        with open(self.cfg.key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(self.cfg.key_path, 0o600)
        open(self.cfg.cert_path, "w").write(r["cert_pem"])
        open(self.cfg.server_ca, "w").write(r["ca_pem"])
        open(self.cfg.signing_pub, "w").write(r["bundle_signing_pub"])
        self.state.set("endpoint_id", r["endpoint_id"]); self.state.set("config", r["config"]); self.state.set("phase", "baseline")
        log(f"enrolled as endpoint {r['endpoint_id']}")

    def connect(self):
        self.eid = self.state.get("endpoint_id")
        if not self.eid:
            raise RuntimeError("not enrolled")
        self.tr = Transport(self.cfg.agent_url, self.cfg.server_ca, self.cfg.cert_path, self.cfg.key_path)

    # ------------------------------------------------------------------ collection
    def ingest(self, items) -> int:
        """items: iterable of (entities, Event). Registers entities and spools events. Returns count."""
        ents, evs, n = [], [], 0
        tz = self.tz
        for entities, ev in items:
            for e in entities:
                if self.reg.get(e.uuid) is None:
                    self.reg.add(e); ents.append(e)
            evs.append((ev.ts_ns, ev.src, ev.op, ev.dst, ev.event_uuid, day_of(ev.ts_ns, tz)))
            n += 1
            if len(evs) >= 5000:
                self._commit(ents, evs); ents, evs = [], []
        self._commit(ents, evs)
        return n

    @property
    def tz(self) -> str:
        """Calendar of the baseline days: the server's endpoint configuration (set from this agent at enrolment)."""
        return (self.state.get("config") or {}).get("tz") or self.cfg.day_tz

    def _commit(self, ents, evs):
        if ents:
            self.state.add_entities(ents)
        if evs:
            self.state.add_events(evs)
            for d in dict.fromkeys(e[5] for e in evs):   # order of first appearance (a set's order is random per process)
                self.state.touch_day(d)

    # ------------------------------------------------------------------ baseline upload
    def upload_baseline(self):
        pend = self.state.pending_entities()
        while pend:
            # the agent's dense id travels with each entity: the server builds its registry in exactly this order, so
            # node ids (and the detector-2 neighbour state keyed by them) are identical on both sides
            for p in pend:
                p["dense_id"] = self.reg.get(p["uuid"])
            self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/entities", pend)
            self.state.mark_entities_uploaded([p["uuid"] for p in pend])
            pend = self.state.pending_entities()
        need = int((self.state.get("config") or {}).get("baseline_days", 7)) + 1
        days = self.state.days()[:need]        # the baseline is the first N+1 days seen; later days stay local
        for i, (day, completed, reported) in enumerate(days):
            rows = self.state.pending_events(day)
            while rows:
                bid = f"{day}-{rows[0][0]}-{rows[-1][0]}"
                self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/events", [{"ts_ns": r[1], "src": r[2], "op": r[3], "dst": r[4], "event_uuid": r[5]} for r in rows], batch_id=bid)
                self.state.mark_events_uploaded([r[0] for r in rows])
                rows = self.state.pending_events(day)
            # the source declares days complete; for a chronological live source a day is also complete once a later
            # day has started or the wall clock has passed its end (an idle host); replays may stream days out of
            # order, so they rely on the explicit declaration
            if not reported and (completed or self._day_over(day, i, len(days))):
                self.tr.request("POST", f"/v1/endpoints/{self.eid}/day-complete", {"date": day})
                self.state.mark_day_reported(day)
                log(f"baseline day {day} uploaded and completed")

    def _day_over(self, day: str, i: int, n: int) -> bool:
        if not self.chronological:
            return False
        if i < n - 1:
            return True
        return time.time_ns() > day_end_ns(day, self.tz) + DAY_GRACE_S * 1_000_000_000

    # ------------------------------------------------------------------ bundles
    def fetch_bundle(self, bundle_id: str):
        status, headers, payload = self.tr.request("GET", f"/v1/endpoints/{self.eid}/bundle", raw=True)
        if status != 200:
            raise TransportError(status, "bundle download failed")
        dest = os.path.join(self.cfg.data_dir, "bundles", bundle_id)
        os.makedirs(dest, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            for m in tar.getmembers():
                if m.name.startswith("/") or ".." in m.name:
                    raise ValueError("unsafe bundle path")
            tar.extractall(dest)
        self._load_bundle(bundle_id, os.path.join(dest, "bundle"))

    def _load_bundle(self, bundle_id: str, bdir: str):
        verify_signature(bdir, open(self.cfg.signing_pub, "rb").read())
        device = getattr(self.cfg, "device", "cpu")
        feat_device = getattr(self.cfg, "feat_device", None) or ("cpu" if device == "cuda" else device)
        cfg = self.state.get("config") or {}
        self.runtime = Runtime(bdir, self.reg, device=device, fp_budget=self.state.get("fp_budget"), feat_device=feat_device,
                               approved_executables=cfg.get("approved_executables"), daily_budget=cfg.get("learned_daily_budget"))
        self.runtime.set_learned_alerts(bool(cfg.get("learned_alerts", True)))
        wns = int(self.runtime.m.get("window_ns") or 0)
        if wns and wns != self.builder.window_ns and not self.builder.pending:   # windows as long as the bundle was trained on
            self.builder.window_ns = wns
        first = self.state.get("bundle_id") is None
        self.state.set("bundle_id", bundle_id)
        if first:   # detection starts after the baseline; the days the bundle was built on are not re-scored
            skipped = self.state.mark_days_scored(list(self.runtime.m.get("train_days", [])) + [self.runtime.m.get("val_day")])
            log(f"bundle {bundle_id} verified and loaded; {skipped} baseline events skipped for scoring")
        else:
            log(f"bundle {bundle_id} verified and loaded")

    def _apply_layer_config(self, cfg: dict):
        """Console-side layer settings that need no new bundle: approved programs (layer 1) and the learned layer's
        daily alert budget."""
        if self.runtime is None:
            return
        appr = sorted(cfg.get("approved_executables") or [])
        if appr != getattr(self, "_approved", None):
            self.runtime.set_approved_executables(appr)
            if getattr(self, "_approved", None) is not None:
                log(f"approved executables updated ({len(appr)})")
            self._approved = appr
        la = bool(cfg.get("learned_alerts", True))
        if self.runtime.policy is not None and la != self.runtime.policy.learned_alerts:
            self.runtime.set_learned_alerts(la)
            log(f"learned-layer alerts {'on' if la else 'off (ranking only)'}")
        b = cfg.get("learned_daily_budget")
        if b is not None and int(b) != self.runtime.daily_budget:
            self.runtime.daily_budget = int(b)
            log(f"learned daily alert budget set to {b}")

    def _apply_fp_budget(self, fb):
        """Switch the alert threshold mode (None = validation-max, or a percentile key like '99.9') when the server
        configuration changes it; the loaded bundle is re-instantiated with the new calibration."""
        if fb == self.state.get("fp_budget"):
            return
        self.state.set("fp_budget", fb)
        log(f"fp_budget set to {fb!r}; reloading detectors")
        if self.runtime is not None:
            self.load_local_bundle()

    def load_local_bundle(self) -> bool:
        """After a restart, resume detection with the bundle already on disk (re-verified)."""
        bid = self.state.get("bundle_id")
        bdir = os.path.join(self.cfg.data_dir, "bundles", bid or "", "bundle")
        if not bid or not os.path.exists(os.path.join(bdir, "manifest.json")):
            return False
        try:
            self._load_bundle(bid, bdir)
            return True
        except Exception as e:  # noqa - a damaged local bundle is re-fetched from the server
            log(f"local bundle {bid} unusable ({e}); will fetch again")
            self.state.set("bundle_id", None)
            return False

    # ------------------------------------------------------------------ detection
    def score_backlog(self):
        rows = self.state.unscored_events()
        while rows:
            results = []
            for r in rows:
                s, d = self.reg.get(r[2]), self.reg.get(r[4])
                if s is None or d is None:
                    continue
                for w in self.builder.push(s, d, r[1], EDGE_TYPE_ID[r[3]], r[5]):
                    results.append((w, self.runtime.score(w, keep_edge_losses=True)))
            self.report(results)
            # Events still buffered in the open window are persisted (not re-read from the spool on restart),
            # so marking the whole batch scored here does not lose them; the builder state is saved alongside.
            self.state.mark_scored([r[0] for r in rows])
            self.state.set("window_builder", self.builder.state())
            rows = self.state.unscored_events()

    def flush_window(self):
        results = [(w, self.runtime.score(w, keep_edge_losses=True)) for w in self.builder.finish()]
        self.report(results)

    def context(self, w: Window, r: WindowResult, node: int, hops: int = 1, cap: int = 300) -> dict:
        """Window-local neighbourhood of a flagged node with per-edge losses (detector-1)."""
        src, dst = w.src, w.dst
        frontier, keep = {node}, {node}
        for _ in range(hops):
            m = np.isin(src, list(frontier)) | np.isin(dst, list(frontier))
            frontier = (set(src[m].tolist()) | set(dst[m].tolist())) - keep
            keep |= frontier
            if len(keep) > cap:
                break
        m = np.isin(src, list(keep)) & np.isin(dst, list(keep))
        idx = np.where(m)[0][:cap * 4]
        l1 = r.edge_loss.get("detector-1")
        nodes = [{"uuid": self.reg[i].uuid, "ntype": self.reg[i].ntype, "label": self.reg[i].label} for i in sorted(keep)[:cap]]
        edges = [{"src": self.reg[int(src[i])].uuid, "dst": self.reg[int(dst[i])].uuid, "op": EDGE_TYPES[int(w.etype[i])], "ts_ns": int(w.t[i]),
                  "loss": float(l1[i]) if l1 is not None else None} for i in idx]
        return {"nodes": nodes, "edges": edges}

    def report(self, results: list[tuple[Window, WindowResult]]):
        self._unreported = getattr(self, "_unreported", [])
        if not results and not self._unreported:
            return
        wins, alerts = [], []
        for w, r in results:
            wins.append(r.summary())
            self._last_window_end = max(self._last_window_end, int(w.end_ns))
            pos = {int(n): i for i, n in enumerate(r.node_ids)}
            for n in r.alerts:
                i = pos[int(n)]
                e = self.reg[int(n)]
                rs = r.reasons.get(int(n)) or [{"layer": "learned", "rule": "learned_score", "detail": f"learned score {float(r.fused[i]):.2f}x the benign maximum"}]
                layer = r.layer_of(int(n))
                main = next(x for x in rs if x["layer"] == layer)
                alerts.append({"window_start_ns": w.start_ns, "node": {"uuid": e.uuid, "ntype": e.ntype, "label": e.label, "display": e.display},
                               "fused": float(r.fused[i]), "r1": float(r.r1[i]), "r2": float(r.r2[i]), "context": self.context(w, r, int(n)),
                               "layer": layer, "rule": main.get("rule"), "reason": main.get("detail"), "reasons": rs})
        if wins:
            self._unreported.append((wins, alerts))
        try:
            while self._unreported:
                w0, a0 = self._unreported[0]
                self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/windows", w0)
                if a0:
                    self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/alerts", a0)
                    log(f"reported {len(a0)} alerts in {len(w0)} windows")
                self._unreported.pop(0)
        except (TransportError, OSError) as e:
            log(f"report deferred ({len(self._unreported)} batches pending): {e}")

    # ------------------------------------------------------------------ main loop
    def run(self, source):
        self.chronological = bool(getattr(source, "chronological", self.chronological))
        self.connect()
        if self.load_local_bundle():
            self.builder.load_state(self.state.get("window_builder"))   # resume the open detection window
            if self.builder.pending:
                log(f"resumed open window with {self.builder.pending} buffered events")
        last_hb, last_status, last_purge = 0, 0, time.time()
        self._offline_since = 0
        for batch in source.batches(lambda: self.stop):   # source yields lists of (entities, Event); empty list = idle tick
            if batch:
                self.ingest(batch)
            now = time.time()
            if now - last_status > self.cfg.status_interval:
                # Server contact is best-effort: collection, spooling and local detection continue while the
                # server is unreachable, and uploads resume from the sqlite spool on the next successful contact.
                try:
                    st = self.tr.request("GET", f"/v1/endpoints/{self.eid}/status")
                    phase = st["phase"]; self.state.set("phase", phase)
                    if isinstance(st.get("config"), dict):      # the server owns the endpoint configuration
                        self.state.set("config", st["config"])
                        self._apply_fp_budget(st["config"].get("fp_budget"))
                        self._apply_layer_config(st["config"])
                    if phase == "baseline":
                        self.upload_baseline()
                    elif phase == "protected":
                        b = st.get("bundle")
                        if b and b["id"] != self.state.get("bundle_id"):
                            self.fetch_bundle(b["id"])
                    for cmd in st.get("commands", []):
                        self.handle_command(cmd)
                    if self._offline_since:
                        log(f"server reachable again after {now - self._offline_since:.0f}s")
                        self._offline_since = 0
                except (TransportError, OSError) as e:
                    if not self._offline_since:
                        self._offline_since = now
                        log(f"server unreachable, continuing offline: {e}")
                last_status = now
            if self.runtime is not None:
                self.score_backlog()
            if now - last_purge > 120:   # spool hygiene: scored + uploaded rows older than the retention window are dropped
                need = int((self.state.get("config") or {}).get("baseline_days", 7)) + 1
                self.state.purge_scored(keep_days=getattr(self.cfg, "spool_keep_days", 2), baseline_days=[d for d, _, _ in self.state.days()[:need]])
                last_purge = now
            if now - last_hb > self.cfg.heartbeat_interval:
                try:
                    self.tr.request("POST", f"/v1/endpoints/{self.eid}/heartbeat", self.health())
                except (TransportError, OSError) as e:
                    log(f"heartbeat failed: {e}")
                last_hb = now

    # ------------------------------------------------------------------ control
    def handle_command(self, cmd: dict):
        """Server commands (queued from the console). Each is acknowledged so it is delivered once."""
        cid = cmd.get("id")
        result = "ok"
        try:
            if "fp_budget" in cmd:
                self._apply_fp_budget(cmd["fp_budget"])
            elif cmd.get("command") == "refetch_bundle":
                bid = self.state.get("bundle_id")
                self.state.set("bundle_id", None)
                self.runtime = None
                log(f"command: re-fetching bundle (was {bid})")
            else:
                result = "unsupported"
        except Exception as e:  # noqa - reported back to the server
            result = f"error: {e}"
        log(f"command {cid} {cmd}: {result}")
        if cid:
            self.tr.request("POST", f"/v1/endpoints/{self.eid}/commands/{cid}/ack", {"result": result})

    def health(self) -> dict:
        now, t = time.time(), os.times()
        t0, c0 = self._cpu0
        cpu = 100.0 * ((t.user + t.system) - (c0.user + c0.system)) / max(now - t0, 1e-6)
        self._cpu0 = (now, t)
        try:
            rss = int(open("/proc/self/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 2**20
        except (OSError, ValueError, IndexError):
            rss = 0.0
        # work not yet done: events awaiting upload while building the baseline, awaiting scoring once protected
        col = "scored" if self.runtime is not None else "uploaded"
        q = self.state.c.execute(f"SELECT count(*) FROM spool WHERE {col}=0").fetchone()[0] + self.builder.pending
        return {"agent_version": VERSION, "queue_depth": int(q), "last_window_end_ns": int(self._last_window_end),
                "cpu_pct": round(cpu, 1), "rss_mb": round(rss, 1)}
