"""Endpoint agent: collect -> (baseline upload | local detection) -> report.

Phases (mirrors the server's view):
  enroll     one-time token -> client certificate (key generated locally)
  baseline   events are spooled and uploaded day by day; a day is reported complete when the next day starts
  training   nothing leaves the host; events keep spooling
  protected  the signed bundle is installed; the backlog and then the live stream are scored locally; only window
             summaries and alerts (flagged nodes + window-local context) are reported
"""
from __future__ import annotations

import errno
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import threading
import time
import uuid as uuidlib
from datetime import datetime, timezone

import numpy as np

from pdp_engine.bundle import verify_signature
from pdp_engine.runtime import Runtime, WindowResult
from pdp_engine.schema import EDGE_TYPE_ID, EDGE_TYPES, NO_DISPLAY, Entity, Event, Registry
from pdp_engine.windows import Window, WindowBuilder

from .config import Config
from .state import State, disk_full
from .transport import Transport, TransportError

VERSION = "0.3.20"
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


_SKIP_WRITE = ("/proc/", "/sys/", "/dev/")


def _observable(src, op: str, dst):
    """(kind, program, object) for the activity index: programs run, addresses contacted (both directions), files
    written; None for everything else."""
    def prog(e):
        parts = e.label.split(" ")
        return parts[1] if len(parts) > 1 and parts[1] != "None" else (parts[2] if len(parts) > 2 else None)
    if op == "EXECUTE" and dst.ntype == "subject":
        p = prog(dst)
        parts = dst.label.split(" ", 2)
        cmd = parts[2][:160] if len(parts) > 2 and parts[2] != "None" else ""
        return ("exec", p, cmd) if p else None
    if op in ("CONNECT", "SENDTO", "SENDMSG") and src.ntype == "subject" and dst.ntype == "netflow":
        p, a = prog(src), dst.label.split(" ", 1)[1].replace(" ", ":") if " " in dst.label else None
        return ("net", p, a) if p and a else None
    if op in ("RECVFROM", "RECVMSG") and dst.ntype == "subject" and src.ntype == "netflow":
        p, a = prog(dst), src.label.split(" ", 1)[1].replace(" ", ":") if " " in src.label else None
        return ("net", p, a) if p and a else None
    if op == "WRITE" and src.ntype == "subject" and dst.ntype == "file":
        path = dst.label[5:] if dst.label.startswith("file ") else dst.label
        if path.startswith(_SKIP_WRITE) or path in ("None", ""):
            return None
        p = prog(src)
        return ("write", p, path) if p else None
    return None


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, flush=True)


class Agent:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = State(os.path.join(cfg.data_dir, "state.sqlite"))
        # entity display data stays on disk (read per alert). After a compaction only the live entities are loaded
        # (the saved live set, everything registered since, and what spooled events refer to); otherwise all.
        live = self._load_live_set()
        if live is not None:
            gids, after = live
            self.reg = self.state.load_registry(display=False, gids=set(gids.tolist()) | self.state.spool_gids(), after_gid=after)
            log(f"registry: {len(self.reg)} live entities loaded (of {self.state.next_gid()} registered)")
        else:
            self.reg = self.state.load_registry(display=False)
        self.next_gid = self.state.next_gid()
        if self.state.has_old_spool():
            log("migrating the local event spool to the compact format")
            n = self.state.migrate_spool(self.reg, self.baseline_days())
            log(f"spool migrated: {n} events still to upload or score, {self.state.size_bytes() / 2**20:.0f} MB on disk")
        self.runtime: Runtime | None = None
        self.builder = WindowBuilder()
        self.tr: Transport | None = None
        self.stop = False
        self._ents_retry: list = []            # full disk (see _commit)
        self._dropped_disk_full = 0
        self._disk_full_since = 0
        self._disk_full_logged = 0
        self._offline_since = 0                 # offline mode (see _went_offline); set up again by run()
        self._reachable = threading.Event()
        self._unreported = []
        # wall-clock sources complete a day once it is over; replays/sandbox declare their days (set again in run())
        self.chronological = cfg.source.get("kind") in ("auditd", "ebpf", "strace", "etw")
        self._cpu0 = (time.time(), os.times())
        self._last_window_end = 0
        self._cursor: tuple | None = None    # (ts_ns, id) of the last spooled event handed to the window builder
        self._max_id = 0                     # highest spool id handed out
        self._open_ids: list[int] = []       # spool ids in the open window: marked scored once their window is
        self._last_compact = time.time()     # scored (on restart they are replayed into a fresh builder)
        self._obs: dict = {}                 # activity index, flushed to disk once a minute
        self._obs_flush = time.time()
        self._slice: list[tuple] = []        # events pushed since the rules last ran (real-time rules)
        self._win_hits: list = []            # rule hits of the open window, handed to score() when it closes
        # (uuid, rule) -> ts of alerts already sent in real time: not sent again with their window, nor after a
        # restart replays the open window
        self._early = {tuple(k[:2]): k[2] for k in (self.state.get("early_alerts") or [])}
        self.exit_code = 0
        # the host's updater (install.sh 0.6+) is present when the unit says so; without it the agent only reports
        # that an update is available (older installs, hand-made units)
        self.updater = os.environ.get("PDP_UPDATER") == "1"
        self._update_offer: dict | None = None

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
                r = t.request("POST", "/v1/enroll", {"token": token, "hostname": os.environ.get("PDP_HOSTNAME") or pf.node(), "os": pf.system().lower(), "arch": pf.machine(),
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
        # one attempt per call with a short connect timeout: the main loop retries on its own (offline mode below), so
        # a lost network never holds collection and local detection
        self.tr = Transport(self.cfg.agent_url, self.cfg.server_ca, self.cfg.cert_path, self.cfg.key_path,
                            timeout=60, connect_timeout=10, attempts=1)

    # ------------------------------------------------------------------ offline mode
    # After a failed server call the loop stops calling the server (each call could otherwise wait for a timeout);
    # a background probe (GET /healthz on the agent port, no side effects) checks every 10 s and lets the loop
    # resume as soon as the server answers. Collection, the spool, local detection and alerting never wait.
    def _went_offline(self, now: float, e: Exception) -> None:
        if not self._offline_since:
            self._offline_since = now
            log(f"server unreachable, continuing offline (collection and local detection go on): {e}")
        self._reachable.clear()

    def _online(self) -> bool:
        return not self._offline_since or self._reachable.is_set()

    def _probe(self) -> None:
        while not self.stop:
            if self._offline_since and not self._reachable.is_set():
                try:
                    self.tr.request("GET", "/healthz")
                    self._reachable.set()
                except TransportError as e:
                    if 400 <= e.status < 500:            # the server answered
                        self._reachable.set()
                except Exception:  # noqa - still offline
                    pass
            time.sleep(10)

    def _save_unreported(self) -> None:
        """Alerts and window summaries not yet delivered survive a restart or power cut (real-time alerts are
        marked as sent when queued, so losing the queue would lose them for good)."""
        try:
            self.state.set("unreported", self._unreported[-500:])
        except Exception as e:  # noqa - best effort
            log(f"could not save the pending alerts: {e}")

    # ------------------------------------------------------------------ collection
    def ingest(self, items) -> int:
        """items: iterable of (entities, Event). Registers entities and spools events. Returns count."""
        ents, evs, n = [], [], 0
        tz = self.tz
        obs = self._obs
        for entities, ev in items:
            if len(entities) == 2:                 # activity index for hunting
                k = _observable(entities[0], ev.op, entities[1])
                if k is not None:
                    v = obs.get(k)
                    if v is None:
                        obs[k] = [ev.ts_ns, ev.ts_ns, 1]
                    else:
                        v[1] = max(v[1], ev.ts_ns); v[2] += 1
            for e in entities:
                if self.reg.get(e.uuid) is None:   # in memory without display data (that goes to disk with `ents`)
                    ents.append((e, self.reg.gid(self._register(e))))
            reg = self.reg
            evs.append((ev.ts_ns, reg.gid(reg.get(ev.src)), ev.op, reg.gid(reg.get(ev.dst)), ev.event_uuid, day_of(ev.ts_ns, tz)))
            n += 1
            if len(evs) >= 5000:
                self._commit(ents, evs); ents, evs = [], []
        self._commit(ents, evs)
        return n

    def _register(self, e: Entity) -> int:
        """Add an entity to the in-memory registry with its global id: a new one gets the next id (its sqlite row
        is written in the same order by _commit); one dropped by a compaction that shows up again gets its old id."""
        g = self.state.gid_for(e.uuid) if self.reg.gids is not None else None
        if g is None:
            g = self.next_gid
            self.next_gid += 1
        return self.reg.add(Entity(e.uuid, e.ntype, sys.intern(e.label), NO_DISPLAY), gid=g)

    def _ensure_gids(self, gids) -> None:
        """Runtime callback: entities a loaded model's neighbour state points to, added back from disk."""
        for g, e in self.state.entities_by_gid(gids):
            if self.reg.get(e.uuid) is None:
                self.reg.add(e, gid=g)

    def _live_path(self) -> str:
        return os.path.join(self.cfg.data_dir, "live_entities.npy")

    def _load_live_set(self):
        """(live global ids, highest global id at that time) saved by the last compaction, or None."""
        try:
            a = np.load(self._live_path())
            return a[:-1], int(a[-1])
        except (OSError, ValueError):
            return None

    def _save_live_set(self) -> None:
        g = self.reg.gid_array()
        tmp = self._live_path() + ".tmp.npy"
        np.save(tmp, np.concatenate([g, np.array([self.next_gid - 1], dtype=np.int64)]))
        os.replace(tmp, self._live_path())

    def maybe_compact(self, now: float) -> None:
        """Drop entities nobody needs any more (not seen for entity_max_age_h, no pending work, no rule state, not
        a neighbour of a kept entity): a busy host registers ~1 M short-lived processes and files a day."""
        if self.runtime is None or now - self._last_compact < float(self.cfg.compact_interval_s):
            return
        self._last_compact = now
        n = len(self.reg)
        if n < int(self.cfg.compact_min_entities):
            return
        t0 = time.time()
        extra = set(self.builder.node_ids())
        for g in self.state.spool_gids():
            i = self.reg.local(g)
            if i is not None:
                extra.add(i)
        keep = self.runtime.compaction_keep(time.time_ns(), int(float(self.cfg.entity_max_age_h) * 3600e9), extra)
        if keep.sum() > n * 0.8:
            return
        old2new = self.runtime.compact(keep)
        self.builder.remap(old2new)
        self._save_live_set()
        import gc
        gc.collect()
        pruned = 0
        mat = self.runtime.m.get("maturity") or {}
        if (self.state.get("phase") == "protected" and not mat.get("early")) or getattr(self.cfg, "prune_entities_always", False):
            # final model: entities registered after its baseline and no longer held are deleted from disk too
            live = set(self.reg.gid_array().tolist()) | self.state.spool_gids()
            pruned = self.state.prune_entities(live, int(self.runtime.N), self.next_gid,
                                               require_uploaded=self.state.get("phase") != "protected")
            if not self.state.get("baseline_transients_pruned"):   # once: baseline processes and connections
                pruned += self.state.prune_baseline_transients(live, int(self.runtime.N))
                self.state.set("baseline_transients_pruned", True)
        log(f"registry compacted: {n} -> {len(self.reg)} entities in {time.time() - t0:.1f}s"
            + (f"; {pruned} entity records deleted from disk" if pruned else ""))

    def baseline_days(self) -> list[str]:
        """Days uploaded to the server: the first N+1 days seen (N baseline days plus the validation day), and later
        the fresh days the server asks a protected agent for to retrain (config refresh_days)."""
        cfg = self.state.get("config") or {}
        need = int(cfg.get("baseline_days", 7)) + 1
        days = [d for d, _, _ in self.state.days()[:need]]
        return days + [d for d in (cfg.get("refresh_days") or []) if d not in days]

    @property
    def tz(self) -> str:
        """Calendar of the baseline days: the server's endpoint configuration (set from this agent at enrolment)."""
        return (self.state.get("config") or {}).get("tz") or self.cfg.day_tz

    def _commit(self, ents, evs):
        # entities that could not be stored (full disk) are in the in-memory registry already: they are stored first
        # next time, so no stored event ever refers to an entity missing on disk; events that cannot be stored are
        # dropped and counted
        ents = self._ents_retry + ents if self._ents_retry else ents
        stored = False
        try:
            if ents:
                self.state.add_entities(ents)
            stored = True
            self._ents_retry = []
            if evs:
                self.state.add_events(evs)
                for d in dict.fromkeys(e[5] for e in evs):   # order of first appearance (a set's order is random per process)
                    self.state.touch_day(d)
        except sqlite3.OperationalError as e:
            if not disk_full(e):
                raise
            if not stored:
                self._ents_retry = list(ents)
            self._dropped_disk_full += len(evs)
            self._disk_full(e)
            return
        if self._disk_full_since:
            log(f"disk space available again after {time.time() - self._disk_full_since:.0f}s; "
                f"{self._dropped_disk_full} events could not be stored meanwhile")
            self._disk_full_since = 0

    def _disk_full(self, e: Exception) -> None:
        now = time.time()
        if not self._disk_full_since:
            self._disk_full_since = now
            self._disk_full_logged = 0
        if now - self._disk_full_logged > 300:
            self._disk_full_logged = now
            log(f"the disk holding {self.cfg.data_dir} is full ({e}): events are dropped until there is space "
                f"({self._dropped_disk_full} so far); detection of what is in memory, alerts and the heartbeat go on")
            try:                                 # free what the server already has (sqlite reuses the pages)
                n = self.state.free_uploaded()
                if n:
                    log(f"freed {n} already uploaded events from the local spool")
            except Exception:  # noqa - may itself fail on a full disk
                pass

    # ------------------------------------------------------------------ baseline upload
    def upload_baseline(self, budget_s: float = 20.0):
        """Uploads what is pending, for at most about `budget_s` per call: after a long outage the backlog goes up
        over several loop turns while collection keeps up (the loop calls this every status interval)."""
        t_end = time.time() + budget_s
        pend = self.state.pending_entities()
        while pend:
            # the agent's dense id travels with each entity: the server builds its registry in exactly this order, so
            # node ids (and the detector-2 neighbour state keyed by them) are identical on both sides
            self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/entities", pend)
            self.state.mark_entities_uploaded([p["uuid"] for p in pend])
            pend = self.state.pending_entities()
        want = self.baseline_days()             # the baseline (first N+1 days) and requested fresh days; others stay local
        known = {d: (c_, r_) for d, c_, r_ in self.state.days()}
        days = [(d, *known[d]) for d in want if d in known]
        for i, (day, completed, reported) in enumerate(days):
            rows = self.state.pending_events(day)
            while rows:
                if time.time() > t_end:
                    return                          # the rest next turn
                bid = f"{day}-{rows[0][0]}-{rows[-1][0]}"
                uid = self._uuids({r[2] for r in rows} | {r[4] for r in rows})
                self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/events", [{"ts_ns": r[1], "src": uid[r[2]], "op": r[3], "dst": uid[r[4]], "event_uuid": r[5]} for r in rows], batch_id=bid)
                self.state.mark_events_uploaded([r[0] for r in rows])
                rows = self.state.pending_events(day)
            # the source declares days complete; for a chronological live source a day is also complete once a later
            # day has started or the wall clock has passed its end (an idle host); replays may stream days out of
            # order, so they rely on the explicit declaration
            if not reported and (completed or self._day_over(day, i, len(days))):
                self.tr.request("POST", f"/v1/endpoints/{self.eid}/day-complete", {"date": day})
                self.state.mark_day_reported(day)
                log(f"baseline day {day} uploaded and completed")

    def _uuids(self, gids) -> dict[int, str]:
        """Global id -> uuid (registry, else disk)."""
        out, missing = {}, []
        for g in gids:
            i = self.reg.local(g)
            if i is None:
                missing.append(g)
            else:
                out[g] = self.reg.entities[i].uuid
        for g, e in self.state.entities_by_gid(missing):
            out[g] = e.uuid
        return out

    def _day_over(self, day: str, i: int, n: int) -> bool:
        if not self.chronological:
            return False
        if i < n - 1:
            return True
        return time.time_ns() > day_end_ns(day, self.tz) + DAY_GRACE_S * 1_000_000_000

    # ------------------------------------------------------------------ bundles
    def fetch_bundle(self, bundle_id: str):
        """Download (streamed to disk; `slim`: without the server-only replay state), unpack, verify, load."""
        root = os.path.join(self.cfg.data_dir, "bundles")
        dest = os.path.join(root, bundle_id)
        os.makedirs(dest, exist_ok=True)
        tmp = os.path.join(root, f".{bundle_id}.tar.gz")
        try:
            self.tr.download(f"/v1/endpoints/{self.eid}/bundle?slim=1", tmp)
            with tarfile.open(tmp, mode="r:gz") as tar:
                for m in tar.getmembers():
                    if m.name.startswith("/") or ".." in m.name or not (m.isfile() or m.isdir()):
                        raise ValueError("unsafe bundle path")
                tar.extractall(dest)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        self._load_bundle(bundle_id, os.path.join(dest, "bundle"))

    def _load_bundle(self, bundle_id: str, bdir: str):
        verify_signature(bdir, open(self.cfg.signing_pub, "rb").read())
        device = getattr(self.cfg, "device", "cpu")
        feat_device = getattr(self.cfg, "feat_device", None) or ("cpu" if device == "cuda" else device)
        cfg = self.state.get("config") or {}
        self.runtime = None    # the previous model's memory is released before the next one is loaded
        self.runtime = Runtime(bdir, self.reg, device=device, fp_budget=self.state.get("fp_budget"), feat_device=feat_device,
                               approved_executables=cfg.get("approved_executables"), daily_budget=cfg.get("learned_daily_budget"),
                               keep_reset_state=False, ensure_entities=self._ensure_gids, seen_at_load_ns=time.time_ns())
        self.runtime.set_learned_alerts(bool(cfg.get("learned_alerts", True)))
        wns = int(self.runtime.m.get("window_ns") or 0)
        if wns and wns != self.builder.window_ns and not self.builder.pending:   # windows as long as the bundle was trained on
            self.builder.window_ns = wns
        first = self.state.get("bundle_id") is None
        self.state.set("bundle_id", bundle_id)
        self._prune_bundles(bundle_id)
        mat = self.runtime.m.get("maturity") or {}
        what = (f"early model, {mat.get('baseline_hours')} h of activity" if mat.get("early") else "final model")
        if mat.get("trained_until_ns"):    # the activity the model was built on is not scored again
            skipped = self.state.mark_scored_before(int(mat["trained_until_ns"]))
            log(f"bundle {bundle_id} verified and loaded ({what}); {skipped} already learned events skipped for scoring")
        elif first:   # older bundles: detection starts after the baseline; the days the bundle was built on are not re-scored
            skipped = self.state.mark_days_scored(list(self.runtime.m.get("train_days", [])) + [self.runtime.m.get("val_day")])
            log(f"bundle {bundle_id} verified and loaded; {skipped} baseline events skipped for scoring")
        else:
            log(f"bundle {bundle_id} verified and loaded")

    def _prune_bundles(self, keep: str):
        """Superseded models (early models are replaced as the endpoint learns) are removed from disk."""
        root = os.path.join(self.cfg.data_dir, "bundles")
        try:
            for d in os.listdir(root):
                if d != keep:
                    shutil.rmtree(os.path.join(root, d), ignore_errors=True)
        except OSError:
            pass

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
        allow = (sorted(cfg.get("trusted_addresses") or []), sorted(tuple(x) for x in (cfg.get("suppressed_detections") or [])))
        if allow != getattr(self, "_allow", None) and hasattr(self.runtime, "set_allowlist"):
            self.runtime.set_allowlist(*allow)
            if getattr(self, "_allow", None) is not None:
                log(f"allow list updated ({len(allow[0])} addresses, {len(allow[1])} detections)")
            self._allow = allow
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
        """Feed spooled events to the window builder and score each window it closes. A row is marked scored only
        once its window has been scored: after a restart the open window's rows are simply replayed."""
        rows = self.state.unscored_events(after=self._cursor, max_id=self._max_id)
        while rows:
            results = []
            loc = self.reg.local
            for r in rows:
                s, d = loc(r[2]), loc(r[4])
                if s is None or d is None:      # not expected (spooled entities are never compacted away)
                    self._ensure_gids([g for g, x in ((r[2], s), (r[4], d)) if x is None])
                    self.runtime.grow()
                    s, d = loc(r[2]), loc(r[4])
                self._open_ids.append(r[0])
                ev = (s, d, r[1], EDGE_TYPE_ID[r[3]], r[5])
                self._slice.append(ev)
                closed = list(self.builder.push(*ev))
                if closed:
                    self.run_rules(closed[0].start_ns)            # the rest of the closed window
                    for w in closed:
                        results.append((w, self.runtime.score(w, keep_edge_losses=True, hits=self._win_hits)))
                        self._win_hits = []
                    self.state.mark_scored(self._open_ids)    # everything pushed so far was in the closed window(s)
                    self._open_ids = []
            last = rows[-1]
            self._cursor = (last[1], last[0])
            self._max_id = max(self._max_id, max(r[0] for r in rows))
            self.run_rules(self.builder._start if self.builder._start is not None else (self._slice[0][2] if self._slice else 0))
            self.report(results)
            rows = self.state.unscored_events(after=self._cursor, max_id=self._max_id)

    def run_rules(self, window_start_ns: int) -> None:
        """Layers 1-2 on the events pushed since the last call (real-time path). Alerts they raise on their own are
        sent at once, seconds after the events instead of when the 15-minute window closes; the hits go to
        score() with the window, which then gives the same result as before (tests/unit/test_realtime.py)."""
        if not self._slice or self.runtime is None:
            return
        sl, self._slice = self._slice, []
        a = list(zip(*sl))
        mini = Window(start_ns=int(sl[0][2]), end_ns=int(sl[-1][2]), src=np.array(a[0], dtype=np.int64), dst=np.array(a[1], dtype=np.int64),
                      t=np.array(a[2], dtype=np.int64), etype=np.array(a[3], dtype=np.int64), event_uuid=list(a[4]))
        hits = self.runtime.rules(mini)
        self._win_hits += hits
        if not hits:
            return
        out = []
        now = time.time_ns()
        for n, rs in self.runtime.immediate_alerts(hits).items():
            e = self.reg[int(n)]
            layer = min((x["layer"] for x in rs), key=lambda x: {"novelty": 0, "rules": 1}.get(x, 9))
            main = next(x for x in rs if x["layer"] == layer)
            key = (e.uuid, main.get("rule"))
            if key in self._early:
                continue
            self._early[key] = now
            out.append((n, e, layer, main, rs))
        if not out:
            return
        disp = self.state.displays([e.uuid for _, e, _, _, _ in out])
        alerts = [{"window_start_ns": int(window_start_ns), "node": {"uuid": e.uuid, "ntype": e.ntype, "label": e.label, "display": disp.get(e.uuid) or e.display},
                   "fused": 0.0, "r1": 0.0, "r2": 0.0, "context": self.context(mini, None, int(n)), "layer": layer, "rule": main.get("rule"),
                   "reason": main.get("detail"), "reasons": rs} for n, e, layer, main, rs in out]
        self._save_early()
        self._unreported = getattr(self, "_unreported", [])
        self._unreported.append(([], alerts))
        self._save_unreported()
        log(f"real-time: {len(alerts)} rule alerts ({', '.join(sorted({a['rule'] for a in alerts}))})")

    def _save_early(self):
        cut = time.time_ns() - 2 * 3600 * 10**9          # longer than a window plus a restart
        self._early = {k: t for k, t in self._early.items() if t >= cut}
        self.state.set("early_alerts", [[k[0], k[1], t] for k, t in self._early.items()])

    def flush_window(self):
        self.run_rules(self.builder._start or 0)
        results = [(w, self.runtime.score(w, keep_edge_losses=True, hits=self._win_hits)) for w in self.builder.finish()]
        self._win_hits = []
        if results:
            self.state.mark_scored(self._open_ids)
            self._open_ids = []
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
        l1 = r.edge_loss.get("detector-1") if r is not None else None
        nodes = [{"uuid": self.reg[i].uuid, "ntype": self.reg[i].ntype, "label": self.reg[i].label} for i in sorted(keep)[:cap]]
        edges = [{"src": self.reg[int(src[i])].uuid, "dst": self.reg[int(dst[i])].uuid, "op": EDGE_TYPES[int(w.etype[i])], "ts_ns": int(w.t[i]),
                  "loss": float(l1[i]) if l1 is not None else None} for i in idx]
        return {"nodes": nodes, "edges": edges}

    def report(self, results: list[tuple[Window, WindowResult]]):
        self._unreported = getattr(self, "_unreported", [])
        if not results and not self._unreported:
            return
        wins, alerts = [], []
        disp = self.state.displays(list({self.reg[int(n)].uuid for _, r in results for n in r.alerts}))
        for w, r in results:
            wins.append(r.summary())
            self._last_window_end = max(self._last_window_end, int(w.end_ns))
            pos = {int(n): i for i, n in enumerate(r.node_ids)}
            for n in r.alerts:
                i = pos.get(int(n))
                if i is None:
                    continue
                e = self.reg[int(n)]
                rs = r.reasons.get(int(n)) or [{"layer": "learned", "rule": "learned_score", "detail": f"learned score {float(r.fused[i]):.2f}x the benign maximum"}]
                layer = r.layer_of(int(n))
                main = next(x for x in rs if x["layer"] == layer)
                if layer in ("rules", "novelty") and (e.uuid, main.get("rule")) in self._early:
                    continue                      # already sent in real time
                alerts.append({"window_start_ns": w.start_ns, "node": {"uuid": e.uuid, "ntype": e.ntype, "label": e.label, "display": disp.get(e.uuid) or e.display},
                               "fused": float(r.fused[i]), "r1": float(r.r1[i]), "r2": float(r.r2[i]), "context": self.context(w, r, int(n)),
                               "layer": layer, "rule": main.get("rule"), "reason": main.get("detail"), "reasons": rs})
        if wins or alerts:
            self._unreported.append((wins, alerts))
            self._save_unreported()
        if not self._online():
            return                                  # delivered when the server is back (kept on disk meanwhile)
        try:
            while self._unreported:
                w0, a0 = self._unreported[0]
                if w0:
                    self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/windows", w0)
                if a0:
                    self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/alerts", a0)
                    log(f"reported {len(a0)} alerts in {len(w0)} windows")
                self._unreported.pop(0)
                self._save_unreported()
        except (TransportError, OSError) as e:
            log(f"report deferred ({len(self._unreported)} batches pending): {e}")
            self._went_offline(time.time(), e)

    # ------------------------------------------------------------------ main loop
    def run(self, source):
        self.source = source
        self.chronological = bool(getattr(source, "chronological", self.chronological))
        self.connect()
        if self.load_local_bundle():
            old = self.state.get("window_builder")    # agents up to 0.3.4 saved the open window (ids = global ids then)
            if old and self.reg.gids is None:
                self.builder.load_state(old)
                if self.builder.pending:
                    log(f"resumed open window with {self.builder.pending} buffered events")
            self.state.set("window_builder", None)
        if self.state.get("isolated"):         # isolation survives an agent restart (DNS may already be blocked:
            if self.tr is not None and self.state.get("isolated_addrs"):        # the saved server addresses first)
                self.tr.pinned = list(self.state.get("isolated_addrs"))
            log(f"response: re-applying network isolation: {self.isolate()}")
        last_hb, last_status, last_purge = 0, 0, time.time()
        self._offline_since = 0
        self._reachable = threading.Event()
        self._unreported = [tuple(x) for x in (self.state.get("unreported") or [])] + getattr(self, "_unreported", [])
        if self._unreported:
            log(f"{len(self._unreported)} alert/window batches from before the restart are waiting to be delivered")
        threading.Thread(target=self._probe, daemon=True, name="pdp-probe").start()
        for batch in source.batches(lambda: self.stop):   # source yields lists of (entities, Event); empty list = idle tick
            try:
                if batch:
                    self.ingest(batch)
                now = time.time()
                if now - last_status > self.cfg.status_interval and self._online():
                    # Server contact is best-effort: collection, spooling and local detection continue while the
                    # server is unreachable, and uploads resume from the sqlite spool on the next successful contact.
                    try:
                        st = self.tr.request("GET", f"/v1/endpoints/{self.eid}/status")
                        phase = st["phase"]; self.state.set("phase", phase)
                        if isinstance(st.get("config"), dict):      # the server owns the endpoint configuration
                            self.state.set("config", st["config"])
                            self._apply_fp_budget(st["config"].get("fp_budget"))
                            self._apply_layer_config(st["config"])
                        if self._offline_since:
                            log(f"server reachable again after {now - self._offline_since:.0f}s; catching up")
                            self._offline_since = 0
                        if phase == "baseline" or (phase == "protected" and (st.get("config") or {}).get("refresh_days")):
                            self.upload_baseline()     # keeps learning, also while an early model detects; fresh days later
                        if phase in ("baseline", "protected"):
                            b = st.get("bundle")       # while learning: an early model (server 0.5), replaced as it improves
                            if b and b["id"] != self.state.get("bundle_id") and b["id"] != getattr(self, "_bad_bundle", None):
                                try:
                                    self.fetch_bundle(b["id"])
                                except (TransportError, OSError):
                                    raise
                                except Exception as e:  # noqa - a model this agent cannot use must not stop it
                                    self._bad_bundle = b["id"]
                                    log(f"bundle {b['id']} could not be loaded ({type(e).__name__}: {e}); keeping the current model")
                                    if self.runtime is None:          # it was released for the new one: load it again
                                        self.load_local_bundle()
                        for cmd in st.get("commands", []):
                            self.handle_command(cmd)
                        self._update_offer = st.get("update")
                        if self._update_offer and self.request_update(self._update_offer):
                            break
                        if self._unreported:
                            self.report([])            # alerts held while offline
                    except (TransportError, OSError) as e:
                        self._went_offline(now, e)
                    last_status = now
                if self.runtime is not None:
                    self.score_backlog()
                if now - last_purge > 60:   # spool hygiene: finished rows go, the size cap is enforced
                    self.purge_spool()
                    last_purge = now
                self.maybe_compact(now)
                if now - self._obs_flush > 60:
                    self._obs_flush = now
                    try:
                        self.state.add_observables(self._obs)
                        if int(now) % 3600 < 60:
                            self.state.prune_observables()
                    except Exception as e:  # noqa - the index is best effort
                        log(f"activity index: {e}")
                    self._obs = {}
                if now - last_hb > self.cfg.heartbeat_interval and self._online():
                    try:
                        self.tr.request("POST", f"/v1/endpoints/{self.eid}/heartbeat", self.health())
                        self.confirm_update()
                    except (TransportError, OSError) as e:
                        self._went_offline(now, e)
                    last_hb = now
            except sqlite3.OperationalError as e:      # a full disk must not stop the agent (crash loop): it keeps
                if not disk_full(e):                   # running, drops what it cannot store (counted, in the heartbeat)
                    raise                               # and continues by itself once there is space again
                self._disk_full(e)
            except OSError as e:
                if e.errno != errno.ENOSPC:
                    raise
                self._disk_full(e)

    def data_usage(self) -> dict:
        """What the agent keeps on this host, in MB: the local database (event spool, entity registry, activity
        index) and the detection model. Reported in the heartbeat so the console shows the agent's footprint."""
        def size(p):
            try:
                return os.path.getsize(p)
            except OSError:
                return 0
        db = sum(size(os.path.join(self.cfg.data_dir, f)) for f in ("state.sqlite", "state.sqlite-wal", "state.sqlite-shm"))
        models = 0
        for root, _d, files in os.walk(os.path.join(self.cfg.data_dir, "bundles")):
            models += sum(size(os.path.join(root, f)) for f in files)
        return {"database": round(db / 1e6, 1), "models": round(models / 1e6, 1), "total": round((db + models) / 1e6, 1)}

    def spool_max_bytes(self) -> int:
        """Configured cap (server config, else agent config), never more than 10% of the data file system."""
        mb = (self.state.get("config") or {}).get("spool_max_mb") or self.cfg.spool_max_mb
        try:
            st = os.statvfs(self.cfg.data_dir)
            fs = st.f_blocks * st.f_frsize
        except OSError:
            fs = 0
        cap = int(mb) << 20
        return min(cap, fs // 10) if fs else cap

    def purge_spool(self):
        try:
            r = self.state.purge(self.baseline_days(), scoring=self.runtime is not None,
                                 unscored_max_age_s=float(self.cfg.spool_unscored_max_age_h) * 3600, max_bytes=self.spool_max_bytes())
        except Exception as e:  # noqa - hygiene must never stop collection
            log(f"spool purge failed: {e}")
            return
        if r["dropped_unscored"] or r["dropped_unuploaded"]:
            log(f"spool over its size cap: dropped {r['dropped_unscored']} events before local scoring and "
                f"{r['dropped_unuploaded']} before upload")

    # ------------------------------------------------------------------ updates
    UPD_RE = re.compile(r"^[A-Za-z0-9._:/@-]{1,300}$")

    def _upd(self, name: str) -> str:
        return os.path.join(self.cfg.data_dir, name)

    def failed_versions(self) -> list[str]:
        try:
            return sorted({x.strip() for x in open(self._upd("update-failed")) if x.strip()})
        except OSError:
            return []

    def update_health(self) -> dict:
        """What the console shows about updates: offered/updating/trial/failed."""
        failed = self.failed_versions()
        st = {"state": "none", "failed": failed, "updater": self.updater}
        if os.path.exists(self._upd("update-request.env")):
            st["state"] = "updating"
        elif os.path.exists(self._upd("update-trial.env")) and not self._confirmed():
            st["state"] = "trial"         # (the host updater clears the trial files only at the next start)
        elif self._update_offer:
            v = self._update_offer.get("version")
            st["state"] = "failed" if v in failed else "offered" if self.updater else "available"
            st["version"] = v
        return st

    def request_update(self, offer: dict) -> bool:
        """Hand an update to the host's updater: a short-lived pull credential and the image, then stop (systemd
        starts us again; the updater pulls and switches before the start). True when the agent is stopping."""
        v = str(offer.get("version") or "")
        if not self.updater or v == VERSION or v in self.failed_versions():
            return False
        try:     # the updater could not pull last time: try again after an hour, not on every status check
            if time.time() - os.path.getmtime(self._upd("update-backoff")) < 3600:
                return False
        except OSError:
            pass
        try:
            r = self.tr.request("POST", f"/v1/endpoints/{self.eid}/pull-token")
        except (TransportError, OSError) as e:
            log(f"update to {v}: no pull credential yet ({e})")
            return False
        vals = {"VERSION": v, "IMAGE": r.get("image", ""), "REGISTRY": r.get("registry", ""), "TOKEN": r.get("token", "")}
        if not all(self.UPD_RE.match(x) for x in vals.values()):
            log(f"update to {v}: refused, unexpected characters in the server's answer")
            return False
        tmp = self._upd("update-request.env.tmp")
        with open(tmp, "w") as f:
            f.write("".join(f"{k}={x}\n" for k, x in vals.items()))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._upd("update-request.env"))
        log(f"update to agent {v} requested ({vals['IMAGE']}); restarting through the updater")
        self.exit_code = 75
        self.stop = True
        return True

    def kernel_btf(self) -> str | None:
        """BTF for the eBPF collector on kernels without /sys/kernel/btf/vmlinux: a local file, else one the server
        has for this kernel release (GET /v1/btf/<release>; raw .btf, or BTFHub's .btf.tar.xz unpacked here)."""
        from .sources.ebpf import find_btf, KERNEL_BTF
        if os.path.exists(KERNEL_BTF):
            return None
        f = find_btf(self.cfg.data_dir)
        if f or self.tr is None or not self.eid:
            return f
        rel = os.uname().release
        dst = os.path.join(self.cfg.data_dir, "btf", rel + ".btf")
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tmp = dst + ".part"
            self.tr.download(f"/v1/endpoints/{self.eid}/btf/{rel}", tmp)
            with open(tmp, "rb") as fh:
                head = fh.read(6)
            if head.startswith(b"\xfd7zXZ"):           # BTFHub archive: <release>.btf.tar.xz with one .btf member
                import tarfile
                with tarfile.open(tmp, "r:xz") as t:
                    m = next(m for m in t.getmembers() if m.isfile() and m.name.endswith(".btf"))
                    with t.extractfile(m) as src, open(dst + ".x", "wb") as out:
                        shutil.copyfileobj(src, out)
                os.replace(dst + ".x", dst); os.remove(tmp)
            else:
                os.replace(tmp, dst)
            log(f"collector: BTF for kernel {rel} downloaded from the server")
            return dst
        except Exception as e:  # noqa - reported through the collector error
            for x in (dst + ".part", dst + ".x"):
                try:
                    os.remove(x)
                except OSError:
                    pass
            log(f"collector: no BTF for kernel {rel} from the server ({e})")
            return None

    def _confirmed(self) -> bool:
        try:
            with open(self._upd("update-ok")) as f:
                return f.read().strip() == VERSION
        except OSError:
            return False

    def confirm_update(self) -> None:
        """First successful heartbeat on a new version: tell the updater this version works (no rollback)."""
        if os.path.exists(self._upd("update-trial.env")) and not os.path.exists(self._upd("update-ok")):
            with open(self._upd("update-ok"), "w") as f:
                f.write(VERSION + "\n")
            log(f"agent {VERSION} confirmed working after the update")

    # ------------------------------------------------------------------ control
    def handle_command(self, cmd: dict):
        """Server commands (queued from the console). Each is acknowledged so it is delivered once."""
        cid = cmd.get("id")
        result = "ok"
        try:
            if "fp_budget" in cmd:
                self._apply_fp_budget(cmd["fp_budget"])
            elif cmd.get("command") == "kill_process":
                result = self.kill_process(int(cmd["pid"]), str(cmd.get("uuid") or ""), str(cmd.get("label") or ""))
            elif cmd.get("command") == "isolate":
                result = self.isolate()
            elif cmd.get("command") == "release":
                result = self.release()
            elif cmd.get("command") == "hunt":
                self.state.add_observables(self._obs); self._obs = {}
                rows = self.state.hunt(str(cmd.get("q") or ""), cmd.get("kind") or None, int(cmd.get("limit") or 200))
                self.tr.post_ndjson(f"/v1/endpoints/{self.eid}/hunts/{cmd['hunt_id']}", rows or [{"none": True}])
                result = f"ok: {len(rows)} matches"
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

    # ------------------------------------------------------------------ response actions
    def kill_process(self, pid: int, uuid: str, label: str) -> str:
        """Stop the process an alert was raised on - only if the pid still is that process (the collector's table
        maps it to the same identity; a pid reused by another program is never touched)."""
        import signal
        if pid <= 1 or pid == os.getpid():
            return "refused: protected process"
        procs = getattr(getattr(self, "source", None), "procs", None)
        cur = getattr(procs, "current", {}).get(pid) if procs is not None else None
        if procs is not None and (cur is None or cur.uuid != uuid):
            return "not stopped: that process has already ended (its pid is free or used by another program now)"
        exe = label.split(" ")[1] if label.startswith("subject ") and len(label.split(" ")) > 1 else None
        try:
            real = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return "not stopped: the process has already ended"
        if exe and exe not in ("None", real) and os.path.basename(exe) != os.path.basename(real):
            return f"not stopped: pid {pid} now runs {real}, not {exe}"
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return "not stopped: the process has already ended"
        log(f"response: stopped pid {pid} ({real})")
        return f"ok: stopped pid {pid} ({real})"

    def _server_addrs(self) -> tuple[list[str], list[int]]:
        import socket
        from urllib.parse import urlparse
        addrs, ports = set(), set()
        for url in {self.cfg.agent_url, self.cfg.server_url}:
            u = urlparse(url)
            ports.add(u.port or 443)
            try:
                for info in socket.getaddrinfo(u.hostname, None):
                    addrs.add(info[4][0])
            except OSError:
                if not self.state.get("isolated_addrs"):
                    raise
        addrs |= set(self.state.get("isolated_addrs") or []) if not addrs else set()
        return sorted(addrs), sorted(ports | {443})

    def isolate(self) -> str:
        """Network isolation: everything dropped except loopback, established connections, the PDP server on its
        ports and DNS to the host's own resolvers (the agent must still reach the server to be released). Re-applied
        when the agent starts while isolated."""
        import subprocess
        try:
            addrs, ports = self._server_addrs()
        except OSError as e:
            return f"not isolated: cannot resolve the server ({e})"
        # no DNS while isolated (a resolver is a way out): the agent connects to the addresses resolved now
        srv4 = ", ".join(a for a in addrs if ":" not in a); srv6 = ", ".join(a for a in addrs if ":" in a)
        pl = ", ".join(str(p) for p in ports)
        out_rules = []
        if srv4: out_rules.append(f"ip daddr {{ {srv4} }} tcp dport {{ {pl} }} accept")
        if srv6: out_rules.append(f"ip6 daddr {{ {srv6} }} tcp dport {{ {pl} }} accept")
        ruleset = ("table inet pdp_isolate\ndelete table inet pdp_isolate\ntable inet pdp_isolate {\n"
                   "  chain input { type filter hook input priority -200; policy drop; iif \"lo\" accept; ct state established,related accept; }\n"
                   "  chain forward { type filter hook forward priority -200; policy drop; ct state established,related accept; }\n"
                   "  chain output { type filter hook output priority -200; policy drop; oif \"lo\" accept; ct state established,related accept; "
                   + " ".join(r + ";" for r in out_rules) + " }\n}\n")
        r = subprocess.run(["nft", "-f", "-"], input=ruleset, capture_output=True, text=True)
        if r.returncode != 0:
            return f"not isolated: nft failed: {r.stderr.strip()[:300]}"
        self.state.set("isolated", True)
        self.state.set("isolated_addrs", addrs)
        if self.tr is not None:
            self.tr.pinned = addrs
        log(f"response: endpoint isolated (only the server {addrs} on ports {ports} is reachable)")
        return f"ok: isolated; only the PDP server ({', '.join(addrs)}) is reachable; check: {self._isolation_check(addrs, ports)}"

    @staticmethod
    def _isolation_check(addrs, ports) -> str:
        """Self-test right after isolating: an outside address must be unreachable, the server reachable."""
        import socket
        def can(host, port):
            try:
                socket.create_connection((host, port), timeout=3).close(); return True
            except OSError:
                return False
        outside = can("1.1.1.1", 443) or can("8.8.8.8", 53)
        server = any(can(a, p) for a in addrs for p in ports)
        return ("outside blocked" if not outside else "OUTSIDE STILL REACHABLE") + ", " + ("server reachable" if server else "SERVER UNREACHABLE")

    def release(self) -> str:
        import subprocess
        subprocess.run(["nft", "delete", "table", "inet", "pdp_isolate"], capture_output=True, text=True)
        self.state.set("isolated", False)
        if self.tr is not None:
            self.tr.pinned = None
        log("response: network isolation released")
        return "ok: released"

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
        # (rows of the open window stay unscored until it closes, so they are in unscored_count already)
        q = self.state.unscored_count() if self.runtime is not None else self.state.unuploaded_count()
        h = {"agent_version": VERSION, "queue_depth": int(q), "last_window_end_ns": int(self._last_window_end),
             "cpu_pct": round(cpu, 1), "rss_mb": round(rss, 1), "spool_mb": round(self.state.size_bytes() / 2**20, 1), "entities": len(self.reg),
             "spool_dropped_unscored": int(self.state.get("dropped_unscored", 0)),
             "spool_dropped_unuploaded": int(self.state.get("dropped_unuploaded", 0)), "update": self.update_health(),
             "disk_full_dropped": self._dropped_disk_full, "disk_full": bool(self._disk_full_since),
             "data_mb": self.data_usage(),
             "isolated": bool(self.state.get("isolated", False))}
        try:
            st = os.statvfs(self.cfg.data_dir)
            h["disk_free_mb"] = round(st.f_bavail * st.f_frsize / 2**20, 1)
            h["disk_free_pct"] = round(100.0 * st.f_bavail / max(st.f_blocks, 1), 1)
        except OSError:
            pass
        err = getattr(getattr(self, "source", None), "error", None)
        if err:
            h["collector_error"] = err
        try:   # collector health (CO-RE eBPF): records the kernel dropped (ring buffer full), and records the loader dropped
               # because the agent fell behind reading them
            tr = getattr(getattr(self, "source", None), "_tracer", None)
            if tr is not None and getattr(tr, "stats", None) is not None and type(tr).__name__ == "CoreTracer":
                h["collector_lost"] = int(tr.stats.get("lost", 0))
                h["collector_behind"] = int(tr.stats.get("behind", 0))
                # the same counts over the last hour: a burst long ago is not a current problem
                now = time.time()
                hist = self.__dict__.setdefault("_lost_hist", [])
                hist.append((now, h["collector_lost"], h["collector_behind"]))
                while len(hist) > 1 and hist[1][0] <= now - 3600:
                    hist.pop(0)
                h["collector_lost_1h"] = h["collector_lost"] - hist[0][1]
                h["collector_behind_1h"] = h["collector_behind"] - hist[0][2]
        except Exception:  # noqa - health must never fail
            pass
        return h
