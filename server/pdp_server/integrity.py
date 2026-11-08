"""Integrity of the endpoint signal (0.6): can the server trust that an endpoint which looks healthy is really being
watched? An attacker with root on a monitored host can stop or detach the collector, drop alerts before they leave
the host, swap the model or its signing key, or stop the agent and keep the console green by re-sending its last
heartbeat. Every such attempt is turned into an endpoint health problem (console) and an `agent_health`
notification; the detection-relevant ones are errors (notified as high severity).

What the agent (0.6+) sends and the server checks (docs/PROTOCOL.md, "Integrity of the endpoint signal (0.6)"):

  heartbeat sequence  hb_seq (persisted on the agent, survives restarts) + run_id/started_at (one per agent process).
                      A sequence number that does not increase within one run is a replayed heartbeat: it is not
                      stored as the endpoint's health (which therefore goes stale) and is reported. A sequence that
                      goes back at a restart means the agent's local state was reset or restored.
  liveness            counters since the previous heartbeat (events collected, dropped, windows scored, alerts raised)
                      and the collector's state. A host that normally never goes quiet and reports no events for
                      longer than it ever did is "collection stopped". eBPF agents also watch a canary: a child
                      process opens a known file every minute and the collector must see it.
  delivery            every window summary and alert carries a per-endpoint sequence number; when the agent says it
                      has nothing left to deliver, every number up to its last one must have arrived.
  model               the loaded bundle id, its manifest sha256 and the signing-key fingerprint, compared with the
                      endpoint's current bundle and the server's own key.
  configuration       sha256 of the agent's effective local configuration and its source kind.
  clock               the agent's wall clock.

Agents before 0.6 send none of this: they are never flagged for missing fields; their posture is "unsupported".
Everything here is general (no per-client constants); the thresholds below are environment-overridable defaults.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import zlib


def _q(c, sql, args=(), one=False):
    """db.q, imported on use: health.py (and so this module) is also loaded where there is no database driver."""
    from . import db
    return db.q(c, sql, args, one=one)


FINDING_TTL_S = float(os.environ.get("PDP_INTEGRITY_FINDING_H", "24")) * 3600   # a one-off finding shows this long
HB_STALE_S = float(os.environ.get("PDP_INTEGRITY_HB_STALE_S", "300"))      # min. heartbeat silence while the agent calls in
QUIET_MIN_S = float(os.environ.get("PDP_INTEGRITY_QUIET_MIN_S", "1800"))   # collection stopped: never sooner than this
QUIET_FACTOR = float(os.environ.get("PDP_INTEGRITY_QUIET_FACTOR", "2"))    # ... nor before 2x the longest silence seen
QUIET_MAX_S = float(os.environ.get("PDP_INTEGRITY_QUIET_MAX_S", str(6 * 3600)))   # hosts quieter than this: not judged
QUIET_HISTORY_S = float(os.environ.get("PDP_INTEGRITY_QUIET_HISTORY_S", str(24 * 3600)))   # history needed first
QUIET_DAYS = 7                                                              # silences remembered (per UTC day)
CANARY_MISSED = int(os.environ.get("PDP_INTEGRITY_CANARY_MISSED", "3"))    # consecutive canaries not seen
BUNDLE_GRACE_S = float(os.environ.get("PDP_INTEGRITY_BUNDLE_GRACE_S", "3600"))   # a new model must be loaded by then
BUNDLE_SETTLE_S = 600                                    # ... and the mismatch has lasted this long (re-fetch, reload)
CLOCK_SKEW_S = float(os.environ.get("PDP_INTEGRITY_CLOCK_SKEW_S", "300"))
MIN_VERSION = (0, 6, 0)
LIVE_SOURCES = {"ebpf", "auditd", "etw"}                 # collectors that watch the whole host
PARTIAL_SOURCES = {"strace"}                              # one traced program only

# ingest bounds (agent uploads)
MAX_BODY = int(os.environ.get("PDP_INGEST_MAX_BYTES", str(1 << 30)))      # decompressed request body
MAX_RATIO = int(os.environ.get("PDP_INGEST_MAX_RATIO", "200"))             # ... and its compression ratio (above 64 MB)
MAX_ROWS = int(os.environ.get("PDP_INGEST_MAX_ROWS", "250000"))            # rows per request
MAX_DAYS_PER_BATCH = int(os.environ.get("PDP_INGEST_MAX_DAYS", "8"))        # daily partitions one event batch may touch
# security review F11: what one endpoint may upload per rolling 24 hours (compressed bytes as sent, and rows), over all
# its event / entity uploads; a per-endpoint override lives in its config (ingest_daily_bytes / ingest_daily_rows,
# set by the operator). A busy server uploads about 0.7 GB and 60 M events a day.
DAILY_BYTES = int(os.environ.get("PDP_INGEST_DAILY_BYTES", str(8 << 30)))
DAILY_ROWS = int(os.environ.get("PDP_INGEST_DAILY_ROWS", str(200_000_000)))
TS_FLOOR_NS = 946_684_800 * 10**9                         # 2000-01-01: no endpoint (nor a replayed dataset) is older
DAY_S = 86400
DAY_NS_ = DAY_S * 10**9                                     # = db.DAY_NS (partitions)


class IngestError(ValueError):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


# ================================================================================================ helpers
def version_tuple(v: str | None) -> tuple:
    out = []
    for p in str(v or "").split(".")[:3]:
        digits = "".join(ch for ch in p if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out + [0] * (3 - len(out)))


def supported(h: dict) -> bool:
    """The heartbeat comes from an agent that implements the integrity protocol."""
    return h.get("hb_seq") is not None


def key_fingerprint(pem: str | bytes) -> str:
    """sha256 (hex) of a public key's DER SubjectPublicKeyInfo; the agent computes the same."""
    from cryptography.hazmat.primitives import serialization
    pem = pem.encode() if isinstance(pem, str) else pem
    k = serialization.load_pem_public_key(pem)
    return hashlib.sha256(k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


_FP: dict = {}


def server_signing_fp() -> str | None:
    if "fp" not in _FP:
        try:
            from . import pki
            _FP["fp"] = key_fingerprint(pki.signing_public_pem())
        except Exception:  # noqa - no PKI in this process (tests): the key check is skipped
            _FP["fp"] = None
    return _FP["fp"]


def _finding(key: str, level: str, text: str, now: float) -> dict:
    return {"key": key, "level": level, "text": text, "at": now}


def _fmt_dur(s: float) -> str:
    s = int(s)
    if s >= 7200:
        return f"{s // 3600} hours"
    if s >= 120:
        return f"{s // 60} minutes"
    return f"{s} seconds"


# ================================================================================================ heartbeat
def evaluate(st: dict, hb: dict, ctx: dict, now: float) -> tuple[dict, list[dict], list[dict], bool]:
    """Pure check of one heartbeat. st: the endpoint's stored integrity state; hb: the heartbeat as received;
    ctx: {kind, phase, current_bundle, bundle_sha256, bundle_created (epoch s), signing_fp}.

    Returns (new state, new one-off findings, ongoing problems, accept). accept=False: the heartbeat is a replay and
    must not become the endpoint's health."""
    st = dict(st or {})
    found: list[dict] = []
    active: list[dict] = []
    live = ctx.get("kind", "live") == "live"
    if not supported(hb):
        st["posture"] = "unsupported"
        return st, found, active, True
    st["posture"] = "checked"
    seq, run, started = int(hb["hb_seq"]), str(hb.get("run_id") or ""), float(hb.get("started_at") or 0)
    pseq, prun, pstarted = st.get("seq"), st.get("run_id"), float(st.get("started_at") or 0)
    if pseq is not None and seq <= int(pseq):
        if run == prun or (pstarted and started and started < pstarted):
            what = "the same agent run" if run == prun else "an earlier agent run"
            found.append(_finding(f"heartbeat_replay:{int(now)}", "error",
                                  f"A heartbeat was sent again (sequence {seq} after {pseq}, from {what}): someone is "
                                  "re-sending the agent's old status, for example after stopping the agent. The endpoint's "
                                  "health is not updated from it", now))
            return st, found, active, False
        found.append(_finding(f"heartbeat_reset:{int(now)}", "warning",
                              f"The agent restarted with its sequence number back at {seq} (was {pseq}): its local state "
                              "was deleted or restored from an older copy", now))
    prev_at = st.get("hb_at")
    st.update({"seq": seq, "run_id": run, "started_at": started, "hb_at": now})
    st.setdefault("since", now)
    episodes = dict(st.get("episodes") or {})

    def ongoing(name: str, cond: bool, level: str, text: str, min_s: float = 0):
        """A condition that lasts: one key per episode (notified once); shown once it has lasted min_s."""
        if cond:
            t0 = episodes.setdefault(name, now)
            if now - t0 >= min_s:
                active.append({"key": f"{name}:{int(t0)}", "level": level, "text": text})
        else:
            episodes.pop(name, None)

    # ---- liveness: events since the previous heartbeat; silences remembered per day
    ctr = hb.get("counters") or {}
    src = hb.get("source") or {}
    ev = ctr.get("events")
    hist = {d: v for d, v in (st.get("quiet_hist") or {}).items() if d >= time.strftime("%Y-%m-%d", time.gmtime(now - QUIET_DAYS * DAY_S))}
    if ev is not None:
        if int(ev) > 0:
            if st.get("quiet_since"):
                q = now - float(st["quiet_since"])
                d = time.strftime("%Y-%m-%d", time.gmtime(now))
                hist[d] = max(float(hist.get(d, 0)), q)
            st["quiet_since"] = None
        elif not st.get("quiet_since"):
            st["quiet_since"] = float(prev_at or now)
    st["quiet_hist"] = hist
    learned = max([float(v) for v in hist.values()] or [0.0])
    threshold = max(QUIET_MIN_S, QUIET_FACTOR * learned)
    quiet = now - float(st["quiet_since"]) if st.get("quiet_since") else 0.0
    judged = live and threshold <= QUIET_MAX_S and now - float(st["since"]) >= QUIET_HISTORY_S and not hb.get("collector_error")
    ongoing("collection_stopped", judged and quiet >= threshold, "error",
            f"The agent is running but its collector has reported no activity for {_fmt_dur(quiet)}; this host was never "
            f"silent for more than {_fmt_dur(learned)} before. Collection may have been stopped or detached: nothing on it is "
            "being recorded or detected")
    can = src.get("canary") or {}
    ongoing("collector_blind", live and int(can.get("missed") or 0) >= CANARY_MISSED, "error",
            f"The collector did not see the agent's test activity {int(can.get('missed') or 0)} times in a row (a file opened "
            "every minute): it is not observing this host. Collection may have been detached or tampered with"
            + (" (it also lost events: the host may be overloaded)" if (hb.get("collector_lost_1h") or hb.get("collector_behind_1h")) else ""))
    kind = src.get("kind")
    if live and kind:
        ongoing("source_kind", kind not in LIVE_SOURCES, "warning" if kind in PARTIAL_SOURCES else "error",
                f"The agent's collector is '{kind}', which does not watch the whole host"
                + (" (only one traced program)" if kind in PARTIAL_SOURCES else ": this endpoint is not being monitored"))
    # ---- scoring failures (a window the detector cannot score is skipped, not retried forever)
    nf = int(hb.get("score_failures_24h") or 0)
    ongoing("scoring_failed", nf > 0, "error",
            f"Detection failed on {nf} window{'s' if nf != 1 else ''} of activity in the last 24 hours; that activity was not "
            "checked for attacks (the agent skipped it so detection could go on)")
    # ---- clock
    at = hb.get("agent_time")
    skew = float(at) - now if at else 0.0
    ongoing("clock_skew", live and abs(skew) > CLOCK_SKEW_S, "error" if abs(skew) > 3600 else "warning",
            f"The endpoint's clock is {_fmt_dur(abs(skew))} {'ahead' if skew > 0 else 'behind'}: activity is placed at the "
            "wrong time and days may be cut wrongly")
    # ---- model
    b = hb.get("bundle") or {}
    sfp = ctx.get("signing_fp")
    if b.get("refused"):
        r = b["refused"]
        found.append(_finding(f"bundle_refused:{r.get('id')}", "error",
                              f"The agent refused model {r.get('id')}: {str(r.get('reason') or '')[:300]}", now))
    key_bad = bool(sfp and b.get("signing_key_fp") and b["signing_key_fp"] != sfp)
    ongoing("bundle_key", key_bad, "error",
            "The agent verifies models with a signing key that is not this server's: someone replaced it, so a forged "
            "model could be loaded")
    ongoing("bundle_key_pin", bool(b.get("pinned_key_fp") and b.get("signing_key_fp") and b["pinned_key_fp"] != b["signing_key_fp"]),
            "error", "The model signing key on the endpoint differs from the one pinned at enrolment; the agent refuses models signed with it")
    cur, created = ctx.get("current_bundle"), ctx.get("bundle_created")
    loaded = b.get("id")
    grace_over = bool(created) and now - float(created) > BUNDLE_GRACE_S
    if "id" in b and cur and ctx.get("phase") in ("baseline", "protected", "degraded"):
        ongoing("bundle_mismatch", grace_over and str(loaded or "") != str(cur), "error",
                (f"The agent detects with model {loaded}, not with the current model {cur} published "
                 f"{_fmt_dur(now - float(created or now))} ago" if loaded else
                 f"The agent has no detection model loaded although model {cur} was published {_fmt_dur(now - float(created or now))} ago")
                + ": its detection is not what the console shows", min_s=BUNDLE_SETTLE_S)   # a re-fetch takes a moment
        sha_bad = bool(loaded and str(loaded) == str(cur) and b.get("manifest_sha256") and ctx.get("bundle_sha256")
                       and b["manifest_sha256"] != ctx["bundle_sha256"])
        ongoing("bundle_modified", sha_bad, "error",
                "The model loaded on the endpoint is not the one the server published (its manifest digest differs): it was modified")
    # ---- configuration
    cs = hb.get("config_sha256")
    if cs:
        if st.get("config_sha256") and cs != st["config_sha256"]:
            found.append(_finding(f"config_changed:{int(now)}", "info",
                                  "The agent's local configuration on the endpoint was changed" + (f" (collector: {kind})" if kind else ""), now))
        st["config_sha256"] = cs
    st["episodes"] = episodes
    return st, found, active, True


def seq_findings(kind: str, lo: int, hi: int, missing: list[int], lost: list, now: float) -> list[dict]:
    """Findings for sequence numbers in (lo, hi] that never arrived. `lost`: [[a, b], ...] ranges the agent itself
    reports as dropped (its delivery queue overflowed during a long outage): reported, but not as tampering."""
    def in_lost(s):
        return any(int(a) <= s <= int(b) for a, b in lost or [])
    gone = [s for s in missing if not in_lost(s)]
    capped = [s for s in missing if in_lost(s)]
    what = {"a": "alerts", "w": "window summaries"}[kind]
    out = []
    if gone:
        rng = f"{gone[0]}" if len(gone) == 1 else f"{gone[0]}..{gone[-1]}"
        out.append(_finding(f"{kind}_seq_gap:{gone[0]}", "error",
                            f"{len(gone)}{'+' if len(gone) >= 50 else ''} {what} produced on the endpoint never reached the server "
                            f"(sequence {rng}): they were removed before delivery - alerts may be being suppressed", now))
    if capped:
        out.append(_finding(f"{kind}_seq_lost:{capped[0]}", "warning",
                            f"{len(capped)} {what} were dropped by the agent's delivery queue during a long outage", now))
    return out


def lost_seqs(hb: dict, kind: str) -> list:
    return list(((hb.get("lost_seqs") or {}).get(kind)) or [])


def _missing(c, endpoint_id: str, kind: str, lo: int, hi: int, cap: int = 50) -> list[int]:
    n = _q(c, "SELECT count(*) AS n FROM integrity_seqs WHERE endpoint_id=%s AND kind=%s AND seq > %s AND seq <= %s",
             (endpoint_id, kind, lo, hi), one=True)["n"]
    if n >= hi - lo:
        return []
    return [r["s"] for r in _q(c, "SELECT s FROM generate_series(%s::bigint, %s::bigint) s WHERE NOT EXISTS (SELECT 1 FROM integrity_seqs "
                                    "WHERE endpoint_id=%s AND kind=%s AND seq=s) ORDER BY s LIMIT %s", (lo + 1, hi, endpoint_id, kind, cap))]


def check_delivery(c, endpoint_id: str, st: dict, hb: dict, now: float) -> list[dict]:
    """The agent has nothing left to deliver (unreported == 0): every window and alert sequence number up to the
    ones it last assigned must have arrived. Verified ranges are forgotten (st[kind+'_ok'] is the watermark)."""
    out = []
    if not supported(hb) or hb.get("unreported") != 0:
        return out
    for kind, field in (("w", "window_seq"), ("a", "alert_seq")):
        hi = hb.get(field)
        if hi is None:
            continue
        hi = int(hi)
        if kind + "_ok" not in st:      # first check for this endpoint: from the first number this server received, if any
            m = _q(c, "SELECT min(seq) AS m FROM integrity_seqs WHERE endpoint_id=%s AND kind=%s", (endpoint_id, kind), one=True)
            st[kind + "_ok"] = int(m["m"]) - 1 if m and m.get("m") is not None else hi
        lo = int(st[kind + "_ok"])
        if hi < lo:            # the agent's counter went back (state reset): start over from it
            st[kind + "_ok"] = hi
            continue
        if hi == lo:
            continue
        lo = max(lo, hi - 1_000_000)     # bounded work for an endpoint seen for the first time after a huge gap
        miss = _missing(c, endpoint_id, kind, lo, hi)
        out += seq_findings(kind, lo, hi, miss, lost_seqs(hb, kind), now)
        st[kind + "_ok"] = hi
        _q(c, "DELETE FROM integrity_seqs WHERE endpoint_id=%s AND kind=%s AND seq <= %s", (endpoint_id, kind, hi))
    return out


def record_seqs(c, endpoint_id: str, kind: str, rows: list[dict]) -> None:
    """Window/alert upload: remember which sequence numbers arrived (agents 0.6+ send `seq`)."""
    seqs = sorted({int(r["seq"]) for r in rows if isinstance(r, dict) and isinstance(r.get("seq"), int)})
    if not seqs:
        return
    import psycopg2.extras
    with c.cursor() as cur:
        psycopg2.extras.execute_values(cur, "INSERT INTO integrity_seqs (endpoint_id, kind, seq) VALUES %s ON CONFLICT DO NOTHING",
                                       [(endpoint_id, kind, s) for s in seqs], page_size=5000)


def _prune(findings: list[dict], now: float) -> list[dict]:
    by_key = {}
    for f in findings:                 # one entry per key (the latest)
        if now - float(f.get("at") or 0) < FINDING_TTL_S:
            by_key.pop(f["key"], None)
            by_key[f["key"]] = f
    return list(by_key.values())[-20:]


def on_heartbeat(c, ep: dict, hb: dict) -> tuple[dict, bool]:
    """Heartbeat hook (inside the request's transaction). Returns (health JSON to store, accept). With accept=False
    (replay) only health['integrity'] may be written; the rest of the stored health stays as it was."""
    now = float(hb.get("at") or time.time())
    eid = str(ep["id"])
    row = _q(c, "SELECT state FROM endpoint_integrity WHERE endpoint_id=%s FOR UPDATE", (eid,), one=True)
    st = (row or {}).get("state") or {}
    b = None
    if ep.get("current_bundle"):
        b = _q(c, "SELECT sha256, extract(epoch FROM created_at) AS created FROM bundles WHERE id=%s", (ep["current_bundle"],), one=True)
    ctx = {"kind": ep.get("kind") or "live", "phase": ep.get("phase"), "current_bundle": str(ep["current_bundle"]) if ep.get("current_bundle") else None,
           "bundle_sha256": b["sha256"] if b else None, "bundle_created": float(b["created"]) if b and b.get("created") is not None else None,
           "signing_fp": server_signing_fp()}
    st, found, active, accept = evaluate(st, hb, ctx, now)
    if accept:
        found += check_delivery(c, eid, st, hb, now)
    st["findings"] = _prune(list(st.get("findings") or []) + found, now)
    _q(c, "INSERT INTO endpoint_integrity (endpoint_id, state, updated_at) VALUES (%s,%s,now()) "
            "ON CONFLICT (endpoint_id) DO UPDATE SET state=EXCLUDED.state, updated_at=now()", (eid, json.dumps(st)))
    integ = {"posture": st.get("posture"), "findings": st["findings"], "active": active, "checked_at": now}
    return {**hb, "integrity": integ}, accept


def on_ingest_rejects(c, endpoint_id: str, n: int, why: str) -> None:
    """Rows the server refused (impossible timestamps): a one-off finding, shown from the next heartbeat on."""
    if not n:
        return
    now = time.time()
    f = json.dumps([_finding(f"ingest_rejected:{int(now) // 3600}", "warning", f"{n:,} uploaded events were refused: {why}", now)])
    _q(c, "INSERT INTO endpoint_integrity (endpoint_id, state) VALUES (%s, jsonb_build_object('findings', %s::jsonb)) "
            "ON CONFLICT (endpoint_id) DO UPDATE SET state = jsonb_set(endpoint_integrity.state, '{findings}', "
            "coalesce(endpoint_integrity.state->'findings', '[]'::jsonb) || %s::jsonb, true), updated_at=now()", (endpoint_id, f, f))


def quota_for(ep: dict) -> tuple[int, int]:
    cfg = ep.get("config") or {}
    def pick(k, default):
        v = cfg.get(k)
        return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 else default
    return pick("ingest_daily_bytes", DAILY_BYTES), pick("ingest_daily_rows", DAILY_ROWS)


def used_today(c, endpoint_id: str) -> tuple[int, int]:
    r = _q(c, "SELECT coalesce(sum(bytes), 0) AS b, coalesce(sum(rows), 0) AS n FROM upload_batches WHERE endpoint_id=%s "
              "AND received_at > now() - interval '24 hours'", (endpoint_id,), one=True) or {}
    return int(r.get("b") or 0), int(r.get("n") or 0)


def check_quota(c, ep: dict, rows: int, nbytes: int) -> None:
    """Refuse (429) an upload that would take the endpoint over its daily budget; the first refusal of a day is an
    integrity finding (the console's health view) and a high-severity security event for the organisation."""
    max_b, max_n = quota_for(ep)
    used_b, used_n = used_today(c, str(ep["id"]))
    if used_b + nbytes <= max_b and used_n + rows <= max_n:
        return
    what = (f"{(used_b + nbytes) / 2**20:,.0f} MB" if used_b + nbytes > max_b else f"{used_n + rows:,} rows") + " in 24 hours"
    why = f"over its daily upload budget ({max_b >> 20:,} MB, {max_n:,} rows): {what}"
    now = time.time()
    key = f"ingest_quota:{int(now) // 86400}"
    st = _q(c, "SELECT state FROM endpoint_integrity WHERE endpoint_id=%s", (str(ep["id"]),), one=True)
    if not any(f.get("key") == key for f in ((st or {}).get("state") or {}).get("findings") or []):
        f = json.dumps([_finding(key, "error", f"Uploads refused: the endpoint is {why} (a runaway or hostile agent fills the server's storage)", now)])
        _q(c, "INSERT INTO endpoint_integrity (endpoint_id, state) VALUES (%s, jsonb_build_object('findings', %s::jsonb)) "
              "ON CONFLICT (endpoint_id) DO UPDATE SET state = jsonb_set(endpoint_integrity.state, '{findings}', "
              "coalesce(endpoint_integrity.state->'findings', '[]'::jsonb) || %s::jsonb, true), updated_at=now()", (str(ep["id"]), f, f))
        if ep.get("org_id"):
            from .posture import security_event
            security_event(c, ep["org_id"], "ingest_quota", f"Uploads from {ep.get('name') or ep['id']} refused: {why}", severity="high",
                           endpoint_id=str(ep["id"]), detail={"type": "ingest_quota", "endpoint_name": ep.get("name"), "bytes_24h": used_b + nbytes,
                                                              "rows_24h": used_n + rows, "max_bytes": max_b, "max_rows": max_n})
    raise IngestError(429, f"upload refused: this endpoint is {why}")


# ================================================================================================ health problems
def problems(row: dict, now: float | None = None) -> list[dict]:
    """[{key, level: error|warning|info, text}] from what the heartbeat hook stored plus what time alone tells
    (heartbeats stopped while the agent still calls the server). Nothing for agents that do not support it."""
    h = row.get("health") or {}
    if not isinstance(h, dict) or not supported(h):
        return []
    now = time.time() if now is None else now
    integ = h.get("integrity") or {}
    out = [dict(p) for p in integ.get("active") or []]
    for f in integ.get("findings") or []:
        if now - float(f.get("at") or 0) < FINDING_TTL_S:
            out.append({"key": f["key"], "level": f["level"], "text": f["text"]})
    at = float(h.get("at") or 0)
    ls = row.get("last_seen")
    ls = ls.timestamp() if hasattr(ls, "timestamp") else float(ls or 0)
    interval = float((h.get("counters") or {}).get("interval_s") or 60)
    stale = max(HB_STALE_S, 3 * min(interval, 3600))
    if at and now - at > stale and ls and now - ls < 180 and (row.get("kind") or "live") == "live":
        out.append({"key": f"heartbeat_stale:{int(at)}", "level": "error",
                    "text": f"The agent still contacts the server but has sent no valid heartbeat for {_fmt_dur(now - at)}: the "
                            "agent may have been stopped and its identity reused; the health shown is out of date"})
    return out


def posture(row: dict) -> str:
    """'checked' (agent 0.6+), 'unsupported' (older agent: no integrity checks), or 'unknown' (no heartbeat yet)."""
    h = row.get("health") or {}
    if not h:
        return "unknown"
    return "checked" if supported(h) else "unsupported"


# ================================================================================================ notifications
def notify_key(p: dict, h: dict, alerts_1h: int | None = None) -> tuple[str, str]:
    """(notify_log key suffix, severity) for a health problem. Drop problems are keyed per hour (the 1-hour delta,
    not a running total that resets with the collector) and escalate to high when large or while the endpoint raises
    alerts; disk-full / collector errors once per day while they last; integrity keys carry their episode already."""
    k, lvl = p["key"], p["level"]
    sev = "high" if lvl == "error" else "low" if lvl == "info" else "medium"
    hour = time.strftime("%Y-%m-%dT%H", time.gmtime())
    if k in ("collector_lost", "collector_behind", "spool_dropped"):
        tot = {"collector_lost": ("collector_lost_1h", "collector_lost"), "collector_behind": ("collector_behind_1h", "collector_behind"),
               "spool_dropped": ("spool_dropped_unuploaded_1h", "spool_dropped_unuploaded")}[k]
        if tot[0] not in h:    # agents before 0.3.19 / 0.3.22: only running totals - by order of magnitude, as before
            n = int(h.get(tot[1]) or 0) + (int(h.get("spool_dropped_unscored") or 0) if k == "spool_dropped" else 0)
            return f"{k}:{10 ** len(str(max(1, n))) // 10}", sev
        n = int(h.get("collector_lost_1h") or 0) + int(h.get("collector_behind_1h") or 0) + int(h.get("spool_dropped_unuploaded_1h") or 0) \
            + int(h.get("spool_dropped_unscored_1h") or 0)
        if n >= int(os.environ.get("PDP_NOTIFY_DROPS_HIGH", "100000")) or (alerts_1h or 0) > 0:
            sev = "high"
        return f"{k}:{hour}", sev
    if k in ("disk_full", "collector_error"):
        return f"{k}:{time.strftime('%Y-%m-%d', time.gmtime())}", sev
    return k, sev


def recent_alerts(c, endpoint_id) -> int:
    """Alerts the endpoint raised in the last hour (drops during an attack matter more)."""
    r = _q(c, "SELECT count(*) AS n FROM alerts WHERE endpoint_id=%s AND created_at > now() - interval '1 hour'", (str(endpoint_id),), one=True)
    return int(r["n"]) if r else 0


# ================================================================================================ ingest bounds
def bounded_decompress(body: bytes, max_bytes: int = MAX_BODY, max_ratio: int = MAX_RATIO) -> bytes:
    """gzip body -> bytes, refusing more than max_bytes or (beyond 64 MB) a compression ratio above max_ratio: a
    small upload must not expand into gigabytes (gzip bomb)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out, total, chunk = [], 0, 1 << 20
    data = body
    while data:
        part = d.decompress(data, chunk)
        total += len(part)
        if total > max_bytes or (total > 64 << 20 and total > max_ratio * max(len(body), 1)):
            raise IngestError(413, "upload too large once decompressed")
        out.append(part)
        data = d.unconsumed_tail
    rest = d.flush()
    total += len(rest)
    if total > max_bytes:
        raise IngestError(413, "upload too large once decompressed")
    out.append(rest)
    if not d.eof:
        raise IngestError(400, "truncated gzip body")
    return b"".join(out)


def ts_bounds(ep: dict, now: float | None = None) -> tuple[int, int]:
    """Accepted event time range: live endpoints from a day before enrolment to a day ahead of the server's clock;
    benchmark/simulation endpoints replay old datasets (2018/2019), so only 2000-01-01 .. now + 1 day."""
    now = time.time() if now is None else now
    hi = int((now + DAY_S) * 1e9)
    lo = TS_FLOOR_NS
    en = ep.get("enrolled_at")
    if (ep.get("kind") or "live") == "live" and en is not None:
        en = en.timestamp() if hasattr(en, "timestamp") else float(en)
        lo = max(lo, int((en - DAY_S) * 1e9))
    return lo, hi


def filter_events(rows: list[dict], lo: int, hi: int) -> tuple[list[dict], int]:
    """(rows inside [lo, hi], number refused). Rows without an integer timestamp are refused too."""
    keep = [r for r in rows if isinstance(r.get("ts_ns"), int) and lo <= r["ts_ns"] <= hi]
    return keep, len(rows) - len(keep)


def batch_days(rows: list[dict]) -> list[int]:
    """Distinct UTC days (partition numbers) the rows fall on; at most MAX_DAYS_PER_BATCH, else IngestError."""
    days = sorted({int(r["ts_ns"]) // DAY_NS_ for r in rows})
    if len(days) > MAX_DAYS_PER_BATCH:
        raise IngestError(400, f"an event batch may span at most {MAX_DAYS_PER_BATCH} days (this one: {len(days)})")
    return days
