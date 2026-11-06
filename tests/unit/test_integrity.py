"""Integrity of the endpoint signal (0.6, pdp_server/integrity.py): heartbeat replay and state reset, collection
stopped (learned from the endpoint's own silences), collector canary, model identity and signing key, configuration
change, clock skew, scoring failures, missing window/alert sequence numbers, the health problems and notification keys
they produce, older agents never flagged, and the ingest bounds (gzip bomb, rows, timestamps, partitions).
No database: the SQL glue runs against a small fake. Run: PYTHONPATH=server:engine python tests/unit/test_integrity.py
"""
import gzip
import os
import sys
import time
from datetime import datetime, timezone

from pdp_server import integrity as I

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


T0 = 1_800_000_000.0
LIVE = {"kind": "live", "phase": "protected", "current_bundle": "b1", "bundle_sha256": "aa", "bundle_created": T0 - 7200, "signing_fp": "fp1"}


def hb(seq, run="r1", started=T0 - 10, at=None, events=10, **kw):
    h = {"agent_version": "0.6.0", "hb_seq": seq, "run_id": run, "started_at": started, "agent_time": at,
         "counters": {"events": events, "dropped": 0, "windows": 1, "alerts": 0, "interval_s": 60},
         "source": {"kind": "ebpf", "alive": True}, "bundle": {"id": "b1", "manifest_sha256": "aa", "signing_key_fp": "fp1", "pinned_key_fp": "fp1"},
         "config_sha256": "c1"}
    h.update(kw)
    return h


def keys(items):
    return sorted(x["key"].split(":")[0] for x in items)


# 1. older agents: nothing is checked and nothing is flagged for missing fields
st, found, active, ok = I.evaluate({}, {"agent_version": "0.5.0", "queue_depth": 0}, LIVE, T0)
check(ok and not found and not active and st["posture"] == "unsupported", "agent 0.5: accepted, posture 'unsupported', no findings")
row_old = {"kind": "live", "health": {"agent_version": "0.5.0", "at": T0 - 3600}, "last_seen": T0}
check(I.problems(row_old, T0) == [] and I.posture(row_old) == "unsupported", "agent 0.5: no integrity problems (also no stale-heartbeat check)")

# 2. heartbeat sequence: replay within a run, replay of an earlier run, a reset at a restart
st, found, active, ok = I.evaluate({}, hb(1), LIVE, T0)
check(ok and not found and not active and st["seq"] == 1 and st["posture"] == "checked", "first heartbeat accepted, nothing flagged")
st, found, _, ok = I.evaluate(st, hb(2), LIVE, T0 + 60)
check(ok and not found and st["seq"] == 2, "increasing sequence accepted")
st2, found, _, ok = I.evaluate(st, hb(2), LIVE, T0 + 120)
check(not ok and keys(found) == ["heartbeat_replay"] and found[0]["level"] == "error" and st2["hb_at"] == T0 + 60,
      "same sequence again in the same run: replay, rejected (the stored health goes stale), error")
st3, found, _, ok = I.evaluate(st, hb(1, run="r0", started=T0 - 9999), LIVE, T0 + 120)
check(not ok and keys(found) == ["heartbeat_replay"], "a heartbeat of an earlier run (started before this one): replay")
st4, found, _, ok = I.evaluate(st, hb(1, run="r2", started=T0 + 100), LIVE, T0 + 120)
check(ok and keys(found) == ["heartbeat_reset"] and found[0]["level"] == "warning" and st4["seq"] == 1,
      "a new run whose sequence went back: the agent's state was reset - accepted, warning")
st5, found, _, ok = I.evaluate(st, hb(3, run="r2", started=T0 + 100), LIVE, T0 + 120)
check(ok and not found, "a restart that keeps its sequence is normal")

# 3. collection stopped: learned from the endpoint's own silences, judged only after a day of history
st, t = {}, T0
for i in range(26 * 60):                     # 26 h, one heartbeat a minute; one 10-minute silence on the way
    quiet = 600 <= i < 610
    st, _, active, _ = I.evaluate(st, hb(i + 1, events=0 if quiet else 5), LIVE, t)
    t += 60
check(not active and max(st["quiet_hist"].values()) >= 600, f"normal host: no problem; longest silence learned ({max(st['quiet_hist'].values()):.0f}s)")
seq = 26 * 60 + 1
for i in range(29):
    st, _, active, _ = I.evaluate(st, hb(seq, events=0), LIVE, t); seq += 1; t += 60
check(not active, "29 silent minutes: below the threshold (max(30 min, 2 x 10 min))")
for i in range(3):
    st, _, active, _ = I.evaluate(st, hb(seq, events=0), LIVE, t); seq += 1; t += 60
check(keys(active) == ["collection_stopped"] and active[0]["level"] == "error", "32 silent minutes on a host never silent that long: collection stopped (error)")
k1 = active[0]["key"]
st, _, active, _ = I.evaluate(st, hb(seq, events=0), LIVE, t); seq += 1; t += 60
check(active[0]["key"] == k1, "the problem keeps one key while it lasts (one notification per episode)")
st, _, active, _ = I.evaluate(st, hb(seq, events=3), LIVE, t); seq += 1; t += 60
check(not active and "collection_stopped" not in st["episodes"], "events again: resolved")
st_new, t = {}, T0
for i in range(120):
    st_new, _, active, _ = I.evaluate(st_new, hb(i + 1, events=0 if i > 30 else 5), LIVE, t); t += 60
check(not active, "less than a day of history: not judged")
st, _, active, _ = I.evaluate(st, hb(seq, events=0, collector_error="no BTF"), LIVE, t + 7200)
check("collection_stopped" not in keys(active), "a collector error is already reported: no second problem")
st_b, _, active, _ = I.evaluate(dict(st, quiet_since=t - 7200), hb(seq + 1, events=0), dict(LIVE, kind="benchmark"), t)
check(not active, "benchmark endpoints are not judged")

# 4. canary, source kind, scoring failures, clock
_, _, active, _ = I.evaluate({}, hb(1, source={"kind": "ebpf", "alive": True, "canary": {"sent": 9, "seen": 6, "missed": 3}}), LIVE, T0)
check(keys(active) == ["collector_blind"] and active[0]["level"] == "error", "3 canaries in a row not seen: collector blind (error)")
_, _, active, _ = I.evaluate({}, hb(1, source={"kind": "ebpf", "canary": {"missed": 2}}), LIVE, T0)
check(not active, "2 missed: not yet")
_, _, active, _ = I.evaluate({}, hb(1, source={"kind": "db-replay"}), LIVE, T0)
check(keys(active) == ["source_kind"] and active[0]["level"] == "error", "a live endpoint fed by a replay source: error")
_, _, active, _ = I.evaluate({}, hb(1, source={"kind": "strace"}), LIVE, T0)
check(active[0]["level"] == "warning", "strace (one program): warning")
_, _, active, _ = I.evaluate({}, hb(1, source={"kind": "db-replay"}), dict(LIVE, kind="benchmark"), T0)
check(not active, "benchmark endpoints replay datasets: fine")
_, _, active, _ = I.evaluate({}, hb(1, score_failures_24h=2), LIVE, T0)
check(keys(active) == ["scoring_failed"] and active[0]["level"] == "error" and "2 windows" in active[0]["text"], "scoring failures: error with the count")
_, _, active, _ = I.evaluate({}, hb(1, at=T0 + 400), LIVE, T0)
check(keys(active) == ["clock_skew"] and active[0]["level"] == "warning" and "ahead" in active[0]["text"], "clock 400 s ahead: warning")
_, _, active, _ = I.evaluate({}, hb(1, at=T0 - 7200), LIVE, T0)
check(active[0]["level"] == "error" and "behind" in active[0]["text"], "clock 2 h behind: error")
_, _, active, _ = I.evaluate({}, hb(1, at=T0 + 30), LIVE, T0)
check(not active, "30 s: fine")

# 5. model identity and signing key
_, found, active, _ = I.evaluate({}, hb(1, bundle={"id": "b1", "manifest_sha256": "aa", "signing_key_fp": "evil", "pinned_key_fp": "fp1"}), LIVE, T0)
check(keys(active) == ["bundle_key", "bundle_key_pin"] and all(a["level"] == "error" for a in active), "a swapped signing key: both checks fire (error)")
st, _, active, _ = I.evaluate({}, hb(1, bundle={"id": "b0", "manifest_sha256": "zz", "signing_key_fp": "fp1"}), LIVE, T0)
check(not active, "another model: not at once (a re-fetch or reload takes a moment)")
_, _, active, _ = I.evaluate(st, hb(2, bundle={"id": "b0", "manifest_sha256": "zz", "signing_key_fp": "fp1"}), LIVE, T0 + 601)
check(keys(active) == ["bundle_mismatch"], "an old model for 10 min, 2 h after the new one was published: error")
_, _, active, _ = I.evaluate({}, hb(1, bundle={"id": "b0", "signing_key_fp": "fp1"}), dict(LIVE, bundle_created=T0 - 600), T0)
check(not active, "within the grace period after publishing: fine")
st, _, active, _ = I.evaluate({}, hb(1, bundle={"id": None, "signing_key_fp": "fp1"}), LIVE, T0)
_, _, active, _ = I.evaluate(st, hb(2, bundle={"id": None, "signing_key_fp": "fp1"}), LIVE, T0 + 700)
check(keys(active) == ["bundle_mismatch"] and "no detection model" in active[0]["text"], "no model loaded although one is published: error")
_, _, active, _ = I.evaluate({}, hb(1, bundle={"id": "b1", "manifest_sha256": "bb", "signing_key_fp": "fp1"}), LIVE, T0)
check(keys(active) == ["bundle_modified"], "the current model with another manifest digest: modified (error)")
_, found, _, _ = I.evaluate({}, hb(1, bundle={"id": "b0", "signing_key_fp": "fp1", "refused": {"id": "b1", "reason": "built for endpoint x"}}),
                           dict(LIVE, bundle_created=T0 - 60), T0)
check(keys(found) == ["bundle_refused"] and "endpoint x" in found[0]["text"], "a refused model is reported with the agent's reason")
_, _, active, _ = I.evaluate({}, hb(1, bundle={"id": None}), dict(LIVE, current_bundle=None, phase="baseline"), T0)
check(not active, "still learning without a model: fine")

# 6. configuration change (info) and the problem list the console / notifier see
st, _, _, _ = I.evaluate({}, hb(1), LIVE, T0)
st, found, _, _ = I.evaluate(st, hb(2, config_sha256="c2"), LIVE, T0 + 60)
check(keys(found) == ["config_changed"] and found[0]["level"] == "info", "local configuration changed: info finding")
health = {**hb(2), "at": T0 + 60, "integrity": {"findings": found, "active": [{"key": "clock_skew:1", "level": "warning", "text": "x"}]}}
row = {"kind": "live", "health": health, "last_seen": datetime.fromtimestamp(T0 + 60, timezone.utc)}
check(keys(I.problems(row, T0 + 90)) == ["clock_skew", "config_changed"], "problems: ongoing ones and recent findings")
check(keys(I.problems(row, T0 + 60 + I.FINDING_TTL_S + 1)) == ["clock_skew"], "findings expire after a day")
row_stale = dict(row, last_seen=datetime.fromtimestamp(T0 + 900, timezone.utc))
p = [x for x in I.problems(row_stale, T0 + 960) if x["key"].startswith("heartbeat_stale")]
check(len(p) == 1 and p[0]["level"] == "error", "agent calls the server but sends no heartbeat for 15 min: error")
check(not [x for x in I.problems(dict(row, last_seen=datetime.fromtimestamp(T0 + 60, timezone.utc)), T0 + 960) if x["key"].startswith("heartbeat_stale")],
      "nothing at all for 15 min: that is 'offline' (notified as such), not this")
from pdp_server.health import problems as health_problems
nw = time.time()
hp = health_problems({"kind": "live", "health": {**hb(9), "at": nw - 900}, "last_seen": datetime.fromtimestamp(nw - 10, timezone.utc)})
check(any(x["key"].startswith("heartbeat_stale") for x in hp), "health.problems includes the integrity problems")

# 7. sequence numbers of windows and alerts
f = I.seq_findings("a", 10, 20, [13, 14, 15], [], T0)
check(keys(f) == ["a_seq_gap"] and f[0]["level"] == "error" and "13..15" in f[0]["text"], "missing alerts: error with the range")
f = I.seq_findings("w", 10, 20, [13, 18], [[18, 19]], T0)
check(keys(f) == ["w_seq_gap", "w_seq_lost"] and [x["level"] for x in f] == ["error", "warning"], "numbers the agent declared lost: warning, not tampering")


class FakeDB:
    """Just the statements integrity.py runs, against dicts."""
    def __init__(self):
        self.state, self.seqs, self.bundles = {}, set(), {"b1": {"sha256": "aa", "created": T0 - 7200}}

    def q(self, c, sql, args=(), one=False):
        import json as j
        r = None
        if sql.startswith("SELECT state FROM endpoint_integrity"):
            r = [{"state": self.state[args[0]]}] if args[0] in self.state else []
        elif sql.startswith("SELECT sha256"):
            r = [self.bundles[args[0]]] if args[0] in self.bundles else []
        elif sql.startswith("INSERT INTO endpoint_integrity"):
            self.state[args[0]] = j.loads(args[1]); r = None
        elif "min(seq) AS m FROM integrity_seqs" in sql:
            v = [s for (e, k, s) in self.seqs if e == args[0] and k == args[1]]
            r = [{"m": min(v) if v else None}]
        elif "count(*) AS n FROM integrity_seqs" in sql:
            eid, kind, lo, hi = args
            r = [{"n": sum(1 for (e, k, s) in self.seqs if e == eid and k == kind and lo < s <= hi)}]
        elif "generate_series" in sql:
            lo, hi, eid, kind, cap = args
            r = [{"s": s} for s in range(lo, hi + 1) if (eid, kind, s) not in self.seqs][:cap]
        elif sql.startswith("DELETE FROM integrity_seqs"):
            eid, kind, hi = args
            self.seqs = {x for x in self.seqs if not (x[0] == eid and x[1] == kind and x[2] <= hi)}
        else:
            raise AssertionError(sql)
        if r is None:
            return None
        return (r[0] if r else None) if one else r


fake = FakeDB()
I._q = fake.q
I._FP["fp"] = "fp1"
ep = {"id": "e1", "kind": "live", "phase": "protected", "current_bundle": "b1"}
health, ok = I.on_heartbeat(None, ep, {**hb(1, window_seq=0, alert_seq=0, unreported=0), "at": T0})
check(ok and health["integrity"]["posture"] == "checked" and health["integrity"]["findings"] == [] and fake.state["e1"]["seq"] == 1,
      "on_heartbeat: state stored, nothing flagged")
check(fake.state["e1"]["a_ok"] == 0 and fake.state["e1"]["w_ok"] == 0, "first check: watermark from the agent's current numbers")
fake.seqs |= {("e1", "a", s) for s in (1, 2, 4)} | {("e1", "w", s) for s in (1, 2, 3)}
health, ok = I.on_heartbeat(None, ep, {**hb(2, window_seq=3, alert_seq=4, unreported=1), "at": T0 + 60})
check(ok and health["integrity"]["findings"] == [], "batches still queued on the agent: delivery not judged yet")
health, ok = I.on_heartbeat(None, ep, {**hb(3, window_seq=3, alert_seq=4, unreported=0), "at": T0 + 120})
fs = health["integrity"]["findings"]
check(keys(fs) == ["a_seq_gap"] and "sequence 3" in fs[0]["text"] and fake.state["e1"]["a_ok"] == 4 and fake.state["e1"]["w_ok"] == 3,
      f"queue empty: alert 3 never arrived -> error; verified ranges forgotten ({[x['text'][:40] for x in fs]})")
check(not any(e == "e1" for e, _, _ in fake.seqs), "verified sequence numbers are deleted")
health, ok = I.on_heartbeat(None, ep, {**hb(3, window_seq=3, alert_seq=4, unreported=0), "at": T0 + 180})
check(not ok and keys(health["integrity"]["findings"]) == ["a_seq_gap", "heartbeat_replay"], "replay stored as a finding next to the earlier one")
ep2 = dict(ep, id="e2")         # server upgraded after its agents: numbers from before were never recorded - no false gap
health, ok = I.on_heartbeat(None, ep2, {**hb(1, window_seq=900, alert_seq=70, unreported=0), "at": T0})
check(ok and health["integrity"]["findings"] == [] and fake.state["e2"]["a_ok"] == 70, "first sight of an agent with earlier numbers: no false gap")
fake.seqs |= {("e2", "a", 72)}
health, ok = I.on_heartbeat(None, ep2, {**hb(2, window_seq=900, alert_seq=72, unreported=0), "at": T0 + 60})
check(keys(health["integrity"]["findings"]) == ["a_seq_gap"], "... and a gap after it is found")
health, ok = I.on_heartbeat(None, ep, {"agent_version": "0.5.3", "at": T0 + 240})
check(ok and health["integrity"]["posture"] == "unsupported", "an older agent's heartbeat passes through (posture unsupported)")

# 8. notification keys and severity
os.environ.pop("PDP_NOTIFY_DROPS_HIGH", None)
h = {"collector_lost_1h": 50, "collector_lost": 9_999_999}
k, sev = I.notify_key({"key": "collector_lost", "level": "warning"}, h, 0)
check(k.startswith("collector_lost:") and len(k.split(":")[1]) == 13 and sev == "medium", f"drops: keyed per hour, medium ({k})")
check(I.notify_key({"key": "collector_lost", "level": "warning"}, h, 3)[1] == "high", "drops while the endpoint raises alerts: high")
check(I.notify_key({"key": "spool_dropped", "level": "warning"}, {"spool_dropped_unuploaded_1h": 200_000}, 0)[1] == "high", "large drops: high")
check(I.notify_key({"key": "disk_full", "level": "error"}, {}, 0)[0].count(":") == 1, "disk full: once a day while it lasts")
check(I.notify_key({"key": "collector_lost", "level": "warning"}, {"collector_lost": 4567}, 0)[0] == "collector_lost:1000",
      "agents with running totals only: keyed by order of magnitude as before (no hourly repeat for ever)")
check(I.notify_key({"key": "collection_stopped:123", "level": "error"}, {}, 0) == ("collection_stopped:123", "high"), "integrity: per episode, error -> high")
check(I.notify_key({"key": "config_changed:1", "level": "info"}, {}, 0)[1] == "low", "info -> low")

# 9. ingest bounds
raw = b"\n".join(b'{"ts_ns": 1}' for _ in range(1000))
check(I.bounded_decompress(gzip.compress(raw)) == raw, "bounded decompression: normal upload unchanged")
bomb = gzip.compress(b"\0" * (80 << 20))
try:
    I.bounded_decompress(bomb); check(False, "gzip bomb refused")
except I.IngestError as e:
    check(e.status == 413, f"gzip bomb (80 MB from {len(bomb) // 1024} KB) refused: {e}")
try:
    I.bounded_decompress(gzip.compress(b"x" * 5000), max_bytes=4096); check(False, "size cap")
except I.IngestError:
    check(True, "decompressed size capped")
try:
    I.bounded_decompress(gzip.compress(raw)[:-12]); check(False, "truncated body refused")
except I.IngestError as e:
    check(e.status == 400, "truncated gzip refused")
now = T0
lo, hi = I.ts_bounds({"kind": "live", "enrolled_at": datetime.fromtimestamp(T0 - 10 * 86400, timezone.utc)}, now)
rows = [{"ts_ns": 0}, {"ts_ns": 2**62}, {"ts_ns": int((T0 - 3600) * 1e9)}, {"ts_ns": "x"}, {"ts_ns": int((T0 - 10.5 * 86400) * 1e9)}]
keep, refused = I.filter_events(rows, lo, hi)
check(len(keep) == 2 and refused == 3, "live: events before enrolment - 1 day or after now + 1 day are refused")
lo_b, _ = I.ts_bounds({"kind": "benchmark", "enrolled_at": datetime.fromtimestamp(T0, timezone.utc)}, now)
check(I.filter_events([{"ts_ns": 1_523_000_000 * 10**9}], lo_b, hi)[1] == 0, "benchmark: a 2018 dataset replay is accepted")
check(I.batch_days(keep) == sorted({r["ts_ns"] // (86400 * 10**9) for r in keep}), "partitions: only the days present")
try:
    I.batch_days([{"ts_ns": d * 86400 * 10**9} for d in range(20000, 20020)]); check(False, "too many days")
except I.IngestError as e:
    check(e.status == 400, "a batch spanning 20 days is refused (bounded partition creation)")
from pdp_server import db as D
import inspect
check(I.DAY_NS_ == D.DAY_NS, "same day length as the partitions")
check("days" in inspect.signature(D.ensure_partitions).parameters, "ensure_partitions takes the days present")

# 10. the server keeps the new heartbeat fields
from pdp_server.api import Heartbeat
m = Heartbeat(**hb(5, at=T0, window_seq=1, alert_seq=2, unreported=0, lost_seqs={"a": [[1, 2]]}, score_failures=1, score_failures_24h=1))
d = m.model_dump() if hasattr(m, "model_dump") else m.dict()
check(d["hb_seq"] == 5 and d["counters"]["events"] == 10 and d["bundle"]["id"] == "b1" and d["lost_seqs"] == {"a": [[1, 2]]}, "Heartbeat model keeps the 0.6 fields")
check(Heartbeat(agent_version="0.4.0").hb_seq is None, "an old agent's heartbeat validates without them")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
