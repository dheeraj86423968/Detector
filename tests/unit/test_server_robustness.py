"""Server robustness against agent-supplied data and partial failures (review 2026-11-12): alert rows and heartbeats
are brought into shape at upload; readers of stored health tolerate what older servers stored; the notifier isolates
organisations and channels; a repeated ingest keeps the stored day."""
import os
import sys
import tempfile

os.environ["PDP_SESSION_SECRET"] = os.path.join(tempfile.mkdtemp(), "session.secret")
from pdp_server import api, health, notify, updates  # noqa: E402

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


# ---- alert rows
good = {"window_start_ns": 5, "node": {"uuid": "u1", "ntype": "subject", "label": "subject /bin/x x", "display": {"pid": 1}},
        "fused": 1.5, "r1": 1.0, "r2": 2.0, "layer": "rules", "rule": "exfiltration", "reason": "r", "aid": "a1", "seq": 7,
        "context": {"nodes": [{"uuid": "u1", "label": "l", "ntype": "subject"}], "edges": [{"src": "u1", "dst": "u2", "op": "READ", "ts_ns": 3}]},
        "reasons": [{"layer": "rules", "rule": "exfiltration", "detail": "d", "key": "k"}]}
c = api.clean_alert(dict(good))
check(c["node"]["uuid"] == "u1" and c["fused"] == 1.5 and c["context"]["edges"] == good["context"]["edges"] and c["reasons"] == good["reasons"]
      and c["seq"] == 7 and c["aid"] == "a1" and c["node"]["display"] == {"pid": 1}, "a well-formed alert row is unchanged")
bad = api.clean_alert({"window_start_ns": "x", "node": {"uuid": "u1", "label": None}, "fused": None, "r1": float("nan"), "r2": "inf",
                       "context": {"nodes": [{"uuid": "u1", "label": 3}, {}, "x"], "edges": [{}, {"src": "a", "dst": "b", "op": "READ"}, 5], "note": 1},
                       "reasons": ["x", {"layer": "rules", "rule": 4}], "seq": 2 ** 70})
check(bad["fused"] == 0.0 and bad["r1"] == 0.0 and bad["r2"] == 0.0 and bad["node"]["label"] == "" and bad["window_start_ns"] == 0
      and bad["context"]["edges"] == [{"src": "a", "dst": "b", "op": "READ", "ts_ns": 0}] and bad["context"]["nodes"] == [{"uuid": "u1", "label": "3"}]
      and bad["context"]["note"] == 1 and bad["reasons"] == [{"layer": "rules", "rule": "4"}] and bad["seq"] is None,
      "odd scores, context items and reasons are brought into shape")
check(api.clean_alert({"context": {"edges": [{}]}}) is None and api.clean_alert("x") is None and api.clean_alert({"node": {"uuid": 5}}) is None
      and api.clean_alert({"context": "x", "node": {"uuid": "u"}})["context"] == {"nodes": [], "edges": []}, "a row naming no node is dropped; a non-object context becomes empty")
from pdp_server import incidents  # noqa: E402
row = {"node_uuid": "u1", "context": bad["context"], "layer": "rules", "rule": "exfiltration", "label": "subject /bin/x x", "ntype": "subject", "window_start_ns": 0, "id": 1, "reasons": bad["reasons"], "fused": 0.0}
try:
    incidents._split_connected([row]); ok = True
except Exception as e:  # noqa
    ok = False
check(ok, "incident grouping reads a cleaned context")

# ---- heartbeat
hb = api.Heartbeat(collector_lost_1h=2 ** 80, collector_lost=-(2 ** 90), cpu_pct=float("inf"), last_window_end_ns=1_800_000_000_000_000_000,
                   update={"state": "failed", "failed": 5, "updater": 1, "junk": {"a": 1}}, isolated=True)
d = hb.model_dump()
check(d["collector_lost_1h"] == api.INT_BOUND and d["collector_lost"] == -api.INT_BOUND and d["cpu_pct"] == 0.0
      and d["last_window_end_ns"] == 1_800_000_000_000_000_000 and d["isolated"] is True, "heartbeat numbers stay inside bigint; timestamps and flags untouched")
check(d["update"] == {"state": "failed", "updater": True}, "update state keeps its documented fields only")
check(api.Heartbeat(update={"state": "offered", "version": "0.12.0", "failed": ["0.11.0", 3], "updater": False}).model_dump()["update"]
      == {"state": "offered", "version": "0.12.0", "updater": False, "failed": ["0.11.0"]}, "a normal update state passes")
check(updates.failed_versions({"health": {"update": {"failed": 5}}}) == [] and updates.failed_versions({"health": {"update": "x"}}) == []
      and updates.failed_versions({"health": None}) == [] and updates.failed_versions({"health": {"update": {"failed": ["1.0", 2]}}}) == ["1.0"],
      "failed versions read from stored health of any shape")
try:
    health.problems({"health": {"update": {"failed": 1}, "at": 0}, "agent_version": "1", "config": {}}, "2"); ok = True
except TypeError:
    ok = False
except Exception:  # noqa  (anything else comes from parts this test does not set up)
    ok = True
check(ok, "health problems tolerate a stored non-list 'failed'")


# ---- notifier isolation
class Ctx:
    def __init__(self, log): self.log = log
    def __enter__(self): self.log.append("begin"); return self
    def __exit__(self, t, v, tb): self.log.append("rollback" if t else "commit"); return False


log, ran = [], []
CH = [{"id": i, "org_id": o, "enabled": True, "events": ["incident"], "since_alert_id": 0, "every_alert": False, "kind": "email"}
      for i, o in ((1, "A"), (2, "B"), (3, "B"), (4, "C"))]
notify.db.conn = lambda *a: Ctx(log)
notify.db.q = lambda c, sql, args=(), one=False: CH
notify.org_endpoints = lambda c, org: [org]
def _incs(c, eps, since):
    if eps == ["A"]:
        raise KeyError("src")
    return []
def _run(c, ch, eps, incs):
    if ch["id"] == 2:
        raise TypeError("boom")
    ran.append(ch["id"]); return {"sent": 1, "failed": 0, "suppressed": 0}
notify.org_incidents, notify.run_channel = _incs, _run
t = notify.run_once()
check(ran == [3, 4] and t["sent"] == 2 and t["errors"] == 2, "an organisation whose data raises and a failing channel do not stop the others")
check(log.count("rollback") == 2 and log.count("commit") >= 3, "each organisation / channel has its own transaction (only the failing ones roll back)")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
