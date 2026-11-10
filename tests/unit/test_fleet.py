"""Fleet prevalence (pdp_server.fleet, 0.10): which endpoints form a fleet, the program keys an agent receives (other
endpoints' baselines only, at least fleet_min_endpoints of them), settings validation and what counts as weakening.
The database is replaced by a fake. Run: PYTHONPATH=server:engine python tests/unit/test_fleet.py"""
import json
import os
import sys
import tempfile

os.environ["PDP_SESSION_SECRET"] = os.path.join(tempfile.mkdtemp(), "session.secret")
os.environ["PDP_CONSOLE_URL"] = "https://pdp.example"
from fastapi import HTTPException  # noqa: E402

from pdp_server import fleet as F  # noqa: E402
from pdp_server import posture as P  # noqa: E402

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


root = tempfile.mkdtemp()


def bundle(bid, known):
    d = os.path.join(root, bid); os.makedirs(d, exist_ok=True)
    json.dump({"known_executables": known}, open(os.path.join(d, "layers.json"), "w"))
    return d


EPS = [  # id, org, kind, config, bundle id, baseline programs
    ("e1", "o1", "live", {}, "b1", ["C:\\Windows\\System32\\svchost.exe", "C:/Windows/System32/mstsc.exe", "/usr/bin/own1"]),
    ("e2", "o1", "live", {}, "b2", ["/Device/HarddiskVolume1/Windows/System32/SVCHOST.EXE", "C:/Tools/a.exe"]),
    ("e3", "o1", "live", {}, "b3", ["c:/windows/system32/svchost.exe", "C:/Tools/a.exe", "None"]),
    ("e4", "o1", "benchmark", {}, "b4", ["C:/Tools/a.exe", "C:/bench.exe"]),
    ("e5", "o2", "live", {}, "b5", ["C:/Tools/a.exe"]),
    ("e6", "o1", "benchmark", {"fleet": "lab"}, "b6", ["/bin/x"]),
    ("e7", "o1", "benchmark", {"fleet": "lab"}, "b7", ["/bin/x"]),
]
ROWS = [{"id": e, "org_id": o, "kind": k, "config": c, "bid": b, "path": bundle(b, known), "phase": "protected"} for e, o, k, c, b, known in EPS]


def fake_q(c, sql, params=(), one=False):
    return [dict(r) for r in ROWS if r["org_id"] == params[0] and r["phase"] != "retired"]


F.db.q = fake_q
ep = lambda eid, **cfg: dict(next(r for r in ROWS if r["id"] == eid), config=cfg or next(r for r in ROWS if r["id"] == eid)["config"])  # noqa: E731

p1 = F.programs_for(None, ep("e1"))
check(p1 == {"/windows/system32/svchost.exe": 2, "/tools/a.exe": 2},
      f"e1 gets programs run by >= 2 OTHER live endpoints of its organisation, by program key ({p1})")
check("/usr/bin/own1" not in p1 and "c:/bench.exe" not in p1, "its own baseline does not count; benchmark endpoints are not in the live fleet")
p1k1 = F.programs_for(None, ep("e1", fleet_min_endpoints=1))
check(p1k1.get("/tools/a.exe") == 2 and "/windows/system32/svchost.exe" in p1k1, f"fleet_min_endpoints 1 ({p1k1})")
p2 = F.programs_for(None, ep("e2", fleet_min_endpoints=1))
check(p2.get("/windows/system32/svchost.exe") == 2 and p2.get("/windows/system32/mstsc.exe") == 1 and p2.get("/tools/a.exe") == 1,
      f"counts exclude the endpoint itself ({p2})")
check(F.programs_for(None, ep("e1", fleet_prevalence="off")) == {}, "fleet_prevalence off: nothing sent")
check(F.programs_for(None, ep("e4", fleet_min_endpoints=1)) == {}, "a benchmark endpoint without a fleet label is alone")
check(F.programs_for(None, ep("e5", fleet_min_endpoints=1)) == {}, "another organisation's endpoints never count")
check(F.programs_for(None, ep("e6", fleet="lab", fleet_min_endpoints=1)) == {"/bin/x": 1}, "endpoints with the same fleet label form a fleet")
ROWS[1]["phase"] = "retired"
check("/tools/a.exe" not in F.programs_for(None, ep("e1")), "a retired endpoint's baseline stops counting (cache follows membership)")
ROWS[1]["phase"] = "protected"
check(F.settings({}) == ("drop", 2) and F.settings({"fleet_prevalence": "bogus", "fleet_min_endpoints": True}) == ("drop", 2),
      "defaults (lab_v10 P2): drop, 2 other endpoints; invalid stored values fall back to them")
check((P.FLEET_DEFAULT_MODE, P.FLEET_DEFAULT_MIN) == (F.DEFAULT_MODE, F.DEFAULT_MIN_ENDPOINTS), "posture and fleet agree on the defaults")


def refused(cfg):
    try:
        P.validate_config(cfg, engine_check=False)
    except HTTPException as e:
        return str(e.detail)
    return None


check(refused({"fleet_prevalence": "evidence", "fleet_min_endpoints": 3, "fleet": "servers-eu 1"}) is None, "valid fleet settings accepted")
check(refused({"fleet_prevalence": "always"}) and refused({"fleet_min_endpoints": 0}) and refused({"fleet": ""}) and refused({"fleet": "a" * 65})
      and refused({"fleet": "x;drop"}), "invalid fleet settings refused")
W = P.weakenings
check(W({"fleet_prevalence": "evidence"}, {}) and W({"fleet_prevalence": "off"}, {"fleet_prevalence": "evidence"})
      and not W({}, {"fleet_prevalence": "evidence"}) and not W({}, {"fleet_prevalence": "off"}),
      "evidence/off -> drop (the default) and off -> evidence are weakening; the stricter settings are not")
check(W({}, {"fleet_min_endpoints": 1}) and not W({}, {"fleet_min_endpoints": 5}), "fewer endpoints needed to call a program known is weakening")
check(W({}, {"fleet": "big"}) and not W({}, {"fleet": "big", "fleet_prevalence": "off"}), "joining a fleet is weakening unless prevalence is off")
# 0.10.1 console fleet controls: clearing the label (null), weakening by the fleet the endpoint is actually in, summary
check(refused({"fleet": None}) is None, "fleet null (back to the default fleet) accepted")
check(W({"fleet": "servers"}, {"fleet": None}, kind="live") and not W({"fleet": "lab"}, {"fleet": None}, kind="benchmark"),
      "clearing the label: a live endpoint joins its organisation's fleet (weakening); a benchmark endpoint is alone again (not)")
check(W({}, {"fleet": "lab"}, kind="benchmark") and W({}, {"fleet": "servers"}, kind="live")
      and not W({"fleet": "lab"}, {"fleet": "lab", "fleet_min_endpoints": 3}, kind="benchmark")
      and not W({}, {"fleet": "lab", "fleet_prevalence": "off"}, kind="benchmark"),
      "with the kind: joining another fleet is weakening, staying in the same one or prevalence off is not")
for r, n in zip(ROWS, ("ep-1", "ep-2", "ep-3", "bench-4", "other-org", "lab-6", "lab-7")):
    r["name"] = n; r["current_bundle"] = r["bid"]
ROWS[2]["current_bundle"] = None
S1 = F.summary(None, ep("e1"))
check(S1["label"] == "org" and S1["named"] is None and S1["default_label"] == "org" and [m["name"] for m in S1["members"]] == ["ep-2", "ep-3"]
      and S1["member_count"] == 2 and S1["trained_members"] == 1,
      f"summary of a live endpoint: the organisation fleet, its other live members and how many are trained ({S1})")
check(S1["mode"] == "drop" and S1["min_endpoints"] == 2 and S1["known_programs"] == 2, "summary: settings in force and programs known")
S4 = F.summary(None, ep("e4"))
check(S4["label"] is None and S4["members"] == [] and S4["known_programs"] == 0, "summary of an unlabelled benchmark endpoint: alone")
S6 = F.summary(None, ep("e6", fleet="lab", fleet_min_endpoints=1))
check(S6["named"] == "lab" and [m["name"] for m in S6["members"]] == ["lab-7"] and S6["known_programs"] == 1, f"summary of a labelled fleet ({S6})")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
