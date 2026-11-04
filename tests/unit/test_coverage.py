"""Detection coverage per release: which changes count as regressions, and which earlier measurement a release is
compared with (same suite, same reference endpoint). No database, no campaign.
Run: PYTHONPATH=server:engine:agent:sim python tests/unit/test_coverage.py"""
import sys
from datetime import datetime, timedelta

from pdp_server.tools.coverage import previous, regressions

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


def row(rel, rate, fp=2.0, fams=None, ci=None, ep="e1", spec="s1", day=0):
    return {"release": rel, "detection_rate": rate, "ci": ci or [rate - 0.03, rate + 0.03], "fp_per_day": fp, "endpoint_id": ep, "spec_hash": spec,
            "created_at": datetime(2026, 11, 1) + timedelta(days=day),
            "by_family": [{"family": f, "fused": {"rate": r}} for f, r in (fams or {}).items()]}


base = row("0.6.0", 0.90, fams={"web_backdoor": 0.95, "ransomware": 0.90})
check(regressions(base, row("0.6.1", 0.88, fams={"web_backdoor": 0.93, "ransomware": 0.88})) == [], "small changes within noise: no regression")
check(regressions(base, row("0.6.1", 0.80)) == ["overall detection 90% -> 80%"], "overall drop of 10 points")
check(regressions(base, row("0.6.1", 0.86, ci=[0.70, 0.96])) == [], "a drop inside a wide confidence interval is not flagged")
r = regressions(base, row("0.6.1", 0.89, fams={"web_backdoor": 0.95, "ransomware": 0.60}))
check(r == ["ransomware: 90% -> 60%"], f"one family down 30 points ({r})")
check(regressions(base, row("0.6.1", 0.90, fp=4.0)) == ["false positives per day 2.0 -> 4.0"], "false positives doubled")
check(regressions(row("a", 0.9, fp=0.2), row("b", 0.9, fp=0.9)) == [], "tiny absolute false-positive changes are not flagged")
check(regressions(base, row("0.7.0", 0.97, fp=1.0, fams={"web_backdoor": 1.0, "ransomware": 0.95})) == [], "improvements are not regressions")

hist = [row("0.5.0", 0.8, day=0), row("0.5.9", 0.8, spec="s2", day=1), row("0.6.0", 0.9, ep="e2", day=2), row("0.6.1", 0.85, day=3)]
check(previous(hist, hist[3])["release"] == "0.5.0", "compared with the last release on the same suite and endpoint")
check(previous(hist, hist[0]) is None, "first measurement: nothing to compare")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
