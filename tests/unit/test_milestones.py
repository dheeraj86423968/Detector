"""Early-model scheduling: a model trained for a milestone is not queued again for it (regression: the 6 h
milestone was retrained every minute because the model's measured baseline_hours was 5.5)."""
import sys

from pdp_server.worker import due_milestones

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


check(due_milestones({}, 1.2) == [1], "no model, 1.2 h: the 1 h milestone")
check(due_milestones({"milestone_h": 1, "baseline_hours": 0.8}, 6.3) == [6], "1 h model, 6.3 h recorded: 6 h")
check(due_milestones({"milestone_h": 6, "baseline_hours": 5.5}, 7.0) == [], "6 h model measured 5.5 h: not queued again")
check(due_milestones({"milestone_h": 6, "baseline_hours": 5.5}, 24.5) == [24], "then the 1-day milestone")
check(due_milestones({"baseline_hours": 9.2}, 10) == [], "older manifests without milestone_h fall back to baseline_hours")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
