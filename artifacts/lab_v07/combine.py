"""Union of the information-flow product alerts (with / without layer 1) and the learned alert sets (score > 1 at the
validation-budget threshold). Usage: combine.py DATASET..."""
import sys, json
import numpy as np
from pdp_engine.data import WindowStore
from common import D, load_gt, at
import os
PFX = sys.argv[1]; sys.argv = sys.argv[1:]
rows = {}
for ds in sys.argv[1:]:
    eid, days, gtf = D[ds]
    reg = WindowStore(f"/data/endpoints/{eid}/eval-test").load_registry()
    s = np.load(f"/lab/{PFX}-{ds}.npz"); l2 = np.load(f"/lab/l2-{ds}.npz")
    ix, labels = s["ix"], s["labels"]
    gt = load_gt(gtf); uu = [reg.entities[int(i)].uuid for i in ix]
    na = [{k for k, v in gt.items() if u in v} for u in uu]
    nd = len(days)
    cand = {"prod06": l2["prod06"][ix], "flow_only": l2["prod06_nonovelty"][ix]}
    for k in s.files:
        if k in ("ix", "labels"):
            continue
        cand[f"learned[{k}]"] = s[k] > 1 + 1e-6
        cand[f"flow_only+learned[{k}]"] = l2["prod06_nonovelty"][ix] | (s[k] > 1 + 1e-6)
    print(f"== {ds}  gt nodes {int(labels.sum())}, attacks {len(gt)}, days {nd}")
    for name, pred in cand.items():
        r = at(pred, labels, na); r["FP/day"] = round(r["FP"] / nd, 1)
        rows.setdefault(name, {})[ds] = r
        print(f"  {name:45s} TP {r['TP']:5d} FP {r['FP']:6d} ({r['FP/day']:7.1f}/day) recall {r['recall']:.3f} attacks {r['attacks']}/{len(gt)}")
json.dump(rows, open("/lab/combine.json", "w"), indent=1)
print("== means over datasets (recall, FP/day)")
for name, r in rows.items():
    print(f"  {name:45s} recall {np.mean([v['recall'] for v in r.values()]):.3f}  FP/day {np.mean([v['FP/day'] for v in r.values()]):.1f}  attacks {sum(v['attacks'] for v in r.values())}")
