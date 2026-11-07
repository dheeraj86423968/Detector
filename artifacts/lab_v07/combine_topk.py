"""Daily learned budget: each test day, the K highest-scoring nodes not alerted before (mode topk: any score above a
floor; mode cap: only above the calibrated threshold, at most K), united with the information-flow alerts.
Usage: combine_topk.py PFX DATASET..."""
import sys, json
import numpy as np
from pdp_engine.data import WindowStore
from common import D, load_gt, at
pfx = sys.argv[1]; dss = sys.argv[2:]
rows = {}
for ds in dss:
    eid, days, gtf = D[ds]
    reg = WindowStore(f"/data/endpoints/{eid}/eval-test").load_registry()
    s = np.load(f"/lab/{pfx}-{ds}.npz"); l2 = np.load(f"/lab/l2-{ds}.npz")
    ix, labels = s["ix"], s["labels"]
    gt = load_gt(gtf); uu = [reg.entities[int(i)].uuid for i in ix]
    na = [{k for k, v in gt.items() if u in v} for u in uu]
    flow = l2["prod06_nonovelty"][ix]
    cand = {"flow_only": flow}
    for key in [k for k in s.files if k.startswith("day:")]:
        M = s[key]
        for mode in ("topk", "cap"):
            for K in (5, 10, 20):
                al = np.zeros(len(ix), bool)
                for d in range(M.shape[0]):
                    sc = np.where(al, -np.inf, M[d])
                    ok = sc > (0.3 if mode == "topk" else 1 + 1e-6)
                    idx = np.where(ok)[0]
                    if len(idx) > K:
                        idx = idx[np.argsort(-sc[idx], kind="stable")[:K]]
                    al[idx] = True
                cand[f"{key[4:]}|{mode}{K}"] = al
                cand[f"flow+{key[4:]}|{mode}{K}"] = al | flow
    nd = len(days)
    for name, pred in cand.items():
        r = at(pred, labels, na); r["FP/day"] = round(r["FP"] / nd, 1); r["n_att"] = len(gt)
        rows.setdefault(name, {})[ds] = r
json.dump(rows, open(f"/lab/topk-{pfx}.json", "w"), indent=1)
print(f"{'variant':42s} " + "  ".join(f"{d[:9]:>22s}" for d in dss) + "   mean-recall FP/day attacks")
for name, r in rows.items():
    cells = "  ".join(f"{r[d]['TP']:4d}/{r[d]['FP']:5d} a{r[d]['attacks']}/{r[d]['n_att']} {r[d]['recall']:.2f}" for d in dss)
    print(f"{name:42s} {cells}   {np.mean([v['recall'] for v in r.values()]):.3f}  {np.mean([v['FP/day'] for v in r.values()]):5.1f}  {sum(v['attacks'] for v in r.values())}")
