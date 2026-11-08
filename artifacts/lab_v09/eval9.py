"""Lab 0.8.1: score a set once with its 0.7 released bundle (runtime, streaming) and apply the alert-policy variants
R (0.7: near-alert on the propagated score), A (near-alert on the node's own score), B (A + at most 3 corroborated
repeat runs per new program per day) to the same windows - the policy does not change the scores or the layers'
state, only which nodes alert. Usage: eval9.py SET BUNDLE_SUBDIR --out file.json"""
import argparse, copy, json, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from common8 import Set, log, at

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("bundle"); ap.add_argument("--out", required=True)
a = ap.parse_args()
S = Set(a.set)
bdir = a.bundle if a.bundle.startswith("/") else f"{S.work}/{a.bundle}"
st = S.eval_store(); reg = st.load_registry()
t0 = time.time()
rt = Runtime(bdir, reg, device="cuda", feat_device="cuda")
VARIANTS = {"R": ("final", 0), "A": ("own", 0), "B": ("own", 3)}
pols = {}
for k, (score, rep) in VARIANTS.items():
    p = copy.copy(rt.policy); p.reset()
    p.near_alert_score, p.repeat_corroborations = score, rep
    pols[k] = p
alerted = {k: {} for k in VARIANTS}
cur = {}


def apply_all(w, ids, fused, hits=None):
    if hits is None:
        hits = rt.layers.process(w, rt.reg, ids)
    own = getattr(rt, "_own", None)
    out = None
    for k, p in pols.items():
        al, rs, hs = p.apply(w, rt.reg, ids, fused, hits, own=own)
        cur[k] = (al, rs)
        if k == "R":
            out = (al, rs, hs)
    return out


rt._alert_policy = apply_all
order = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}
seen = np.zeros(0, bool)
for d in S.test_days:
    for w in st.windows(d):
        rt.score(w)
        for k, (al, rs) in cur.items():
            for n in al.tolist():
                if n not in alerted[k]:
                    alerted[k][n] = min((x["layer"] for x in rs[n]), key=lambda x: order.get(x, 9))
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, v in S.gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
res = {"set": a.set, "bundle": a.bundle, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days)}
for k in VARIANTS:
    pred = np.zeros(len(ix), bool); lay = {}
    for n, l in alerted[k].items():
        if n in pos:
            pred[pos[n]] = True; lay[pos[n]] = l
    r0 = at(pred, labels, na); r0["FP/day"] = round(r0["FP"] / max(1, len(S.test_days)), 1)
    r0["by_layer"] = dict(Counter(lay.values()))
    r0["by_layer_tp"] = dict(Counter(l for j, l in lay.items() if labels[j]))
    r0["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]})
    res[k] = r0
    log(f"{k}: {r0}")
print(json.dumps(res))
json.dump(res, open(a.out, "w"), indent=1)
