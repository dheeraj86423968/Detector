"""Lab 0.9 (false positives of 0.8.1): score a set once with its 0.7 released bundle and apply a grid of alert-policy
variants to the same windows; dump every alert of the reference variant A (0.8.1) with its details for analysis.
Usage: eval10.py SET BUNDLE_SUBDIR --out file.json --dump dump.json"""
import argparse, copy, json, re, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from common8 import Set, log, at

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("bundle"); ap.add_argument("--out", required=True)
ap.add_argument("--dump", required=True)
a = ap.parse_args()
S = Set(a.set)
bdir = a.bundle if a.bundle.startswith("/") else f"{S.work}/{a.bundle}"
st = S.eval_store(); reg = st.load_registry()
t0 = time.time()
rt = Runtime(bdir, reg, device="cuda", feat_device="cuda")
VARIANTS = {   # policy attribute overrides on top of the 0.8.1 runtime defaults
    "A": {},
    "F3": {"learned_floor": 3.0},
    "F3R1": {"learned_floor": 3.0, "repeat_corroborations": 1},
    "F3R3": {"learned_floor": 3.0, "repeat_corroborations": 3},
    "F4": {"learned_floor": 4.0},
    "F5": {"learned_floor": 5.0},
    "F3B10": {"learned_floor": 3.0, "daily_budget": 10},
    "L0R1": {"daily_budget": 0, "repeat_corroborations": 1},
}
pols = {}
for k, ov in VARIANTS.items():
    p = copy.copy(rt.policy); p.reset()
    for kk, vv in ov.items():
        setattr(p, kk, vv)
    pols[k] = p
alerted = {k: {} for k in VARIANTS}
cur = {}; extra = {}


def apply_all(w, ids, fused, hits=None):
    if hits is None:
        hits = rt.layers.process(w, rt.reg, ids)
    own = getattr(rt, "_own", None)
    extra.update(ids=ids, fused=fused, own=own)
    out = None
    for k, p in pols.items():
        al, rs, hs = p.apply(w, rt.reg, ids, fused, hits, own=own)
        cur[k] = (al, rs)
        if k == "A":
            out = (al, rs, hs)
    return out


rt._alert_policy = apply_all
order = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}
seen = np.zeros(0, bool)
dump = []
for d in S.test_days:
    for w in st.windows(d):
        rt.score(w)
        pos = {int(x): i for i, x in enumerate(extra["ids"].tolist())}
        for k, (al, rs) in cur.items():
            for n in al.tolist():
                if n not in alerted[k]:
                    alerted[k][n] = min((x["layer"] for x in rs[n]), key=lambda x: order.get(x, 9))
                    if k == "A":
                        i = pos.get(n); e = reg.entities[n]
                        dump.append({"node": n, "gt": e.uuid in S.allgt, "ntype": e.ntype, "label": e.label[:200],
                                     "layer": alerted[k][n], "rules": [x["rule"] for x in rs[n]],
                                     "key": rs[n][0].get("key"), "fused": None if i is None else round(float(extra["fused"][i]), 3),
                                     "own": None if (i is None or extra["own"] is None) else round(float(extra["own"][i]), 3),
                                     "day": d, "t": int(w.start_ns)})
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, v in S.gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
res = {"set": a.set, "bundle": a.bundle, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days),
       "variants": VARIANTS}
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
    log(f"{k}: attacks {r0['attacks']} TP {r0['TP']} FP {r0['FP']}")
json.dump(res, open(a.out, "w"), indent=1)
json.dump(dump, open(a.dump, "w"))
