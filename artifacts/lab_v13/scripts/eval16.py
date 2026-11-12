"""Lab 0.13 (artifacts/lab_v13/PROTOCOL.md): score a set once with its released bundle; derive Z0 (released layer 1,
as lab_v12 eval15 Z0), R0 (layer 1 re-fitted on fit_days, old parser) and K (the same with backslash_paths) from the
same windows, learned scores and layer-2 hits. Fleet prevalence P2 "drop" in all; R0 / K use the other members'
re-fitted known programs (out/known16-*.json from prep16.py). Usage: eval16.py SET --out res.json"""
import argparse, copy, json, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from pdp_engine.layers import UNKNOWN_PROGRAM, NoveltyLayer, program_name
from common8 import Set, log, at

FLEETS = {"CARBANAKV2": [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)], "OPTC": ["OPTC_H201", "OPTC_H501", "OPTC_H051"],
          "ATLASV2": ["ATLASV2_EDR-h1", "ATLASV2_EDR-h2"],
          "E3": ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "FIVEDIRECTIONS_E3", "TRACE_E3-trace"],
          "THEIA_E5": ["THEIA_E5-theia"]}
BUNDLE = {s: "b07rel" for s in FLEETS["CARBANAKV2"] + ["THEIA_E5-theia"]}
FLEET_K = 2
VARIANTS = ("Z0", "R0", "K")
SRC = {"Z0": "released", "R0": "old", "K": "bs"}

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("--out", required=True)
a = ap.parse_args()
S = Set(a.set)
bdir = f"{S.work}/{BUNDLE.get(a.set, 'v07rel')}"
st = S.eval_store(); reg = st.load_registry()
t0 = time.time()
rt = Runtime(bdir, reg, device="cuda", feat_device="cuda")
rel = rt.layers.novelty
cfg = rt.layers.spec.get("config", {})
fleet = next(m for m in FLEETS.values() if a.set in m)
known = {o: json.load(open(f"out/known16-{o}.json")) for o in fleet}

nov, cnt_key, cnt_name = {}, {}, {}
for v in VARIANTS:
    if v == "Z0":
        nov[v] = rel
    else:
        nov[v] = NoveltyLayer(set(known[a.set][SRC[v]]), None, normalize=cfg.get("normalize_programs", False),
                              instances=cfg.get("novel_instances", 0), full_paths=cfg.get("full_paths", False),
                              strict_keys=cfg.get("strict_program_key", False))
        nov[v].backslash_paths = v == "K"
    ck, cn = Counter(), Counter()
    for o in fleet:
        if o != a.set:
            keys = {nov[v].key(k) for k in known[o][SRC[v]] if k not in UNKNOWN_PROGRAM}
            ck.update(keys); cn.update({program_name(k) for k in keys})
    cnt_key[v], cnt_name[v] = ck, cn
log(f"fleet {fleet}; known programs " + ", ".join(f"{v}={len(nov[v].known)}" for v in VARIANTS))


def fleet_n(v, exe):
    k = nov[v].key(exe)
    n = cnt_key[v].get(k, 0)
    if n == 0 and "/" not in k:
        n = cnt_name[v].get(program_name(k), 0)
    return n


pols = {}
for v in VARIANTS:
    p = copy.copy(rt.policy); p.reset(); p.evidence_rules = set(p.evidence_rules)
    pols[v] = p
cur = {}
dropped = {v: Counter() for v in VARIANTS}


def apply_all(w, ids, fused, hits=None):
    if hits is None:
        hits = rt.layers.process(w, rt.reg, ids)          # Z0's layer 1 + the shared layer 2
    own = getattr(rt, "_own", None)
    other = [h for h in hits if h.layer != "novelty"]
    out = None
    for v in VARIANTS:
        nh = [h for h in hits if h.layer == "novelty"] if v == "Z0" else nov[v].process(w, rt.reg, ids)
        keep = []
        for h in nh:
            if fleet_n(v, h.key) >= FLEET_K:
                dropped[v][h.key] += 1
                continue
            keep.append(h)
        al, rs, hs = pols[v].apply(w, rt.reg, ids, fused, keep + other, own=own)
        cur[v] = (al, rs)
        if out is None:
            out = (al, rs, hs)
    return out


rt._alert_policy = apply_all
ORDER = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}
alerted = {v: {} for v in VARIANTS}
keys = {v: {} for v in VARIANTS}
seen = np.zeros(0, bool)
for d in S.test_days:
    for w in st.windows(d):
        rt.score(w)
        for v, (al, rs) in cur.items():
            for n in al.tolist():
                if n not in alerted[v]:
                    layer = min((x["layer"] for x in rs[n]), key=lambda x: ORDER.get(x, 9))
                    main = next(x for x in rs[n] if x["layer"] == layer)
                    alerted[v][n] = layer
                    keys[v][n] = (main.get("rule"), main.get("key"))
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, x in S.gt.items() if u in x} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
res = {"set": a.set, "bundle": bdir, "fleet": fleet, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days),
       "known": {v: len(nov[v].known) for v in VARIANTS}}
for v in VARIANTS:
    pred = np.zeros(len(ix), bool); lay = {}
    for n, l in alerted[v].items():
        if n in pos:
            pred[pos[n]] = True; lay[pos[n]] = l
    r0 = at(pred, labels, na)
    r0["by_layer"] = dict(Counter(lay.values()))
    r0["by_layer_tp"] = dict(Counter(l for j, l in lay.items() if labels[j]))
    r0["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]})
    r0["attacks_det"] = sorted({x for j, l in lay.items() if labels[j] and l in ("novelty", "rules") for x in na[j]})
    fpk, tpk = Counter(), Counter()
    for n, (rule, key) in keys[v].items():
        if n in pos and alerted[v][n] == "novelty":
            (tpk if labels[pos[n]] else fpk)[str(key)] += 1
    r0["novelty_fp_keys"] = fpk.most_common(40); r0["novelty_tp_keys"] = tpk.most_common(40)
    r0["fleet_dropped"] = sum(dropped[v].values())
    res[v] = r0
    log(f"{v}: attacks {r0['attacks']} det-only {len(r0['attacks_det'])} TP {r0['TP']} FP {r0['FP']} by_layer {r0['by_layer']}")
json.dump(res, open(a.out, "w"), indent=1)
