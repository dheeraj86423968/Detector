"""Lab 0.15 (artifacts/lab_v15/PROTOCOL.md; eval17 of lab 0.14 with rule_instances and attack-days): score a set once with its released bundle; every variant has its own
deterministic layers (out/layers17-SET-<variant>.json from prep17.py; Z0 = the bundle's) and alert policy, fed the
same windows and learned scores. Fleet prevalence P2 "drop": other members' known programs under the same variant.
Records per variant the node results and every alerted node's first reason. Usage: eval17.py SET --out res.json"""
import argparse, copy, gzip, json, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from pdp_engine.layers import UNKNOWN_PROGRAM, DeterministicLayers, program_name
from common8 import Set, log, at

FLEETS = {"CARBANAKV2": [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)], "OPTC": ["OPTC_H201", "OPTC_H501", "OPTC_H051"],
          "ATLASV2": ["ATLASV2_EDR-h1", "ATLASV2_EDR-h2"],
          "E3": ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "FIVEDIRECTIONS_E3", "TRACE_E3-trace"],
          "THEIA_E5": ["THEIA_E5-theia"]}
BUNDLE = {s: "b07rel" for s in FLEETS["CARBANAKV2"] + ["THEIA_E5-theia"]}
FLEET_K = 2
ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("--out", required=True)
ap.add_argument("--variants", default="C0=R0,C1=N1,C2=N2,C3=N3,C4=N4", help="name=layers variant of prep17")
ap.add_argument("--tag", default="layers17"); ap.add_argument("--instances", type=int, default=1)
a = ap.parse_args()
SRC = dict(x.split("=") for x in a.variants.split(","))
VARIANTS = ("Z0",) + tuple(SRC)
S = Set(a.set)
bdir = lambda s: f"{Set(s).work}/{BUNDLE.get(s, 'v07rel')}"
st = S.eval_store(); reg = st.load_registry()
t0 = time.time()
rt = Runtime(bdir(a.set), reg, device="cuda", feat_device="cuda")
fleet = next(m for m in FLEETS.values() if a.set in m)
def spec_of(s, v):
    if v == "Z0":
        return json.load(open(f"{bdir(s)}/layers.json"))
    sp = json.load(open(f"out/{a.tag}-{s}-{SRC[v]}.json"))
    sp["config"]["rule_instances"] = a.instances          # lab 0.15: one layer-2 alarm per (alarm, program, counterpart) and day
    return sp
L, pols, cnt_key, cnt_name = {}, {}, {}, {}
for v in VARIANTS:
    L[v] = rt.layers if v == "Z0" else DeterministicLayers(spec_of(a.set, v), rt.m["num_nodes"])
    nov = L[v].novelty
    ck, cn = Counter(), Counter()
    for o in fleet:
        if o != a.set:
            keys = {nov.key(k) for k in spec_of(o, v)["known_executables"] if k not in UNKNOWN_PROGRAM}
            ck.update(keys); cn.update({program_name(k) for k in keys})
    cnt_key[v], cnt_name[v] = ck, cn
    p = copy.copy(rt.policy); p.layers = L[v]; p.reset(); p.evidence_rules = set(p.evidence_rules)
    pols[v] = p


def fleet_n(v, exe):
    k = L[v].novelty.key(exe)
    n = cnt_key[v].get(k, 0)
    if n == 0 and "/" not in k:
        n = cnt_name[v].get(program_name(k), 0)
    return n


cur = {}


def apply_all(w, ids, fused, hits=None):
    own = getattr(rt, "_own", None)
    out = None
    for v in VARIANTS:
        hs = L[v].process(w, rt.reg, ids)
        hs = [h for h in hs if not (h.layer == "novelty" and fleet_n(v, h.key) >= FLEET_K)]
        al, rs, hh = pols[v].apply(w, rt.reg, ids, fused, hs, own=own)
        cur[v] = (al, rs)
        if out is None:
            out = (al, rs, hh)
    return out


rt._alert_policy = apply_all
ORDER = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}
alerted = {v: {} for v in VARIANTS}
adays = {v: set() for v in VARIANTS}            # (attack, test day) with an alerted ground-truth node
nalerts = {v: 0 for v in VARIANTS}              # alert rows (a node alerting in a window)
uu_attacks = {}
seen = np.zeros(0, bool)
for d in S.test_days:
    for w in st.windows(d):
        rt.score(w)
        for v, (al, rs) in cur.items():
            nalerts[v] += len(al)
            for n in al.tolist():
                u = reg.entities[n].uuid
                if u in S.allgt:
                    if u not in uu_attacks:
                        uu_attacks[u] = [k for k, x in S.gt.items() if u in x]
                    adays[v].update((k, d) for k in uu_attacks[u])
                if n not in alerted[v]:
                    layer = min((x["layer"] for x in rs[n]), key=lambda x: ORDER.get(x, 9))
                    main = next(x for x in rs[n] if x["layer"] == layer)
                    alerted[v][n] = (layer, main.get("rule"), str(main.get("key")), (main.get("detail") or "")[:240])
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, x in S.gt.items() if u in x} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
res = {"set": a.set, "fleet": fleet, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days), "nodes": {}}
for v in VARIANTS:
    pred = np.zeros(len(ix), bool); lay = {}
    for n, x in alerted[v].items():
        if n in pos:
            pred[pos[n]] = True; lay[pos[n]] = x[0]
    r0 = at(pred, labels, na)
    r0["by_layer"] = dict(Counter(lay.values())); r0["by_layer_tp"] = dict(Counter(l for j, l in lay.items() if labels[j]))
    r0["by_rule_fp"] = dict(Counter(x[1] for n, x in alerted[v].items() if n in pos and not labels[pos[n]]))
    r0["by_rule_tp"] = dict(Counter(x[1] for n, x in alerted[v].items() if n in pos and labels[pos[n]]))
    r0["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]})
    r0["attacks_det"] = sorted({x for j, l in lay.items() if labels[j] and l in ("novelty", "rules") for x in na[j]})
    r0["attack_days"] = sorted(map(list, adays[v])); r0["alert_rows"] = nalerts[v]
    res[v] = r0
    res["nodes"][v] = {reg.entities[n].uuid: [x[0], x[1], x[2], x[3], bool(labels[pos[n]]), reg.entities[n].label[:160]]
                       for n, x in alerted[v].items() if n in pos}
    log(f"{v}: attacks {r0['attacks']} det-only {len(r0['attacks_det'])} TP {r0['TP']} FP {r0['FP']} by_layer {r0['by_layer']}")
with gzip.open(a.out + ".gz", "wt") as f:
    json.dump(res, f)
