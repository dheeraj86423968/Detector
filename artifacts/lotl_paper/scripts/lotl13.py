"""LotL counterfactual for the paper (artifacts/lotl_paper/PROTOCOL.md). Copy of artifacts/lab_v10/scripts/adp13.py
(0.10 lab evaluation: the set's released bundle, 0.9 runtime defaults, fleet prevalence k=2 "drop") where
  - the data may be transformed before scoring (--transform):
      none     the recorded test windows (reference: P2 must reproduce lab_v10 res13 P2),
      lotl     lotl.build/apply: the attacker's new programs relabelled as baseline programs (registry labels only),
      launder  lotl + launder.py (payload files copied through three intermediate files; adds events),
  - the alert-policy variants are
      P2   0.10 as released (fleet prevalence k=2 drop),
      F3   P2 + learned-only fallback of lab_v09 F3: learned-only alerts with score above 3x the threshold, at most
           20 per day (the pre-0.9 daily budget),
      L12  P2 hits with zero learned evidence = layers 1-2 only (= baselines_paper anchor13.py A0).
Records node-level results per variant, the first alerting layer / rule per node, and every alert row the agent would
report (as eval13, for inc13.py and the evidence classes), with the original label of relabelled nodes.
Usage: lotl13.py SET --transform none|lotl|launder --out res.json --rows rows.json.gz [--map map.json] [--gt-extra f]"""
import argparse, copy, gzip, json, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from pdp_engine.layers import UNKNOWN_PROGRAM, program_name
from pdp_engine.schema import EDGE_TYPES
from common8 import Set, log, at, load_gt
import lotl

FLEETS = {"CARBANAKV2": [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)], "OPTC": ["OPTC_H201", "OPTC_H501", "OPTC_H051"],
          "ATLASV2": ["ATLASV2_EDR-h1", "ATLASV2_EDR-h2"],
          "E3": ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "FIVEDIRECTIONS_E3", "TRACE_E3-trace"],
          "THEIA_E5": ["THEIA_E5-theia"], "CLEARSCOPE_E5": ["CLEARSCOPE_E5-clearscope"]}
BUNDLE = {s: "b07rel" for s in FLEETS["CARBANAKV2"] + ["THEIA_E5-theia", "CLEARSCOPE_E5-clearscope"]}
VARIANTS = ["P2", "F3", "L12"]
F3_FLOOR, F3_BUDGET = 3.0, 20
EARLY_NS = 2 * 3600 * 10**9
ORDER = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("--out", required=True); ap.add_argument("--rows", required=True)
ap.add_argument("--transform", choices=["none", "lotl", "launder", "lotlall"], required=True); ap.add_argument("--map", default="")
ap.add_argument("--gt-extra", default="")
a = ap.parse_args()
S = Set(a.set)
if a.gt_extra:
    for k, v in load_gt(a.gt_extra.split(",")).items():
        S.gt[k] = v
    S.allgt = set().union(*S.gt.values())
bdir = f"{S.work}/{BUNDLE.get(a.set, 'v07rel')}"
st = S.eval_store(); reg = st.load_registry()
N = json.load(open(f"{bdir}/manifest.json"))["num_nodes"]
t0 = time.time()

# ---- transform (before the Runtime featurises the registry)
orig_label, tinfo, LA = {}, {"transform": a.transform}, None
if a.transform != "none":
    test_nodes = set()
    for d in S.test_days:
        for w in st.windows(d):
            test_nodes.update(np.unique(np.concatenate([w.src, w.dst])).tolist())
    relabel, rep = lotl.build(S, reg, bdir, N, test_nodes, all_new=(a.transform == "lotlall"))
    orig_label = {i: reg.entities[i].label for i in relabel}
    lotl.apply(reg, relabel)
    tinfo["lotl"] = rep
    log(f"lotl: {rep['renamed_nodes']} process nodes relabelled ({rep['renamed_gt']} ground truth), still new to layer 1: {rep['still_unknown']}")
    if a.transform == "launder":
        import launder
        LA = launder.Launder(S, reg, bdir, N, st, set(relabel))
        tinfo["launder"] = LA.report
        log(f"launder: {json.dumps(LA.report)[:600]}")
    del test_nodes
log(f"transform done {time.time()-t0:.0f}s")

rt = Runtime(bdir, reg, device="cuda", feat_device="cuda")
nov = rt.layers.novelty

# fleet prevalence (as eval13 / adp13): other members' baselines
fleet = next(m for m in FLEETS.values() if a.set in m)
cnt_key, cnt_name = Counter(), Counter()
for o in fleet:
    if o == a.set:
        continue
    So = Set(o)
    known = json.load(open(f"{So.work}/{BUNDLE.get(o, 'v07rel')}/layers.json"))["known_executables"]
    keys = {nov.key(k) for k in known if k not in UNKNOWN_PROGRAM}
    cnt_key.update(keys); cnt_name.update({program_name(k) for k in keys})
log(f"fleet {fleet}: {len(cnt_key)} program keys from {len(fleet) - 1} other endpoints")


def fleet_n(exe):
    k = nov.key(exe)
    n = cnt_key.get(k, 0)
    if n == 0 and "/" not in k:
        n = cnt_name.get(program_name(k), 0)
    return n


def drop2(hits):           # P2: a new program known from >= 2 other endpoints' baselines raises nothing
    return [h for h in hits if not (h.layer == "novelty" and fleet_n(h.key) >= 2)]


pols = {}
for k in VARIANTS:
    p = copy.copy(rt.policy); p.reset(); p.evidence_rules = set(p.evidence_rules)
    pols[k] = p
pols["F3"].learned_floor, pols["F3"].daily_budget = F3_FLOOR, F3_BUDGET
log(f"policy P2: budget {pols['P2'].daily_budget} floor {pols['P2'].learned_floor} corroboration {pols['P2'].corroboration} "
    f"repeat {pols['P2'].repeat_corroborations} near {pols['P2'].near_alert_score}; F3: budget {pols['F3'].daily_budget} floor {pols['F3'].learned_floor}")
cur = {}


def apply_all(w, ids, fused, hits=None):
    if hits is None:
        hits = rt.layers.process(w, rt.reg, ids)
    own = getattr(rt, "_own", None)
    h2 = drop2(hits)
    out = None
    for k in VARIANTS:
        if k == "L12":
            z = np.zeros(len(ids)); res = pols[k].apply(w, rt.reg, ids, z, h2, own=z)
        else:
            res = pols[k].apply(w, rt.reg, ids, fused, h2, own=own)
        al, rs, hs = res
        cur[k] = (al, rs)
        if k == "P2":
            out = res
    return out


rt._alert_policy = apply_all


def context(w, node, cap=300):     # = pdp_agent.agent.Agent.context (hops=1), without edge losses
    src, dst = w.src, w.dst
    m = (src == node) | (dst == node)
    keep = {node} | set(src[m].tolist()) | set(dst[m].tolist())
    m = np.isin(src, list(keep)) & np.isin(dst, list(keep))
    idx = np.where(m)[0][:cap * 4]
    nodes = [{"uuid": reg[i].uuid, "ntype": reg[i].ntype, "label": reg[i].label} for i in sorted(keep)[:cap]]
    edges = [{"src": reg[int(src[i])].uuid, "dst": reg[int(dst[i])].uuid, "op": EDGE_TYPES[int(w.etype[i])], "ts_ns": int(w.t[i])} for i in idx]
    return {"nodes": nodes, "edges": edges}


alerted = {k: {} for k in VARIANTS}
rows = {k: [] for k in VARIANTS}
early = {k: {} for k in VARIANTS}
ctxs, seq = {}, 0
seen = np.zeros(0, bool)
for d in S.test_days:
    for w in st.windows(d):
        if LA is not None:
            w = LA.window(w)
        rt.score(w)
        wctx = {}
        for k, (al, rs) in cur.items():
            for n in al.tolist():
                rsn = rs[n]
                layer = min((x["layer"] for x in rsn), key=lambda x: ORDER.get(x, 9))
                main = next(x for x in rsn if x["layer"] == layer)
                if n not in alerted[k]:
                    alerted[k][n] = (layer, main.get("rule"))
                e = reg.entities[n]
                if layer in ("rules", "novelty"):
                    ek = (e.uuid, main.get("rule"))
                    if ek in early[k] and int(w.start_ns) - early[k][ek] < EARLY_NS:
                        continue
                    early[k][ek] = int(w.start_ns)
                if n not in wctx:
                    cid = f"{int(w.start_ns)}:{n}"
                    ctxs[cid] = context(w, n); wctx[n] = cid
                seq += 1
                rows[k].append({"id": seq, "endpoint_id": a.set, "endpoint_name": a.set, "window_start_ns": int(w.start_ns),
                                "node_uuid": e.uuid, "ntype": e.ntype, "label": e.label, "orig_label": orig_label.get(n),
                                "display": None, "layer": layer, "rule": main.get("rule"), "reason": main.get("detail"),
                                "status": "open", "ctx": wctx[n],
                                "gt": e.uuid in S.allgt, "attacks": sorted(x for x, v in S.gt.items() if e.uuid in v)})
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
if LA is not None:
    tinfo["launder"]["edges_added"] = LA.added
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, v in S.gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
res = {"set": a.set, "bundle": bdir, "fleet": fleet, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days),
       "transform": tinfo, "variants": VARIANTS, "attacks_all": sorted(S.gt)}
for k in VARIANTS:
    pred = np.zeros(len(ix), bool); lay = {}
    for n, (l, r) in alerted[k].items():
        if n in pos:
            pred[pos[n]] = True; lay[pos[n]] = (l, r)
    r0 = at(pred, labels, na); r0["FP/day"] = round(r0["FP"] / max(1, len(S.test_days)), 2)
    r0["TP/day"] = round(r0["TP"] / max(1, len(S.test_days)), 2)
    r0["by_layer"] = dict(Counter(l for l, _ in lay.values()))
    r0["by_layer_tp"] = dict(Counter(l for j, (l, _) in lay.items() if labels[j]))
    r0["by_rule"] = dict(Counter(f"{l}/{r}" for l, r in lay.values()))
    r0["by_rule_tp"] = dict(Counter(f"{l}/{r}" for j, (l, r) in lay.items() if labels[j]))
    r0["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]})
    # per attack: first alerting layer/rule of each of its alerted ground-truth nodes
    pa = {}
    for j in np.where(pred & labels)[0]:
        for x in na[j]:
            pa.setdefault(x, Counter())[f"{lay[j][0]}/{lay[j][1]}"] += 1
    r0["per_attack_gt_rules"] = {x: dict(c) for x, c in pa.items()}
    r0["rows"] = len(rows[k])
    r0["precision"] = round(r0["TP"] / max(1, r0["TP"] + r0["FP"]), 3)
    res[k] = r0
    log(f"{k}: attacks {r0['attacks']} TP {r0['TP']} FP {r0['FP']} rows {r0['rows']} {r0['by_layer']}")
json.dump(res, open(a.out, "w"), indent=1)
with gzip.open(a.rows, "wt") as f:
    json.dump({"set": a.set, "days": len(S.test_days), "attacks": sorted(S.gt), "ctx": ctxs, "rows": rows}, f)
if a.map:
    json.dump(tinfo, open(a.map, "w"), indent=1)
