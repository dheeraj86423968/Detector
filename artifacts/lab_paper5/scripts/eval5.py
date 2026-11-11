"""paper5 (artifacts/lab_paper5/PROTOCOL.md): lab_v10 adp13.py unchanged in what it computes, plus (1) --bundle: the
bundle of the run being scored (run 1: the set's v07rel / b07rel; fleet prevalence always uses the other members' run-1
bundles, as adp13), (2) detector-1 alone and detector-2 alone: the seed-ensemble ratios r1 / r2 of the same rt.score()
calls, node score = max over test windows, threshold = max over validation-day nodes (validation day replayed from the
validation-start state, detectors 1-2 only, as Trainer.calibrate_final), (3) amendment 1 (P2 only): ADP of the triage
order with a non-learned tie-break (first alert time, then random; unalerted last in random order; 20 seeds) and layers
1-2 alone (alerts with a novelty / rules reason only: operating point and the same time-ordered ADP), (5) amendment 2:
every stable-order ADP also as the expectation under a random order within ties (mean of 20 permutations) and, for the
triage order and the learned score, the worst case (ground-truth nodes last within every tie); the per-node arrays are
saved next to --out (scores5-*.npz) so that any ranking measure can be recomputed without the bundle, (4) with --gt-extra the base ground truth stays
primary and the extra attacks are scored in a second block. adp13 docstring:
ADP for the paper (artifacts/lab_v10/scripts/adp13.py = eval13.py + node ranking): as eval13, and in addition every
test node's triage-order score (alert severity of each variant, pdp_engine.runtime.alert_tier, then the final learned
score, max over windows; pdp_server.tools.darpa_eval.product_priority) and its ADP (darpa_eval.adp = PIDSMaker's).
--gt-extra adds ground-truth files (CLEARSCOPE_E5: the lockwatch attack Bilot et al. count). Original docstring:
Lab 0.10 (artifacts/lab_v10/PROTOCOL.md): score a set once with its 0.7 released bundle under the 0.9 defaults and
apply the fleet-prevalence variants to the same windows (layer hits are used only by the alert policy, so rewriting
the novelty hits per variant equals running the layer with a fleet list). Records node-level results and every alert
row the agent would report (per window, real-time duplicates within 2 h dropped) with the agent's one-hop context, for
the incident analysis (inc13.py). Usage: eval13.py SET --out res.json --rows rows.json.gz"""
import argparse, copy, dataclasses, gzip, json, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from pdp_engine.layers import FLEET_KNOWN_RULE, UNKNOWN_PROGRAM, program_name
from pdp_engine.schema import EDGE_TYPES
from common8 import Set, log, at, load_gt
from pdp_engine.runtime import alert_tier
from pdp_server.tools.darpa_eval import adp

FLEETS = {"CARBANAKV2": [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)], "OPTC": ["OPTC_H201", "OPTC_H501", "OPTC_H051"],
          "ATLASV2": ["ATLASV2_EDR-h1", "ATLASV2_EDR-h2"],
          "E3": ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "FIVEDIRECTIONS_E3", "TRACE_E3-trace"],
          "THEIA_E5": ["THEIA_E5-theia"], "CLEARSCOPE_E5": ["CLEARSCOPE_E5-clearscope"]}
BUNDLE = {s: "b07rel" for s in FLEETS["CARBANAKV2"] + ["THEIA_E5-theia", "CLEARSCOPE_E5-clearscope"]}
VARIANTS = {"P0": (0, None), "P1": (1, "drop"), "P1e": (1, "evidence"), "P2": (2, "drop"), "P2e": (2, "evidence")}
EARLY_NS = 2 * 3600 * 10**9
ORDER = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("--out", required=True); ap.add_argument("--rows", required=True); ap.add_argument("--gt-extra", default=""); ap.add_argument("--bundle", required=True); ap.add_argument("--run", type=int, required=True)
a = ap.parse_args()
S = Set(a.set)
GTX = dict(S.gt)
if a.gt_extra:
    for k, v in load_gt(a.gt_extra.split(",")).items():
        GTX[k] = v
SC, TIER = {}, {k: {} for k in VARIANTS}
FIRST_T, L12_TIER, L12_T = {}, {}, {}      # amendment 1 (P2): first alert time; layers 1-2 only tier / first time
bdir = a.bundle
t0 = time.time()
# detector-1 / detector-2 alone: thresholds from the validation day (separate runtime without layers, as calibrate_final)
import torch
bst = S.base_store(); breg = bst.load_registry()
rv = Runtime(bdir, breg, device="cuda", feat_device="cuda", layers=False)
rv.reset(at="validation"); rv.bm = None
V1 = np.full(len(rv.reg), -np.inf); V2 = np.full(len(rv.reg), -np.inf)
for w in bst.windows(S.val_day):
    r = rv.score(w)
    if len(V1) < len(rv.reg):
        V1 = np.concatenate([V1, np.full(len(rv.reg) - len(V1), -np.inf)]); V2 = np.concatenate([V2, np.full(len(rv.reg) - len(V2), -np.inf)])
    np.maximum.at(V1, r.node_ids, r.r1); np.maximum.at(V2, r.node_ids, r.r2)
THR = {"detector-1": float(V1[np.isfinite(V1)].max()), "detector-2": float(V2[np.isfinite(V2)].max())}
VN = int(np.isfinite(V1).sum())
del rv, V1, V2, breg, bst; torch.cuda.empty_cache()
log(f"validation replay {time.time()-t0:.0f}s: ensemble thresholds {THR} ({VN} nodes)")
st = S.eval_store(); reg = st.load_registry()
rt = Runtime(bdir, reg, device="cuda", feat_device="cuda")
nov = rt.layers.novelty

# fleet prevalence: other members' baselines (known_executables of their bundles = their training days)
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
    if n == 0 and "/" not in k:            # recorded without a path: by name, as layer 1 matches its own baseline
        n = cnt_name.get(program_name(k), 0)
    return n


def transform(hits, k, mode):
    if not k:
        return hits
    out = []
    for h in hits:
        if h.layer == "novelty":
            n = fleet_n(h.key)
            if n >= k:
                if mode == "drop":
                    continue
                h = dataclasses.replace(h, rule=FLEET_KNOWN_RULE,
                                        detail=f"runs {h.key}, new on this endpoint but known from the baselines of {n} other endpoint(s)")
        out.append(h)
    return out


pols = {}
for k in VARIANTS:
    p = copy.copy(rt.policy); p.reset(); p.evidence_rules = set(p.evidence_rules)
    pols[k] = p
cur, extra = {}, {}


def apply_all(w, ids, fused, hits=None):
    if hits is None:
        hits = rt.layers.process(w, rt.reg, ids)
    own = getattr(rt, "_own", None)
    out = None
    for k, (kk, mode) in VARIANTS.items():
        al, rs, hs = pols[k].apply(w, rt.reg, ids, fused, transform(hits, kk, mode), own=own)
        cur[k] = (al, rs)
        for n in al.tolist():
            TIER[k][n] = max(TIER[k].get(n, 0), alert_tier(rs[n]))
            if k == "P2":
                FIRST_T.setdefault(n, int(w.start_ns))
                l12 = [x for x in rs[n] if x["layer"] in ("novelty", "rules")]
                if l12:
                    L12_TIER[n] = max(L12_TIER.get(n, 0), alert_tier(l12)); L12_T.setdefault(n, int(w.start_ns))
        if k == "P0":
            for n, f in zip(ids.tolist(), np.asarray(fused, dtype=float).tolist()):
                if f > SC.get(n, -1e18):
                    SC[n] = f
        if k == "P0":
            out = (al, rs, hs)
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
R1 = np.full(0, -np.inf); R2 = np.full(0, -np.inf)
for d in S.test_days:
    for w in st.windows(d):
        wr = rt.score(w)
        if len(R1) < len(reg):
            R1 = np.concatenate([R1, np.full(len(reg) - len(R1), -np.inf)]); R2 = np.concatenate([R2, np.full(len(reg) - len(R2), -np.inf)])
        np.maximum.at(R1, wr.node_ids, wr.r1); np.maximum.at(R2, wr.node_ids, wr.r2)
        wctx = {}
        for k, (al, rs) in cur.items():
            for n in al.tolist():
                rsn = rs[n]
                layer = min((x["layer"] for x in rsn), key=lambda x: ORDER.get(x, 9))
                main = next(x for x in rsn if x["layer"] == layer)
                if n not in alerted[k]:
                    alerted[k][n] = layer
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
                                "node_uuid": e.uuid, "ntype": e.ntype, "label": e.label, "display": None, "layer": layer,
                                "rule": main.get("rule"), "reason": main.get("detail"), "status": "open", "ctx": wctx[n],
                                "gt": e.uuid in S.allgt, "attacks": sorted(x for x, v in S.gt.items() if e.uuid in v)})
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, v in S.gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
res = {"set": a.set, "run": a.run, "bundle": bdir, "detector_thresholds": THR, "validation_nodes": VN, "fleet": fleet, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days),
       "variants": {k: list(v) for k, v in VARIANTS.items()}}
for k in VARIANTS:
    pred = np.zeros(len(ix), bool); lay = {}
    for n, l in alerted[k].items():
        if n in pos:
            pred[pos[n]] = True; lay[pos[n]] = l
    r0 = at(pred, labels, na); r0["FP/day"] = round(r0["FP"] / max(1, len(S.test_days)), 1)
    r0["by_layer"] = dict(Counter(lay.values()))
    r0["by_layer_tp"] = dict(Counter(l for j, l in lay.items() if labels[j]))
    r0["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]})
    r0["rows"] = len(rows[k])
    sc = np.array([SC.get(int(i), 0.0) for i in ix]); tr = np.array([TIER[k].get(int(i), 0) for i in ix])
    r0["ADP"] = round(adp(tr * 1e6 + np.clip(sc, 0, 1e5), labels, na), 3)
    r0["ADP_learned_only"] = round(adp(sc, labels, na), 3)
    r0["precision"] = round(r0["TP"] / max(1, r0["TP"] + r0["FP"]), 3)
    res[k] = r0
    log(f"{k}: attacks {r0['attacks']} TP {r0['TP']} FP {r0['FP']} rows {r0['rows']} ADP {r0['ADP']} (learned only {r0['ADP_learned_only']})")
from pdp_engine.scoring import above


def adp_ties(sc, labels, na, worst=False):
    """amendment 2: ADP of the ranking `sc` with ties in random order (mean of NSEED permutations), and the worst case"""
    v = []
    for seed in range(NSEED):
        u = np.random.default_rng(seed).random(len(sc))
        order = np.lexsort((u, -sc))
        r = np.empty(len(sc)); r[order] = -np.arange(len(sc), dtype=float)
        v.append(adp(r, labels, na))
    out = {"random_mean": round(float(np.mean(v)), 3), "random_sd": round(float(np.std(v)), 3), "random_min": round(float(min(v)), 3),
           "random_max": round(float(max(v)), 3)}
    if worst:
        order = np.lexsort((labels.astype(int), -sc))
        r = np.empty(len(sc)); r[order] = -np.arange(len(sc), dtype=float)
        out["worst"] = round(adp(r, labels, na), 3)
    return out


def alone(R, thr, labels, na):
    r = np.nan_to_num(R[ix], nan=0.0, neginf=0.0, posinf=1e30)
    out = {}
    for name, t in (("val_max", thr), ("ratio_1", 1.0)):
        pred = above(r / t)
        m = at(pred, labels, na); m["precision"] = round(m["TP"] / max(1, m["TP"] + m["FP"]), 3)
        m["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]}); m["threshold"] = t
        out[name] = m
    out["ADP"] = round(adp(r, labels, na), 3)
    out["ADP_ties"] = adp_ties(r, labels, na)
    return out


NSEED = 20


def adp_time(tier, t, labels, na):
    """ADP of: tier (desc), then first alert time (asc; unalerted = never), then a random order; mean over NSEED seeds."""
    v = []
    for seed in range(NSEED):
        u = np.random.default_rng(seed).random(len(tier))
        order = np.lexsort((u, t, -tier))
        sc = np.empty(len(tier)); sc[order] = -np.arange(len(tier), dtype=float)
        v.append(adp(sc, labels, na))
    return {"mean": round(float(np.mean(v)), 3), "min": round(float(min(v)), 3), "max": round(float(max(v)), 3), "seeds": NSEED}


def amendment1(labels, na):
    INF = np.iinfo(np.int64).max
    tr = np.array([TIER["P2"].get(int(i), 0) for i in ix], dtype=float)
    tt = np.array([FIRST_T.get(int(i), INF) for i in ix], dtype=np.int64)
    out = {"ADP_triage_time_tiebreak": adp_time(tr, tt, labels, na)}
    lt = np.array([L12_TIER.get(int(i), 0) for i in ix], dtype=float)
    lT = np.array([L12_T.get(int(i), INF) for i in ix], dtype=np.int64)
    pred = lt > 0
    m = at(pred, labels, na); m["precision"] = round(m["TP"] / max(1, m["TP"] + m["FP"]), 3)
    m["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]})
    m["ADP_time_tiebreak"] = adp_time(lt, lT, labels, na)
    out["layers12_only"] = m
    return out


res["P2"].update(amendment1(labels, na))
for k in ("P0", "P2"):
    sc = np.array([SC.get(int(i), 0.0) for i in ix]); tr = np.array([TIER[k].get(int(i), 0) for i in ix])
    res[k]["ADP_ties"] = adp_ties(tr * 1e6 + np.clip(sc, 0, 1e5), labels, na, worst=True)
    res[k]["ADP_learned_only_ties"] = adp_ties(sc, labels, na, worst=True)
log(f"amendment 2: P2 triage ADP ties {res['P2']['ADP_ties']}; learned {res['P2']['ADP_learned_only_ties']}")
INF = np.iinfo(np.int64).max
att_names = sorted(S.gt)
np.savez_compressed(a.out.replace("/res5-", "/scores5-").replace(".json", ".npz"), uuid=np.array(uu), labels=labels,
    attacks=np.array([[x in na[j] for x in att_names] for j in range(len(ix))], dtype=bool).reshape(len(ix), len(att_names)),
    attack_names=np.array(att_names), tier_P2=np.array([TIER["P2"].get(int(i), 0) for i in ix], dtype=np.int8),
    learned=np.array([SC.get(int(i), 0.0) for i in ix]), r1=R1[ix], r2=R2[ix],
    first_alert_ns=np.array([FIRST_T.get(int(i), INF) for i in ix], dtype=np.int64),
    tier_L12=np.array([L12_TIER.get(int(i), 0) for i in ix], dtype=np.int8),
    first_L12_ns=np.array([L12_T.get(int(i), INF) for i in ix], dtype=np.int64), thresholds=np.array([THR["detector-1"], THR["detector-2"]]))
log(f"amendment 1: triage ADP time tie-break {res['P2']['ADP_triage_time_tiebreak']}; layers 1-2 only {res['P2']['layers12_only']}")
for k, R in (("detector-1", R1), ("detector-2", R2)):
    res[k] = alone(R, THR[k], labels, na)
    log(f"{k} alone: attacks {res[k]['val_max']['attacks']} TP {res[k]['val_max']['TP']} FP {res[k]['val_max']['FP']} ADP {res[k]['ADP']}")
if a.gt_extra:      # the extra attacks (Bilot et al.'s count): ADP of the same rankings
    allx = set().union(*GTX.values())
    lx = np.array([u in allx for u in uu]); nx = [{k for k, v in GTX.items() if u in v} for u in uu]
    sc = np.array([SC.get(int(i), 0.0) for i in ix]); ex = {"n_attacks": len(GTX), "attacks": sorted(GTX)}
    for k in ("P0", "P2"):
        tr = np.array([TIER[k].get(int(i), 0) for i in ix]); pred = np.array([int(i) in alerted[k] for i in ix])
        ex[k] = {**at(pred, lx, nx), "ADP": round(adp(tr * 1e6 + np.clip(sc, 0, 1e5), lx, nx), 3), "ADP_learned_only": round(adp(sc, lx, nx), 3),
                 "ADP_ties": adp_ties(tr * 1e6 + np.clip(sc, 0, 1e5), lx, nx, worst=True), "ADP_learned_only_ties": adp_ties(sc, lx, nx, worst=True)}
    for k, R in (("detector-1", R1), ("detector-2", R2)):
        ex[k] = alone(R, THR[k], lx, nx)
    ex["P2"].update(amendment1(lx, nx))
    res["with_extra_gt"] = ex
    log(f"with extra gt: P2 {ex['P2']}")
json.dump(res, open(a.out, "w"), indent=1)
with gzip.open(a.rows, "wt") as f:
    keep = {"P2": rows["P2"]}
    json.dump({"set": a.set, "run": a.run, "days": len(S.test_days), "attacks": sorted(S.gt), "ctx": {c: ctxs[c] for c in {r["ctx"] for r in rows["P2"]}}, "rows": keep}, f)
