"""Anchoring with the ORIGINAL systems' learned evidence (baselines_paper PROTOCOL amendment of 2026-11-11 18:05).
Copy of artifacts/lab_v10/scripts/adp13.py (0.10 lab evaluation) with ONLY the learned-detector evidence replaced:
  P0, P2 : as adp13 (our learned score; P2 = 0.10 as released) - sanity check against res13 / adp-*.json.
  A0     : P2 with zero learned evidence everywhere = layers 1-2 only (with fleet prevalence k=2, drop).
  X:<f>  : P2 with the learned evidence of score file <f> (scores/*.csv.gz, joined on index_id = registry uuid):
           a node is "learned above threshold" (fused = own = corroboration threshold + 1) in EVERY window where it
           appears iff its alert column is 1, else 0. Per-node scores are window-independent (approximation).
Ranking (darpa_eval.adp): tier of the variant x 1e6 + second key, second key = our learned score (P0/P2, as adp13),
the original system score (X), or a random order (mean of 20 shuffles, seed 0). Also dumps per-node tier/score/label
of P2 for the tie analysis (--nodes)."""
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
VARIANTS = {"P0": (0, None), "P2": (2, "drop")}
EARLY_NS = 2 * 3600 * 10**9
ORDER = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("--out", required=True); ap.add_argument("--nodes", default=""); ap.add_argument("--gt-extra", default=""); ap.add_argument("--scores", nargs="*", default=[])
a = ap.parse_args()
S = Set(a.set)
if a.gt_extra:
    for k, v in load_gt(a.gt_extra.split(",")).items():
        S.gt[k] = v
    S.allgt = set().union(*S.gt.values())
SC, TIER = {}, {k: {} for k in VARIANTS}
bdir = f"{S.work}/{BUNDLE.get(a.set, 'v07rel')}"
st = S.eval_store(); reg = st.load_registry()
t0 = time.time()
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



import csv as _csv
SUBS = {}
for f in a.scores:
    m = {}
    for r in _csv.DictReader(gzip.open(f, "rt")):
        m[r["index_id"]] = (float(r["score"]), int(r["alert"]))
    SUBS["X:" + f.split("/")[-1].replace(".csv.gz", "")] = m
log(f"score files: {[(k, len(v), sum(x[1] for x in v.values())) for k, v in SUBS.items()]}")
ALL = ["P0", "P2", "A0"] + list(SUBS)
TIER = {k: {} for k in ALL}
pols = {}
for k in ALL:
    p = copy.copy(rt.policy); p.reset(); p.evidence_rules = set(p.evidence_rules)
    pols[k] = p
P = pols["P2"]
HI = max(float(P.corroboration), 1.0) + 1.0
log(f"policy: corroboration {P.corroboration} daily_budget {P.daily_budget} learned_alerts {P.learned_alerts} near_alert {P.near_alert} score {P.near_alert_score} -> HI {HI}")
alertvec = {k: np.zeros(0) for k in SUBS}


def subvec(k, n):
    v = alertvec[k]
    if len(v) < n:
        m = SUBS[k]
        ext = np.array([HI if m.get(reg.entities[i].uuid, (0, 0))[1] == 1 else 0.0 for i in range(len(v), n)])
        alertvec[k] = v = np.concatenate([v, ext])
    return v


cur = {}


def apply_all(w, ids, fused, hits=None):
    if hits is None:
        hits = rt.layers.process(w, rt.reg, ids)
    own = getattr(rt, "_own", None)
    out = None
    h2 = transform(hits, 2, "drop")
    for k in ALL:
        if k == "P0":
            res = pols[k].apply(w, rt.reg, ids, fused, transform(hits, 0, None), own=own); out = res
        elif k == "P2":
            res = pols[k].apply(w, rt.reg, ids, fused, h2, own=own)
        elif k == "A0":
            z = np.zeros(len(ids)); res = pols[k].apply(w, rt.reg, ids, z, h2, own=z)
        else:
            s = subvec(k, len(rt.reg))[ids]; res = pols[k].apply(w, rt.reg, ids, s, h2, own=s)
        al, rs, hs = res
        cur[k] = (al, rs)
        for n in al.tolist():
            TIER[k][n] = max(TIER[k].get(n, 0), alert_tier(rs[n]))
        if k == "P0":
            for n, f in zip(ids.tolist(), np.asarray(fused, dtype=float).tolist()):
                if f > SC.get(n, -1e18):
                    SC[n] = f
    return out


rt._alert_policy = apply_all
alerted = {k: {} for k in ALL}
seen = np.zeros(0, bool)
for d in S.test_days:
    for w in st.windows(d):
        rt.score(w)
        for k, (al, rs) in cur.items():
            for n in al.tolist():
                if n not in alerted[k]:
                    alerted[k][n] = min((x["layer"] for x in rs[n]), key=lambda x: ORDER.get(x, 9))
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, v in S.gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
sc = np.array([SC.get(int(i), 0.0) for i in ix])
rng = np.random.default_rng(0); RND = [rng.random(len(ix)) for _ in range(20)]
res = {"set": a.set, "bundle": bdir, "fleet": fleet, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days),
       "nodes": int(len(ix)), "HI": HI, "corroboration": float(P.corroboration), "daily_budget": int(P.daily_budget)}
tpset = {}
for k in ALL:
    pred = np.zeros(len(ix), bool); lay = {}
    for n, l in alerted[k].items():
        if n in pos:
            pred[pos[n]] = True; lay[pos[n]] = l
    r0 = at(pred, labels, na); r0["FP/day"] = round(r0["FP"] / max(1, len(S.test_days)), 2)
    r0["by_layer"] = dict(Counter(lay.values())); r0["by_layer_tp"] = dict(Counter(l for j, l in lay.items() if labels[j]))
    r0["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]})
    tpset[k] = set(np.where(pred & labels)[0].tolist())
    tr = np.array([TIER[k].get(int(i), 0) for i in ix])
    r0["ADP_tier_random20"] = round(float(np.mean([adp(tr * 1e6 + r, labels, na) for r in RND])), 4)
    if k in ("P0", "P2"):
        r0["ADP_tier_ours"] = round(adp(tr * 1e6 + np.clip(sc, 0, 1e5), labels, na), 4)
    if k.startswith("X:"):
        m = SUBS[k]
        osc = np.array([m.get(u, (-1e9, 0))[0] for u in uu])
        u_, inv_ = np.unique(osc, return_inverse=True); orank = inv_ / max(1, len(u_))   # order-preserving, ties kept, in [0, 1)
        r0["ADP_tier_original"] = round(adp(tr * 1e6 + orank, labels, na), 4)
        r0["ADP_tier_ours"] = round(adp(tr * 1e6 + np.clip(sc, 0, 1e5), labels, na), 4)
        alone = np.array([m.get(u, (0, 0))[1] == 1 for u in uu])
        ra = at(alone, labels, na); ra["FP/day"] = round(ra["FP"] / max(1, len(S.test_days)), 2)
        ra["attacks_found"] = sorted({x for j in np.where(alone & labels)[0] for x in na[j]})
        ra["system_alerts_total"] = int(sum(x[1] for x in m.values())); ra["system_alerts_in_lab_nodes"] = int(alone.sum())
        ra["lab_nodes_with_score"] = int(sum(u in m for u in uu))
        r0["system_alone"] = ra
    res[k] = r0
for k in ALL:
    if k in ("P0", "A0"):
        continue
    extra = tpset[k] - tpset["A0"]
    res[k]["tp_only_via_learned"] = len(extra)
    res[k]["attacks_only_via_learned"] = sorted(set(res[k]["attacks_found"]) - set(res["A0"]["attacks_found"]))
    log(f"{k}: attacks {res[k]['attacks']} TP {res[k]['TP']} FP {res[k]['FP']} +TP vs A0 {len(extra)} ADP orig {res[k].get('ADP_tier_original')} ours {res[k].get('ADP_tier_ours')} rnd {res[k]['ADP_tier_random20']}")
log(f"A0: attacks {res['A0']['attacks']} TP {res['A0']['TP']} FP {res['A0']['FP']}")
json.dump(res, open(a.out, "w"), indent=1)
if a.nodes:
    tr = np.array([TIER["P2"].get(int(i), 0) for i in ix])
    np.savez_compressed(a.nodes, tier=tr, sc=np.clip(sc, 0, 1e5), label=labels, att=np.array([";".join(sorted(x)) for x in na]))
