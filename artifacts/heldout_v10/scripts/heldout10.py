"""Held-out check (artifacts/heldout_v10/PROTOCOL.md), run once: train the 0.6-config bundle on the host's baseline,
upgrade it to 0.7 released (as artifacts/lab_v08/heldout08.py), score the test days once and apply the R / A / N alert
policies to the same windows; record node-level results and every alert row the agent would report (as lab_v10 eval13.py)
for inc13.py. Usage: heldout10.py SET --out res.json --rows rows.json.gz"""
import argparse, copy, gzip, json, os, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from pdp_engine.schema import EDGE_TYPES
from pdp_engine.trainer import TrainConfig, Trainer, upgrade_bundle_07
from common8 import Set, log, at

VARIANTS = {"R": {"daily_budget": 20, "near_alert_score": "final", "repeat_corroborations": 0},
            "A": {"daily_budget": 20, "near_alert_score": "own", "repeat_corroborations": 0},
            "N": {"daily_budget": 0, "near_alert_score": "own", "repeat_corroborations": 1}}
EARLY_NS = 2 * 3600 * 10**9
ORDER = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("--out", required=True); ap.add_argument("--rows", required=True)
a = ap.parse_args()
S = Set(a.set)
os.makedirs(S.work, exist_ok=True)
t0 = time.time()
cfg8 = TrainConfig(device="cuda")
cfg7 = TrainConfig(**{**cfg8.__dict__, "d3_breadth": False, "layer_novelty": True})
cfg6 = TrainConfig(**{**cfg8.__dict__, "detector3": False, "d3_breadth": False, "layer_novelty": True,
                      "novelty_as_evidence": False, "learned_alerts": False})
b6, b7 = os.path.join(S.work, "b06"), os.path.join(S.work, "b07rel")
base = S.base_store()
if not os.path.exists(os.path.join(b6, "manifest.json")):
    Trainer(base, list(S.train_days), S.val_day, cfg6, b6).run({"endpoint": a.set})
log(f"0.6-config bundle {time.time()-t0:.0f}s")
if not os.path.exists(os.path.join(b7, "manifest.json")):
    upgrade_bundle_07(b6, b7, base, cfg7)
log(f"0.7 released bundle {time.time()-t0:.0f}s")

st = S.eval_store(); reg = st.load_registry()
rt = Runtime(b7, reg, device="cuda", feat_device="cuda")
pols = {}
for k, ov in VARIANTS.items():
    p = copy.copy(rt.policy); p.reset(); p.evidence_rules = set(p.evidence_rules)
    for kk, vv in ov.items():
        setattr(p, kk, vv)
    pols[k] = p
cur = {}


def apply_all(w, ids, fused, hits=None):
    if hits is None:
        hits = rt.layers.process(w, rt.reg, ids)
    own = getattr(rt, "_own", None)
    out = None
    for k, p in pols.items():
        al, rs, hs = p.apply(w, rt.reg, ids, fused, hits, own=own)
        cur[k] = (al, rs)
        if k == "N":
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


man = json.load(open(os.path.join(os.path.dirname(S.eval_dir), "manifest.json")))
extra = {}
for name, g in (man.get("ground_truth_not_in_pidsmaker_list") or {}).items():
    import csv
    extra[name] = {r[2].strip() for r in csv.reader(open(os.path.join("/gt", g["csv"]))) if len(r) >= 3 and r[2].strip()}
allextra = set().union(*extra.values()) if extra else set()

alerted = {k: {} for k in VARIANTS}; rows = {k: [] for k in VARIANTS}; early = {k: {} for k in VARIANTS}
ctxs, seq = {}, 0
seen = np.zeros(0, bool)
for d in S.test_days:
    for w in st.windows(d):
        rt.score(w)
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
                                "gt": e.uuid in S.allgt, "attacks": sorted(x for x, v in S.gt.items() if e.uuid in v),
                                "extra_gt": e.uuid in allextra})
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, v in S.gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
res = {"set": a.set, "bundle": b7, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days),
       "extra_gt_nodes_seen": int(sum(u in allextra for u in uu)), "variants": VARIANTS}
for k in VARIANTS:
    pred = np.zeros(len(ix), bool); lay = {}
    for n, l in alerted[k].items():
        if n in pos:
            pred[pos[n]] = True; lay[pos[n]] = l
    r0 = at(pred, labels, na); r0["FP/day"] = round(r0["FP"] / max(1, len(S.test_days)), 1)
    r0["by_layer"] = dict(Counter(lay.values()))
    r0["by_layer_tp"] = dict(Counter(l for j, l in lay.items() if labels[j]))
    r0["attacks_found"] = sorted({x for j in np.where(pred & labels)[0] for x in na[j]})
    r0["FP_that_are_extra_gt"] = int(sum(1 for j in np.where(pred & ~labels)[0] if uu[j] in allextra))
    r0["rows"] = len(rows[k])
    res[k] = r0
    log(f"{k}: attacks {r0['attacks']} TP {r0['TP']} FP {r0['FP']} (of which extra-GT {r0['FP_that_are_extra_gt']}) rows {r0['rows']}")
json.dump(res, open(a.out, "w"), indent=1)
with gzip.open(a.rows, "wt") as f:
    json.dump({"set": a.set, "days": len(S.test_days), "attacks": sorted(S.gt), "ctx": ctxs, "rows": rows}, f)
