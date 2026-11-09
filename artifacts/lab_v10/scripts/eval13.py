"""Lab 0.10 (artifacts/lab_v10/PROTOCOL.md): score a set once with its 0.7 released bundle under the 0.9 defaults and
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
from common8 import Set, log, at

FLEETS = {"CARBANAKV2": [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)], "OPTC": ["OPTC_H201", "OPTC_H501", "OPTC_H051"],
          "ATLASV2": ["ATLASV2_EDR-h1", "ATLASV2_EDR-h2"],
          "E3": ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "FIVEDIRECTIONS_E3", "TRACE_E3-trace"],
          "THEIA_E5": ["THEIA_E5-theia"]}
BUNDLE = {s: "b07rel" for s in FLEETS["CARBANAKV2"] + ["THEIA_E5-theia"]}
VARIANTS = {"P0": (0, None), "P1": (1, "drop"), "P1e": (1, "evidence"), "P2": (2, "drop"), "P2e": (2, "evidence")}
EARLY_NS = 2 * 3600 * 10**9
ORDER = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("--out", required=True); ap.add_argument("--rows", required=True)
a = ap.parse_args()
S = Set(a.set)
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
                                "gt": e.uuid in S.allgt, "attacks": sorted(x for x, v in S.gt.items() if e.uuid in v)})
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, v in S.gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
res = {"set": a.set, "bundle": bdir, "fleet": fleet, "n_attacks": len(S.gt), "gt_nodes": int(labels.sum()), "days": len(S.test_days),
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
    res[k] = r0
    log(f"{k}: attacks {r0['attacks']} TP {r0['TP']} FP {r0['FP']} rows {r0['rows']}")
json.dump(res, open(a.out, "w"), indent=1)
with gzip.open(a.rows, "wt") as f:
    json.dump({"set": a.set, "days": len(S.test_days), "attacks": sorted(S.gt), "ctx": ctxs, "rows": rows}, f)
