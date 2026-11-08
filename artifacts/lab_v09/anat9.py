"""Anatomy of corroborated alerts (0.7 released bundle): for each corroborated node, where its above-threshold
score came from - its own evidence in this window, suspicion carried from earlier windows, or propagated inside the
window - and which deterministic alerts it sat next to. Usage: anat9.py SET BUNDLE_SUBDIR --out file.json"""
import argparse, json, re
from collections import Counter, defaultdict
import numpy as np
from pdp_engine.runtime import Runtime
from pdp_engine.scoring import fill_missing
from common8 import Set, log

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("bundle"); ap.add_argument("--out", required=True)
a = ap.parse_args()
S = Set(a.set)
bdir = a.bundle if a.bundle.startswith("/") else f"{S.work}/{a.bundle}"
st = S.eval_store(); reg = st.load_registry()
rt = Runtime(bdir, reg, device="cuda", feat_device="cuda")
stash = {}
orig = rt._learned_07


def w07(w, ids, fused):
    n = len(rt.reg)
    prev = np.zeros(len(ids))
    k = ids < len(rt.susp)
    prev[k] = rt.susp[ids[k]]
    final, r3 = orig(w, ids, fused)
    own = np.maximum(r3, fill_missing(fused) / rt.learned_unit)
    stash.update(prev=prev / rt.final_thr, own=own / rt.final_thr, final=final)
    return final, r3


rt._learned_07 = w07
thr = rt.corroboration


def short(n):
    e = reg.entities[int(n)]
    lab = re.sub(r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}\}?", "<guid>", e.label)
    return lab[:110]


recs = []; alerted = set(); layer_count = Counter()
for d in S.test_days:
    for w in st.windows(d):
        r = rt.score(w)
        ids = r.node_ids; pos = {int(x): i for i, x in enumerate(ids.tolist())}
        det = {n for n, rs in r.reasons.items() if any(x["layer"] in ("novelty", "rules") for x in rs)}
        for n in r.alerts.tolist():
            if n in alerted:
                continue
            alerted.add(n)
            lay = r.layer_of(n); layer_count[lay] += 1
            if lay != "corroborated":
                continue
            rs = r.reasons[n]
            i = pos.get(n)
            prev, own, fin = (float(stash[k][i]) if i is not None else float("nan") for k in ("prev", "own", "final"))
            src = "own" if own > thr else ("carried" if prev > thr else "propagated")
            if rs[0]["rule"] == "learned_near_alert":
                m = (w.src == n) | (w.dst == n)
                nb = set(np.concatenate([w.src[m], w.dst[m]]).tolist()) & det
            else:
                nb = set()
            anchors = []
            for x in nb:
                ar = r.reasons[x][0]
                anchors.append({"node": int(x), "layer": ar["layer"], "rule": ar["rule"], "label": short(x)})
            recs.append({"node": int(n), "gt": reg.entities[int(n)].uuid in S.allgt, "ntype": reg.entities[int(n)].ntype,
                         "label": short(n), "rule": rs[0]["rule"], "src": src, "prev": round(prev, 2), "own": round(own, 2),
                         "final": round(fin, 2), "anchors": anchors, "t": int(w.start_ns)})
log(f"alerts by layer {dict(layer_count)}; corroborated {len(recs)}")
summ = {"set": a.set, "bundle": a.bundle, "by_layer": dict(layer_count), "n": len(recs),
        "src": dict(Counter(x["src"] for x in recs)), "src_tp": dict(Counter(x["src"] for x in recs if x["gt"])),
        "rule": dict(Counter(x["rule"] for x in recs)), "ntype": dict(Counter(x["ntype"] for x in recs)),
        "n_anchor_nodes": len({y["node"] for x in recs for y in x["anchors"]})}
per_anchor = Counter(); alab = {}
for x in recs:
    for y in x["anchors"]:
        per_anchor[y["node"]] += 1; alab[y["node"]] = f'{y["layer"]}/{y["rule"]}: {y["label"]}'
summ["top_anchors"] = [(alab[k], v) for k, v in per_anchor.most_common(15)]
summ["anchors_per_corr"] = dict(Counter(min(len(x["anchors"]), 5) for x in recs))
summ["tp"] = [x for x in recs if x["gt"]][:40]
summ["top_labels"] = Counter(re.sub(r"\d+", "#", x["label"])[:70] for x in recs).most_common(15)
print(json.dumps({k: v for k, v in summ.items() if k != "tp"}, indent=1))
json.dump({"summary": summ, "recs": recs}, open(a.out, "w"))
