"""BL (detector-3 prototype) + 0.5 learned fused as seeds, plus learned-seeded provenance propagation.
Usage: run_v2.py DATASET --mode once --out f.json"""
import argparse, json, time
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.schema import EDGE_TYPE_ID
from common import D, log, load_gt, bundle_split, report
import bl

ap = argparse.ArgumentParser(); ap.add_argument("dataset"); ap.add_argument("--out"); ap.add_argument("--mode", default="once")
ap.add_argument("--jobs", default="/lab/jobs05.txt"); ap.add_argument("--deltas", default="0,0.5,0.7,0.85,0.95")
a = ap.parse_args()
eid, test_days, gtf = D[a.dataset]
B05 = {l.split()[0]: l.split()[2] for l in open(a.jobs)}
train_days, val_day = bundle_split(eid)
voc = bl.Vocab()
base = WindowStore(f"/data/endpoints/{eid}/baseline"); breg = base.load_registry(); KB = bl.Keyed(voc, breg)
m = bl.BL()
for d in train_days:
    for w in base.windows(d):
        m.fit_window(w, KB)
m.finish(); log(f"{a.dataset}: fitted")
OPEN = EDGE_TYPE_ID["OPEN"]
DELTAS = [float(x) for x in a.deltas.split(",")]


def node_own(w, K, n):
    p, x, r, e, s = bl.instance_scores(m, K, w, a.mode)
    own = np.zeros(n); np.maximum.at(own, p, s); np.maximum.at(own, x, s)
    return own


def propagate(w, level, delta, passes=3):
    """level: per-node suspicion (registry-indexed, carried across windows). Push delta * level along data-flow
    edges (src -> dst) of this window, `passes` relaxation rounds (OPEN edges excluded)."""
    if delta <= 0:
        return level
    keep = w.etype != OPEN
    s, d = w.src[keep], w.dst[keep]
    for _ in range(passes):
        cand = delta * level[s]
        before = level[d].copy()
        np.maximum.at(level, d, cand)
        if np.array_equal(level[d], before):
            break
    return level


# validation thresholds of BL own scores per node type
vown_max = {}
vn = np.zeros(len(breg)); seen_v = np.zeros(len(breg), bool)
for w in base.windows(val_day):
    o = node_own(w, KB, len(breg)); np.maximum(vn, o, out=vn); seen_v[w.src] = True; seen_v[w.dst] = True
thr = {"proc": float(vn[seen_v & KB.isproc].max()), "obj": float(vn[seen_v & ~KB.isproc].max())}
log(f"val thr {thr}")

st = WindowStore(f"/data/endpoints/{eid}/eval-test"); reg = st.load_registry(); K = bl.Keyed(voc, reg); n = len(reg)
tnorm = np.where(K.isproc, thr["proc"], thr["obj"])
z = np.load(f"/data/lab/{eid}/{B05[eid]}.npz"); off = np.concatenate([[0], np.cumsum(z["wlen"])])
wins = [w for dd in test_days for w in st.windows(dd)]
assert len(wins) == len(z["wlen"])
levels = {(src, dl): np.zeros(n) for src in ("bl", "learned", "both") for dl in DELTAS}
best = {k: np.zeros(n) for k in levels}
seen = np.zeros(n, bool)
for k, w in enumerate(wins):
    own_bl = node_own(w, K, n) / tnorm
    own_l = np.zeros(n); ids = z["ids"][off[k]:off[k + 1]]; fu = z["fused"][off[k]:off[k + 1]]
    fu = np.where(np.isfinite(fu), fu, 0); np.maximum.at(own_l, ids, fu)
    seen[w.src] = True; seen[w.dst] = True
    for (src, dl), lv in levels.items():
        own = own_bl if src == "bl" else own_l if src == "learned" else np.maximum(own_bl, own_l)
        np.maximum(lv, own, out=lv)
        propagate(w, lv, dl)
        np.maximum(best[(src, dl)], lv, out=best[(src, dl)])
    if k % 50 == 0:
        log(f"window {k}/{len(wins)}")
ix = np.where(seen)[0]
gt = load_gt(gtf); allgt = set().union(*gt.values())
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in allgt for u in uu]); node_att = [{kk for kk, v in gt.items() if u in v} for u in uu]
res = {"_meta": {"gt_nodes": int(labels.sum()), "test_nodes": int(len(ix)), "thr": thr}}
for (src, dl), b in best.items():
    res[f"{src}|d{dl}"] = report("", b[ix], labels, node_att, len(gt), len(test_days), {"1.0": 1.0 + 1e-4})
for kname, v in res.items():
    if kname.startswith("_"):
        continue
    print(kname, "ADP", v["ADP"], " ".join(f"{bb}:{v[bb]['TP']}/{v[bb]['attacks']}" for bb in ("fp10/day", "fp50/day", "fp200/day")),
          "thr1:", v["thr:1.0"], flush=True)
if a.out:
    json.dump(res, open(a.out, "w"), indent=1)
