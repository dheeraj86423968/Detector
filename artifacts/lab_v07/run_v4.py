"""Chain scoring: own anomaly (BL, optionally the 0.5 learned fused) + delta * inherited suspicion along data-flow
edges; every variant calibrated on the benign validation day (threshold = its max), as the product does.
Usage: run_v3.py DATASET [--learned] --out f.json"""
import argparse, json, os
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.schema import EDGE_TYPE_ID
from common import D, log, load_gt, bundle_split, report
import bl

ap = argparse.ArgumentParser(); ap.add_argument("dataset"); ap.add_argument("--out"); ap.add_argument("--mode", default="once")
ap.add_argument("--learned", action="store_true"); ap.add_argument("--floor", default="proper")
ap.add_argument("--variants", default="max:0,max:0.85,add:0.3,add:0.5,add:0.7")
ap.add_argument("--seed", type=float, default=0.3); ap.add_argument("--clip", type=float, default=3.0); ap.add_argument("--passes", type=int, default=2); ap.add_argument("--budget", type=int, default=0); ap.add_argument("--online", action="store_true"); ap.add_argument("--save")
a = ap.parse_args()
eid, test_days, gtf = D[a.dataset]
B05 = {l.split()[0]: l.split()[2] for l in open("/lab/jobs05.txt")}
train_days, val_day = bundle_split(eid)
voc = bl.Vocab()
base = WindowStore(f"/data/endpoints/{eid}/baseline"); breg = base.load_registry(); KB = bl.Keyed(voc, breg)
m = bl.BL(); m.floor = a.floor
for d in train_days:
    for w in base.windows(d):
        m.fit_window(w, KB)
m.finish(); log(f"{a.dataset}: fitted")
OPEN = EDGE_TYPE_ID["OPEN"]
UPDATE = False
RUN_PERDAY = {}
CAL_NOW = {}
VARS = [(v.split(":")[0], float(v.split(":")[1]), float(v.split(":")[2]) if v.count(":") > 1 else 0.0) for v in a.variants.split(",")]
SOURCES = ["bl"] + (["learned", "both"] if a.learned else [])


def node_own(w, K, n, tn=None):
    p, x, r, e, s = bl.instance_scores(m, K, w, a.mode)
    own = np.zeros(n); np.maximum.at(own, p, s); np.maximum.at(own, x, s)
    if tn is None:
        return own
    es = np.zeros(w.num_edges); np.maximum.at(es, e, s / tn[p])      # edge score in process-threshold units
    return own, es


def chain(w, level, own, kind, delta, gate=0.0, es=None, passes=None):
    passes = passes or a.passes
    """level: carried suspicion (registry-indexed). max: level = max(level, own, delta * parent level);
    add: level = max(level, own + delta * parent level) for parents above the seed floor."""
    np.maximum(level, own, out=level)
    if delta <= 0:
        return
    keep = w.etype != OPEN
    if gate > 0 and es is not None:
        keep &= es >= gate                      # only unusual edges carry suspicion
    s, d = w.src[keep], w.dst[keep]
    for _ in range(passes):
        ps = np.minimum(level[s], a.clip)
        ok = ps >= a.seed
        if not ok.any():
            break
        cand = delta * ps[ok] if kind == "max" else own[d[ok]] + delta * ps[ok]
        before = level[d[ok]].copy()
        np.maximum.at(level, d[ok], cand)
        if np.array_equal(level[d[ok]], before):
            break


def learned_own(z, off, k, n):
    o = np.zeros(n); ids = z["ids"][off[k]:off[k + 1]]; fu = z["fused"][off[k]:off[k + 1]]
    np.maximum.at(o, ids, np.where(np.isfinite(fu), fu, 0))
    return o


def run(st, days, K, n, tnorm, zpath):
    z = off = None
    if a.learned:
        z = np.load(zpath); off = np.concatenate([[0], np.cumsum(z["wlen"])])
    wins = [w for dd in days for w in st.windows(dd)]
    if z is not None:
        assert len(wins) == len(z["wlen"]), (len(wins), len(z["wlen"]))
    lv = {(src, kd, dl, g): np.zeros(n) for src in SOURCES for kd, dl, g in VARS}
    best = {k: np.zeros(n) for k in lv}
    perday = {k: np.zeros((len(days), n), np.float32) for k in lv}
    seen = np.zeros(n, bool)
    day_of = [dd for dd in days for _ in st.windows(dd)]
    for k, w in enumerate(wins):
        if UPDATE and k > 0 and day_of[k] != day_of[k - 1]:
            # daily incremental update of the BL counts with the finished day, minus nodes that alerted on it
            excl = np.zeros(n, bool)
            for key_, b_ in best.items():
                excl |= b_ > CAL_NOW.get(key_, np.inf)
            for w2 in st.windows(day_of[k - 1]):
                m.fit_window(w2, K, excl)
            m.finish()
        ob, es = node_own(w, K, n, tnorm)
        ob = ob / tnorm
        ol = learned_own(z, off, k, n) / LTHR if z is not None else None
        seen[w.src] = True; seen[w.dst] = True
        for (src, kd, dl, g), L in lv.items():
            own = ob if src == "bl" else ol if src == "learned" else np.maximum(ob, ol)
            chain(w, L, own, kd, dl, g, es)
            np.maximum(best[(src, kd, dl, g)], L, out=best[(src, kd, dl, g)])
            di = days.index(day_of[k])
            np.maximum(perday[(src, kd, dl, g)][di], L, out=perday[(src, kd, dl, g)][di])
    RUN_PERDAY.clear(); RUN_PERDAY.update(perday)
    return best, seen

# BL own-score normalisation per node type: validation max of own scores (no chain)
vn = np.zeros(len(breg)); sv = np.zeros(len(breg), bool)
for w in base.windows(val_day):
    np.maximum(vn, node_own(w, KB, len(breg)), out=vn); sv[w.src] = True; sv[w.dst] = True
def top(v, k):
    """(k+1)-th largest value: the threshold that lets k benign validation nodes through (k=0: the max)."""
    v = np.sort(v)[::-1]
    return float(v[min(k, len(v) - 1)])
thr = {"proc": top(vn[sv & KB.isproc], a.budget), "obj": top(vn[sv & ~KB.isproc], a.budget)}
LTHR = 1.0
if a.learned:
    zv = np.load(f"/data/lab/{eid}/{B05[eid]}.val.npz")
    lv_ = np.full(len(breg), -np.inf); np.maximum.at(lv_, zv["ids"], np.where(np.isfinite(zv["fused"]), zv["fused"], 0))
    LTHR = top(lv_[np.isfinite(lv_)], a.budget)
log(f"own thr {thr} learned thr {LTHR}")
vbest, vseen = run(base, [val_day], KB, len(breg), np.where(KB.isproc, thr["proc"], thr["obj"]),
                   f"/data/lab/{eid}/{B05[eid]}.val.npz")
cal = {k: top(v[vseen], a.budget) for k, v in vbest.items()}
CAL_NOW.update(cal)
if a.online:      # the validation day joins the model once it has been used for calibration
    for w in base.windows(val_day):
        m.fit_window(w, KB)
    m.finish()
    UPDATE = True
log(f"chain thresholds {cal}")
st = WindowStore(f"/data/endpoints/{eid}/eval-test"); reg = st.load_registry(); K = bl.Keyed(voc, reg); n = len(reg)
best, seen = run(st, test_days, K, n, np.where(K.isproc, thr["proc"], thr["obj"]), f"/data/lab/{eid}/{B05[eid]}.npz")
ix = np.where(seen)[0]
gt = load_gt(gtf); allgt = set().union(*gt.values())
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in allgt for u in uu]); node_att = [{kk for kk, v in gt.items() if u in v} for u in uu]
res = {"_meta": {"gt_nodes": int(labels.sum()), "test_nodes": int(len(ix)), "own_thr": thr, "cal": {str(k): v for k, v in cal.items()}}}
for key, b in best.items():
    name = "|".join(map(str, key))
    res[name] = report("", b[ix] / cal[key], labels, node_att, len(gt), len(test_days), {"cal": 1.0 + 1e-6})
    v = res[name]
    print(name, "ADP", v["ADP"], " ".join(f"{bb}:{v[bb]['TP']}/{v[bb]['attacks']}" for bb in ("fp10/day", "fp50/day", "fp200/day")),
          "AT-THRESHOLD:", v["thr:cal"], flush=True)
if a.out:
    json.dump(res, open(a.out, "w"), indent=1)
if a.save:
    np.savez(a.save, ix=ix, labels=labels, **{"|".join(map(str, k)): v[ix] / cal[k] for k, v in best.items()},
             **{"day:" + "|".join(map(str, k)): v[:, ix] / cal[k] for k, v in RUN_PERDAY.items()})
