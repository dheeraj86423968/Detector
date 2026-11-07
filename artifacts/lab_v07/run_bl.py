"""Fit detector-3 prototype on a dev endpoint's train days, calibrate on the val day, score the test days; compare
with the cached learned fused scores (bundle 0). Usage: run_bl.py DATASET [--out f.json]"""
import argparse, json, sys, time
import numpy as np
from pdp_engine.data import WindowStore
from common import D, BUNDLES, log, load_gt, bundle_split, report
import bl

ap = argparse.ArgumentParser(); ap.add_argument("dataset"); ap.add_argument("--out"); ap.add_argument("--save"); ap.add_argument("--mode", default="none")
a = ap.parse_args()
eid, test_days, gtf = D[a.dataset]
train_days, val_day = bundle_split(eid)
voc = bl.Vocab()
base = WindowStore(f"/data/endpoints/{eid}/baseline")
breg = base.load_registry(); KB = bl.Keyed(voc, breg)
log(f"{a.dataset}: baseline registry {len(breg)}; train {train_days} val {val_day}")
m = bl.BL(); t0 = time.time(); ne = 0
for d in train_days:
    for w in base.windows(d):
        m.fit_window(w, KB); ne += w.num_edges
m.finish(); log(f"fit {ne} edges {time.time()-t0:.0f}s; vocab {len(voc.ix)}")


def score_store(st, days, K, n):
    proc_max = np.full(n, -np.inf); proc_top = np.zeros((n, 3)); seen = np.zeros(n, bool)
    for d in days:
        for w in st.windows(d):
            p, x, r, _, s = bl.instance_scores(m, K, w, a.mode)
            np.maximum.at(proc_max, p, s); np.maximum.at(proc_max, x, s)
            seen[w.src] = True; seen[w.dst] = True
            # top-3 distinct-event mean for processes: keep the 3 largest per process
            o = np.lexsort((-s, p)); ps, ss = p[o], s[o]
            first = np.r_[True, ps[1:] != ps[:-1]]
            rank = np.arange(len(ps)) - np.maximum.accumulate(np.where(first, np.arange(len(ps)), 0))
            for j in range(3):
                mm = rank == j
                cur = proc_top[ps[mm], 2]
                # insert ss into sorted top list if larger
                np.maximum.at(proc_top[:, 2], ps[mm], ss[mm])
                proc_top.sort(axis=1)  # ascending
                proc_top[:] = proc_top[:, ::-1]
    return proc_max, proc_top, seen

vreg = breg
pv, tv, sv = score_store(base, [val_day], KB, len(breg))
isp = KB.isproc
thr = {}
for nm, msk in (("proc", isp), ("obj", ~isp)):
    v = pv[sv & msk]; v = v[np.isfinite(v)]
    thr[nm] = {"max": float(v.max()), "99.99": float(np.percentile(v, 99.99)), "99.9": float(np.percentile(v, 99.9)), "n": int(len(v))}
log(f"val thresholds {thr}")

st = WindowStore(f"/data/endpoints/{eid}/eval-test")
reg = st.load_registry(); K = bl.Keyed(voc, reg)
pt, tt, s_t = score_store(st, test_days, K, len(reg))
ix = np.where(s_t)[0]
gt = load_gt(gtf); allgt = set().union(*gt.values())
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in allgt for u in uu]); node_att = [{k for k, v in gt.items() if u in v} for u in uu]
nd = len(test_days)
res = {}
raw = pt[ix]; raw[~np.isfinite(raw)] = 0
# per-type ratio to the validation max
ratio = np.where(K.isproc[ix], raw / thr["proc"]["max"], raw / thr["obj"]["max"])
tmax = {"max": 1.0}
res["bl_raw"] = report("bl_raw", raw, labels, node_att, len(gt), nd)
res["bl_ratio"] = report("bl_ratio", ratio, labels, node_att, len(gt), nd, {"valmax": 1.0 + 1e-6})
p99 = np.where(K.isproc[ix], raw / thr["proc"]["99.99"], raw / thr["obj"]["99.99"])
res["bl_ratio9999"] = report("bl_ratio9999", p99, labels, node_att, len(gt), nd, {"p99.99": 1.0})
# cached learned (bundle 0): node max over windows of fused
z = np.load(f"/data/lab/{eid}/{BUNDLES[eid][0]}.npz")
fused = np.full(len(reg), -np.inf, np.float32); np.maximum.at(fused, z["ids"], z["fused"])
f = fused[ix]; f[~np.isfinite(f)] = 0
res["learned_fused"] = report("learned_fused", f, labels, node_att, len(gt), nd, {"valmax": 1.0 + 1e-4})
comb = np.maximum(ratio, f)
res["max(bl,learned)"] = report("comb", comb, labels, node_att, len(gt), nd, {"valmax": 1.0 + 1e-4})
res["_meta"] = {"test_nodes": int(len(ix)), "gt_nodes": int(labels.sum()), "thr": thr}
print(json.dumps(res, indent=1))
if a.out:
    json.dump(res, open(a.out, "w"), indent=1)
if a.save:
    np.savez(a.save, ix=ix, raw=raw, labels=labels, fused=f, isproc=K.isproc[ix])
