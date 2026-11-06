"""Per-seed learned scores (raw node scores, not ratios) of the published 0.3 bundles on the test days, plus the same
on the validation day (for label-free calibration experiments). /data/lab/<eid>/<bid>.seeds.npz
  cache_seeds.py <eid> <test days,> <bid,bid,...>"""
import os, sys, time
import numpy as np
import torch
from pdp_engine.data import WindowStore
from pdp_engine.models import TGNState, load_tgn_state, make_tgn_batch, window_degrees
from pdp_engine.runtime import Runtime
from pdp_engine.scoring import node_scores
from pdp_engine.windows import batches

eid, days, bids = sys.argv[1], sys.argv[2].split(","), sys.argv[3].split(",")


def run(rt, store, dlist, state):
    reg = store.load_registry(); n = len(reg)
    ids_all, s1_all, s2_all = [], [], []
    for d in dlist:
        for w in store.windows(d):
            src, dst, et = (torch.from_numpy(a).to(rt.dev) for a in (w.src, w.dst, w.etype))
            x = rt.x
            if rt.deg1:
                dgs, dgd = window_degrees(src, dst, et)
            l1 = []
            for v in rt.velox:
                parts = []
                for a, b in batches(w):
                    xs, xd = x[src[a:b]], x[dst[a:b]]
                    if rt.deg1:
                        xs, xd = torch.cat([xs, dgs[a:b]], 1), torch.cat([xd, dgd[a:b]], 1)
                    parts.append(v.losses(xs, xd, et[a:b]))
                l1.append(torch.cat(parts).cpu().numpy())
            l2 = [[] for _ in rt.orthrus]
            for a, b in batches(w):
                tb = make_tgn_batch(src[a:b], dst[a:b], x, state)
                for k, m in enumerate(rt.orthrus):
                    l2[k].append(m.losses(tb, et[a:b]).cpu().numpy())
                state.insert(src[a:b], dst[a:b], et[a:b])
            ids = w.nodes()
            ids_all.append(ids.astype(np.int32))
            s1_all.append(np.stack([node_scores(n, w.src, w.dst, l)[ids] for l in l1], 1))
            s2_all.append(np.stack([node_scores(n, w.src, w.dst, np.concatenate(l))[ids] for l in l2], 1))
    return np.concatenate(ids_all), np.concatenate(s1_all), np.concatenate(s2_all)


test = WindowStore(f"/data/endpoints/{eid}/eval-test")
base = WindowStore(f"/data/endpoints/{eid}/baseline")
for bid in bids:
    out = f"/data/lab/{eid}/{bid}.seeds.npz"
    if os.path.exists(out):
        print("have", out, flush=True); continue
    t0 = time.time()
    bdir = f"/data/bundles/{eid}/{bid}"
    import json
    man = json.load(open(f"{bdir}/manifest.json"))
    with torch.no_grad():
        rt = Runtime(bdir, test.load_registry(), device="cuda", feat_device="cuda", layers=False)
        tids, t1, t2 = run(rt, test, days, rt.state)
        # validation day, from the TGN state at the start of the validation day
        rtv = Runtime(bdir, base.load_registry(), device="cuda", feat_device="cuda", layers=False)
        rtv.reset(at="validation")
        assert rtv.has_validation_state
        vids, v1, v2 = run(rtv, base, [man["val_day"]], rtv.state)
    np.savez(out + ".tmp.npz", ids=tids, s1=t1, s2=t2, vids=vids, v1=v1, v2=v2,
             thr1=np.array([c.threshold for c in rt.cal1]), thr2=np.array([c.threshold for c in rt.cal2]))
    os.replace(out + ".tmp.npz", out)
    print(f"{eid[:8]} {bid[:8]}: {len(tids)} test node-windows, {len(vids)} val, {time.time()-t0:.0f}s", flush=True)
    del rt, rtv; torch.cuda.empty_cache()
