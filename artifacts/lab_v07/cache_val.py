"""Stage A: score every test-day window of a benchmark endpoint with one bundle (learned detectors only) and cache
per-window node ids + fused / r1 / r2 to /data/lab/<eid>/<bid>.npz (layers and policy are re-run on CPU later)."""
import json, os, sys, time
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.runtime import Runtime
eid, days, bids = sys.argv[1], sys.argv[2].split(","), sys.argv[3].split(",")
st = WindowStore(f"/data/endpoints/{eid}/baseline")
os.makedirs(f"/data/lab/{eid}", exist_ok=True)
for bid in bids:
    out = f"/data/lab/{eid}/{bid}.val.npz"
    if os.path.exists(out):
        print("have", out, flush=True); continue
    t0 = time.time()
    reg = st.load_registry()
    rt = Runtime(f"/data/bundles/{eid}/{bid}", reg, device="cuda", feat_device="cuda", layers=False)
    ids, fu, r1, r2, wstart, wlen = [], [], [], [], [], []
    for d in days:
        for w in st.windows(d):
            r = rt.score(w)
            ids.append(r.node_ids.astype(np.int32)); fu.append(r.fused.astype(np.float32))
            r1.append(r.r1.astype(np.float32)); r2.append(r.r2.astype(np.float32))
            wstart.append(w.start_ns); wlen.append(len(r.node_ids))
    np.savez(out + ".tmp.npz", ids=np.concatenate(ids), fused=np.concatenate(fu), r1=np.concatenate(r1), r2=np.concatenate(r2),
             wstart=np.array(wstart, dtype=np.int64), wlen=np.array(wlen, dtype=np.int64))
    os.replace(out + ".tmp.npz", out)
    print(f"{eid[:8]} {bid[:8]}: {len(wstart)} windows, {sum(wlen)} node-windows, {time.time()-t0:.0f}s", flush=True)
    del rt, reg
    import torch; torch.cuda.empty_cache()
