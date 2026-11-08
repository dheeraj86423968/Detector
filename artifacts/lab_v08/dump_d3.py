"""Dump detector-3 events (released 0.7 bundle) for a set's validation day and test days: per event process, object,
role-op, score, time, window; plus the window edges needed for process trees (CLONE, EXECUTE, WRITE). For offline
design of chain scoring."""
import json, os, sys, time
import numpy as np
from pdp_engine.behaviour import BehaviourModel, edge_events, event_groups
from common8 import Set, log
name = sys.argv[1]
S = Set(name)
b = (S.work.replace("/lab08/", "/lab07/") + ("/b07l" if "heldout" in S.work else "/v07l"))
bm = BehaviourModel.load(b)
cal = json.load(open(b + "/calibration.json"))
out = f"/data/lab08/dump/{name}"
os.makedirs(out, exist_ok=True)
json.dump({"bundle": b, "cal": cal, "val_day": S.val_day, "test_days": S.test_days}, open(out + "/meta.json", "w"))
for split, st, days in (("val", S.base_store(), [S.val_day]), ("test", S.eval_store(), S.test_days)):
    reg = st.load_registry(); K = bm.keys(reg)
    P, X, R, SC, T, W = [], [], [], [], [], []
    ES, ED, ET, ETT = [], [], [], []
    wi = 0
    t0 = time.time()
    for d in days:
        for w in st.windows(d):
            p, x, e, s = bm.edge_scores(w, K)
            r = edge_events(w, K)[2]
            P.append(p.astype(np.int32)); X.append(x.astype(np.int32)); R.append(r.astype(np.int8)); SC.append(s.astype(np.float32))
            T.append(w.t[e].astype(np.int64)); W.append(np.full(len(p), wi, np.int32))
            m = np.isin(w.etype, [1, 8, 9])
            ES.append(w.src[m].astype(np.int32)); ED.append(w.dst[m].astype(np.int32)); ET.append(w.etype[m].astype(np.int8)); ETT.append(w.t[m].astype(np.int64))
            wi += 1
    K.grow()
    n = len(reg)
    uu = np.array([e.uuid for e in reg.entities[:n]]) if split == "test" else None
    lab = np.array([u in S.allgt for u in uu]) if split == "test" else np.zeros(n, bool)
    att = {k: [i for i, u in enumerate(uu) if u in v] for k, v in S.gt.items()} if split == "test" else {}
    np.savez(f"{out}/{split}.npz", p=np.concatenate(P), x=np.concatenate(X), r=np.concatenate(R), s=np.concatenate(SC),
             t=np.concatenate(T), w=np.concatenate(W), es=np.concatenate(ES), ed=np.concatenate(ED), et=np.concatenate(ET),
             ett=np.concatenate(ETT), isproc=K.isproc[:n], isnet=K.isnet[:n], label=lab)
    if att:
        json.dump(att, open(f"{out}/gt.json", "w"))
    log(f"{name} {split}: {wi} windows, {sum(len(a) for a in P)} events, {time.time()-t0:.0f}s")
