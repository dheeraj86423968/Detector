"""Offline chain-evidence experiments on a detector-3 dump (detector-3 only, no fusion): own evidence per process =
sum over activity groups of min(group max, cap) - floor (>=0); chain = own + delta * max(parents' chain), parents =
clone parent and the writer of an executed image. Threshold = budget-th benign validation score."""
import json, sys, itertools
import numpy as np
from common8 import Set
EXE, WRITE, CLONE = 1, 8, 9

def load(D, split):
    z = np.load(f"{D}/{split}.npz")
    return {k: z[k] for k in z.files}

def evidence(z, cap, floor, delta, mode, passes=6):
    p, x, r, s = z["p"], z["x"], z["r"], z["s"]
    isproc, isnet = z["isproc"], z["isnet"]
    n = len(isproc)
    g = np.full(len(x), 3); g[isproc[x]] = 0; g[isnet[x]] = 1; g[(g == 3) & (r // 2 == WRITE)] = 2
    G = np.zeros((4, n))
    for k in range(4):
        m = g == k
        np.maximum.at(G[k], p[m], s[m])
    objmax = np.zeros(n); np.maximum.at(objmax, x, s)
    Gc = np.minimum(G, cap)
    if mode == "max":
        own = G.max(0)
    elif mode == "maxcap":
        own = Gc.max(0)
    else:                                  # sum of capped group maxima above floor
        own = np.clip(Gc - floor, 0, None).sum(0)
    own = np.where(isproc, own, np.minimum(objmax, cap) if mode != "max" else objmax)
    es, ed, et = z["es"], z["ed"], z["et"]
    m = (et == CLONE) & isproc[es] & isproc[ed]
    ps, cs = [es[m]], [ed[m]]
    if "w" in mode:                         # writer of the executed image -> executor
        wm = (et == WRITE) & isproc[es] & ~isproc[ed]
        xm = (et == EXE) & isproc[es] & ~isproc[ed]
        wf = {}
        for a, b in zip(es[wm], ed[wm]):
            wf.setdefault(int(b), set()).add(int(a))
        pp, cc = [], []
        for a, b in zip(es[xm], ed[xm]):
            for q in wf.get(int(b), ()):
                if q != a:
                    pp.append(q); cc.append(int(a))
        ps.append(np.array(pp, np.int64)); cs.append(np.array(cc, np.int64))
    ps, cs = np.concatenate(ps).astype(np.int64), np.concatenate(cs).astype(np.int64)
    C = own.copy()
    if delta > 0 and len(ps):
        for _ in range(passes):
            inh = np.zeros(n); np.maximum.at(inh, cs, C[ps])
            C = own + delta * inh
    return C

name = sys.argv[1]
S = Set(name); D = f"/data/lab08/dump/{name}"
gt = json.load(open(D + "/gt.json"))
v, t = load(D, "val"), load(D, "test")
lab = t["label"]
seen_t = np.zeros(len(lab), bool); seen_t[t["p"]] = True; seen_t[t["x"]] = True
seen_v = np.zeros(len(v["isproc"]), bool); seen_v[v["p"]] = True; seen_v[v["x"]] = True
node_att = {}
for k, ids in gt.items():
    for i in ids:
        node_att.setdefault(i, set()).add(k)
ndays = len(S.test_days)
print(name, "gt nodes seen", int((lab & seen_t).sum()), "attacks", len(gt))
configs = [("max", 0, 0, 0)] + [("maxcap", c, 0, d) for c in (25, 35) for d in (0, 0.7, 1.0)] + \
          [(m, c, f, d) for m in ("sum", "sumw") for c in (20, 25, 35) for f in (3, 6) for d in (0, 0.5, 0.8, 1.0)]
for mode, cap, floor, delta in configs:
    Cv = evidence(v, cap, floor, delta, mode)[seen_v]
    Ct = evidence(t, cap, floor, delta, mode)
    thr = np.sort(Cv)[::-1][10]
    pred = (Ct > thr) & seen_t
    tp = int((pred & lab).sum()); fp = int((pred & ~lab).sum())
    att = set().union(*[node_att.get(int(i), set()) for i in np.where(pred & lab)[0]]) if tp else set()
    # rank-based: attacks within fp budget 10/day
    order = np.argsort(-np.where(seen_t, Ct, -1)); fpb = 0; att10 = set()
    for i in order[: 200000]:
        if lab[i]: att10 |= node_att.get(int(i), set())
        else:
            fpb += 1
            if fpb > 10 * ndays: break
    print(f"{mode:6s} cap {cap:3d} floor {floor} delta {delta:.1f} | thr {thr:7.1f} TP {tp:4d} FP {fp:5d} att {len(att)}/{len(gt)} | top10/day att {len(att10)}")
