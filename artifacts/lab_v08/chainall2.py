"""Offline breadth / chain evidence over all dumped sets (detector-3 only). Per config and set: threshold = 11th
largest benign validation node score; attacks found and false positives per test day at that threshold."""
import json, sys
import numpy as np
from common8 import Set, ALL
WRITE, CLONE = 8, 9

def prep(z):
    p, x, r, s = z["p"], z["x"], z["r"], z["s"]
    isproc, isnet = z["isproc"], z["isnet"]
    n = len(isproc)
    NG = int(__import__("os").environ.get("NG", "4"))
    g = np.full(len(x), 3); g[isproc[x]] = 0; g[isnet[x]] = 1; g[(g == 3) & (r // 2 == WRITE)] = 2
    if NG == 6:
        g[isproc[x] & (r % 2 == 1)] = 4          # the child's view: who started me
        g[(g == 3) & (r // 2 == 1)] = 5          # executes a file
    G = np.zeros((NG, n))
    for k in range(NG):
        m = g == k
        np.maximum.at(G[k], p[m], s[m])
    om = np.zeros(n); np.maximum.at(om, x, s)
    seen = np.zeros(n, bool); seen[p] = True; seen[x] = True
    es, ed, et = z["es"], z["ed"], z["et"]
    m = (et == CLONE) & isproc[es] & isproc[ed]
    return dict(G=G, om=om, seen=seen, isproc=isproc, par=(es[m].astype(np.int64), ed[m].astype(np.int64)), label=z["label"])

def score(d, cfg, q=None):
    mode = cfg[0]; G, om, isproc = d["G"], d["om"], d["isproc"]
    if mode == "max":
        own = np.where(isproc, G.max(0), om)
    elif mode == "abs":
        _, cap, floor, delta = cfg
        own = np.where(isproc, np.clip(np.minimum(G, cap) - floor, 0, None).sum(0), np.minimum(om, cap))
    else:   # "q": per-group scale from the validation day
        _, capu, flooru, delta = cfg
        U = np.minimum(G / q[:4, None], capu) if len(G) == 4 else G
        own = np.where(isproc, np.clip(U - flooru, 0, None).sum(0), np.minimum(om / q[4], capu))
    delta = cfg[3] if mode != "max" else 0
    C = own
    if delta > 0:
        ps, cs = d["par"]
        for _ in range(6):
            inh = np.zeros(len(own)); np.maximum.at(inh, cs, C[ps]); C = own + delta * inh
    return C

QRANK = int(sys.argv[1]) if len(sys.argv) > 1 else 100
sets = sys.argv[2].split(",") if len(sys.argv) > 2 else ALL
configs = [("max",)] + [("abs", c, f, 0) for c in (8, 10, 12, 15) for f in (1, 2, 3, 4)]
res = {str(c): {} for c in configs}
for name in sets:
    D = f"/data/lab08/dump/{name}"
    try:
        gt = json.load(open(D + "/gt.json"))
    except FileNotFoundError:
        continue
    S = Set(name); ndays = len(S.test_days)
    v, t = prep(np.load(D + "/val.npz")), prep(np.load(D + "/test.npz"))
    vp = v["seen"] & v["isproc"]; vo = v["seen"] & ~v["isproc"]
    q = np.array([max(np.sort(v["G"][k][vp])[::-1][min(QRANK, vp.sum() - 1)], 1.0) for k in range(len(v["G"]))] +
                 [max(np.sort(v["om"][vo])[::-1][min(QRANK, vo.sum() - 1)], 1.0)])
    na = {}
    for k, ids in gt.items():
        for i in ids: na.setdefault(i, set()).add(k)
    lab = t["label"] & t["seen"]
    for c in configs:
        Cv = score(v, c, q)[v["seen"]]; Ct = score(t, c, q)
        thr = np.sort(Cv)[::-1][min(10, len(Cv) - 1)]
        pred = (Ct > thr) & t["seen"]
        tp = int((pred & lab).sum()); fp = int((pred & ~lab).sum())
        att = set()
        for i in np.where(pred & lab)[0]: att |= na.get(int(i), set())
        res[str(c)][name] = (len(att), len(gt), tp, round(fp / ndays, 1))
    print(name, "q", np.round(q, 1), file=sys.stderr, flush=True)
names = [n for n in sets if n in next(iter(res.values()))]
print("config".ljust(26), " ".join(n[:10].rjust(16) for n in names), "| att  FP/day(mean)")
for c, r in res.items():
    tot = sum(r[n][0] for n in names); tg = sum(r[n][1] for n in names); fpd = np.mean([r[n][3] for n in names])
    print(c.ljust(26), " ".join(f"{r[n][0]}/{r[n][1]} {r[n][2]:3d} {r[n][3]:6.1f}".rjust(16) for n in names), f"| {tot}/{tg} {fpd:6.1f}")
