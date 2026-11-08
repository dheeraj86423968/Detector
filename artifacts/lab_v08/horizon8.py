"""Breadth evidence within a time horizon (H windows of 15 min; 0 = whole period) vs cumulative."""
import json, sys
import numpy as np
from common8 import Set, ALL
WRITE = 8
def prepH(z, H):
    p, x, r, s, w = z["p"], z["x"], z["r"], z["s"], z["w"]
    isproc, isnet = z["isproc"], z["isnet"]
    n = len(isproc)
    g = np.full(len(x), 3); g[isproc[x]] = 0; g[isnet[x]] = 1; g[(g == 3) & (r // 2 == WRITE)] = 2
    b = (w // H) if H > 0 else np.zeros(len(w), np.int64)
    key = b.astype(np.int64) * n + p
    u, inv = np.unique(key, return_inverse=True)
    G = np.zeros((4, len(u)))
    for k in range(4):
        m = g == k
        np.maximum.at(G[k], inv[m], s[m])
    om = np.zeros(n); np.maximum.at(om, x, s)
    seen = np.zeros(n, bool); seen[p] = True; seen[x] = True
    return dict(G=G, node=(u % n), om=om, seen=seen, isproc=isproc, label=z["label"], n=n)
def score(d, cap, floor):
    per = np.clip(np.minimum(d["G"], cap) - floor, 0, None).sum(0)
    C = np.where(d["isproc"], 0.0, np.minimum(d["om"], cap))
    np.maximum.at(C, d["node"], per)
    return C
sets = ALL
cfgs = [(H, c, f) for H in (1, 4, 16, 0) for c in (10, 12, 15) for f in (3, 4)]
res = {c: {} for c in cfgs}
for name in sets:
    D = f"/data/lab08/dump/{name}"; gt = json.load(open(D + "/gt.json")); S = Set(name); nd = len(S.test_days)
    zv, zt = np.load(D + "/val.npz"), np.load(D + "/test.npz")
    na = {}
    for k, ids in gt.items():
        for i in ids: na.setdefault(i, set()).add(k)
    for H in (1, 4, 16, 0):
        v, t = prepH(zv, H), prepH(zt, H)
        lab = t["label"] & t["seen"]
        for c in [c for c in cfgs if c[0] == H]:
            Cv, Ct = score(v, c[1], c[2])[v["seen"]], score(t, c[1], c[2])
            thr = np.sort(Cv)[::-1][min(10, len(Cv) - 1)]
            pred = (Ct > thr) & t["seen"]
            att = set()
            for i in np.where(pred & lab)[0]: att |= na.get(int(i), set())
            res[c][name] = (len(att), len(gt), int((pred & lab).sum()), round(int((pred & ~lab).sum()) / nd, 1))
    print(name, file=sys.stderr, flush=True)
print("H c f".ljust(12), " ".join(n[:10].rjust(15) for n in sets), "| att FP/day")
for c, r in res.items():
    print(str(c).ljust(12), " ".join(f"{r[n][0]}/{r[n][1]} {r[n][2]:3d} {r[n][3]:5.1f}".rjust(15) for n in sets),
          f"| {sum(r[n][0] for n in sets)}/{sum(r[n][1] for n in sets)} {np.mean([r[n][3] for n in sets]):6.1f}")
