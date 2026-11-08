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
    g = np.full(len(x), 3); g[isproc[x]] = 0; g[isnet[x]] = 1; g[(g == 3) & (r // 2 == WRITE)] = 2
    G = np.zeros((4, n))
    for k in range(4):
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
        U = np.minimum(G / q[:4, None], capu)
        own = np.where(isproc, np.clip(U - flooru, 0, None).sum(0), np.minimum(om / q[4], capu))
    delta = cfg[3] if mode != "max" else 0
    C = own
    if delta > 0:
        ps, cs = d["par"]
        for _ in range(6):
            inh = np.zeros(len(own)); np.maximum.at(inh, cs, C[ps]); C = own + delta * inh
    return C

