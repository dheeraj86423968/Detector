"""FP anatomy of breadth scoring (cap, floor) on a set: group profile of the top false positives and of the
validation nodes that set the threshold."""
import json, sys
import numpy as np
from collections import Counter
from common8 import Set
from c8lib import prep
name, cap, floor = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
S = Set(name); D = f"/data/lab08/dump/{name}"
v, t = prep(np.load(D + "/val.npz")), prep(np.load(D + "/test.npz"))
def sc(d):
    return np.where(d["isproc"], np.clip(np.minimum(d["G"], cap) - floor, 0, None).sum(0), np.minimum(d["om"], cap))
Cv, Ct = sc(v), sc(t)
thr = np.sort(Cv[v["seen"]])[::-1][10]
regt = S.eval_store().load_registry(); regv = S.base_store().load_registry()
print("thr", thr)
GN = ["proc", "net", "fwr", "frd"]
def show(d, C, reg, idx, tag):
    for i in idx:
        g = d["G"][:, i] if d["isproc"][i] else None
        prof = " ".join(f"{GN[k]} {g[k]:5.1f}" for k in range(4)) if g is not None else f"obj {d['om'][i]:5.1f}".ljust(39)
        print(f"{tag} {C[i]:5.1f} | {prof} | {reg.entities[i].label[:110]}")
fp = np.where((Ct > thr) & t["seen"] & ~t["label"])[0]
print("FP", len(fp), "procs", int(t["isproc"][fp].sum()))
kinds = Counter(); 
for i in fp:
    if t["isproc"][i]:
        kinds[tuple(GN[k] for k in range(4) if t["G"][k, i] > floor)] += 1
    else:
        kinds["object"] += 1
print(kinds.most_common(10))
progs = Counter(regt.entities[i].label.split(" ")[1][:60] for i in fp if t["isproc"][i])
print(progs.most_common(15))
show(t, Ct, regt, fp[np.argsort(-Ct[fp])][:25], "FP ")
vv = np.where(v["seen"])[0]
show(v, Cv, regv, vv[np.argsort(-Cv[vv])][:12], "VAL")
