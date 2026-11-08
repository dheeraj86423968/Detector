"""Per-process anatomy from a detector-3 dump: max score per activity group, parent chain; ground-truth processes vs
the most unusual benign processes of the validation day."""
import json, sys
import numpy as np
from common8 import Set
name = sys.argv[1]; top = int(sys.argv[2]) if len(sys.argv) > 2 else 15
S = Set(name); D = f"/data/lab08/dump/{name}"
meta = json.load(open(D + "/meta.json")); thr = meta["cal"]["detector-3"]
print("thresholds", thr)
GN = ["proc", "net", "fwrite", "fread"]
def prof(split):
    z = np.load(f"{D}/{split}.npz")
    p, x, r, s = z["p"], z["x"], z["r"], z["s"]
    isproc, isnet = z["isproc"], z["isnet"]
    n = len(isproc)
    g = np.full(len(x), 3); g[isproc[x]] = 0; g[isnet[x]] = 1; g[(g == 3) & (r // 2 == 8)] = 2
    G = np.zeros((4, n))
    for k in range(4):
        m = g == k
        np.maximum.at(G[k], p[m], s[m])
    objmax = np.zeros(n); np.maximum.at(objmax, x, s)
    par = {}
    es, ed, et = z["es"], z["ed"], z["et"]
    m = (et == 9) & isproc[es] & isproc[ed]
    for a, b in zip(es[m], ed[m]):
        par.setdefault(int(b), int(a))
    return z, G, objmax, par
reg_t = S.eval_store().load_registry(); reg_v = S.base_store().load_registry()
zt, Gt, Ot, part = prof("test"); zv, Gv, Ov, parv = prof("val")
def row(G, par, reg, i, tag=""):
    lab = reg.entities[i].label[:80]
    a = G[:, i]
    pp = par.get(i); pl = reg.entities[pp].label[:40] if pp is not None else "-"
    pr = G[:, pp].max() if pp is not None else 0
    return f"{tag:3s} max {a.max():6.1f} | " + " ".join(f"{GN[k]} {a[k]:5.1f}" for k in range(4)) + f" | par {pr:5.1f} {pl:40s} | {lab}"
print("== ground-truth processes (test)")
lab = zt["label"]; isp = zt["isproc"]
gt = np.where(lab & isp)[0]
for i in gt[np.argsort(-Gt[:, gt].max(0))]:
    print(row(Gt, part, reg_t, i, "GT"))
print("== ground-truth non-processes: max as object", np.round(np.sort(Ot[np.where(lab & ~isp)[0]])[::-1][:20], 1))
print(f"== top {top} benign processes by max (validation day)")
vp = np.where(zv["isproc"])[0]
for i in vp[np.argsort(-Gv[:, vp].max(0))][:top]:
    print(row(Gv, parv, reg_v, i, "VAL"))
print(f"== top {top} benign processes by max (test days)")
tp_ = np.where(isp & ~lab)[0]
for i in tp_[np.argsort(-Gt[:, tp_].max(0))][:top]:
    print(row(Gt, part, reg_t, i, "TST"))
# breadth
for split, G, isp_, lab_ in (("val", Gv, zv["isproc"], np.zeros(len(zv["isproc"]), bool)), ("test", Gt, isp, lab)):
    pr = np.where(isp_)[0]
    for tau in (5, 10, 20):
        b = (G[:, pr] > tau).sum(0)
        print(split, "tau", tau, "breadth hist", np.bincount(b, minlength=5), "GT:", np.bincount(b[lab_[pr]], minlength=5) if lab_.any() else "")
