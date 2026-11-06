"""Detector-2 seed normalisation x aggregation, label-free variants, on the per-seed cache (cache_seeds.py).
Node score = max over test windows; ADP per bundle, mean/min/max.  seeds_rank.py DATASET [...]"""
import csv, os, sys
from collections import defaultdict
import numpy as np
sys.path.insert(0, "/lab0")
from lab import D, BUNDLES, HELD_OUT, adp  # noqa: E402
from pdp_engine.data import WindowStore


def norm(mode, s, v):
    v = v[np.isfinite(v)]
    if mode == "max":
        return s / v.max()
    if mode == "p999":
        return s / np.percentile(v, 99.9)
    if mode == "p99":
        return s / np.percentile(v, 99)
    if mode == "rz":            # robust z-score on the validation node-window scores
        med = np.median(v); mad = np.median(np.abs(v - med)) * 1.4826 + 1e-9
        return (s - med) / mad
    raise ValueError(mode)


AGG = {"mean": lambda a: a.mean(1), "median": lambda a: np.median(a, 1), "trim": lambda a: np.sort(a, 1)[:, 1:-1].mean(1)}
for ds in sys.argv[1:]:
    assert ds not in HELD_OUT
    eid, days, gtf = D[ds]
    gt = defaultdict(set)
    for f in gtf:
        for row in csv.reader(open(os.path.join("/gt", f))):
            if len(row) >= 3 and row[2].strip():
                gt[os.path.basename(f)[5:-4]].add(row[2].strip())
    all_gt = set().union(*gt.values())
    reg = WindowStore(f"/data/endpoints/{eid}/eval-test").load_registry()
    out = defaultdict(list)
    for b in BUNDLES[eid]:
        p = f"/data/lab/{eid}/{b}.seeds.npz"
        if not os.path.exists(p):
            continue
        z = np.load(p)
        ids = z["ids"].astype(np.int64); n = int(ids.max()) + 1
        nodes = None
        for det, S, V in (("d1", z["s1"], z["v1"]), ("d2", z["s2"], z["v2"])):
            S = np.where(np.isfinite(S), S, 0.0);
            for nm in ("max", "p999", "p99", "rz"):
                R = np.stack([norm(nm, S[:, k], V[:, k]) for k in range(S.shape[1])], 1)
                for an, ag in AGG.items():
                    if det == "d1" and an == "trim":
                        continue
                    sc = np.full(n, -np.inf); np.maximum.at(sc, ids, ag(R))
                    if nodes is None:
                        nodes = np.where(np.isfinite(sc))[0]
                        uu = [reg[int(i)].uuid for i in nodes]
                        lab = np.array([u in all_gt for u in uu]); na = [{k for k, g in gt.items() if u in g} for u in uu]
                    out[f"{det} {nm:5s} {an}"].append(adp(sc[nodes], lab, na))
            for k in range(S.shape[1]):
                sc = np.full(n, -np.inf); np.maximum.at(sc, ids, S[:, k])
                out[f"{det} seed{k}"].append(adp(sc[nodes], lab, na))
    for name, v in out.items():
        print(f"{ds:10s} {name:18s} ADP mean {np.mean(v):.3f} min {np.min(v):.3f} max {np.max(v):.3f}  {[round(x, 2) for x in v]}", flush=True)
