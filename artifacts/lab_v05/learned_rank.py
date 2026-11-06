"""Learned-only ranking quality (ADP, node level) of the cached 0.3 per-window scores: detector-1, detector-2, the
deployed 2:1 fusion and simple alternative combinations. Node score = max over test windows (PIDSMaker rule).
  learned_rank.py DATASET [DATASET ...]"""
import os, sys
import numpy as np
sys.path.insert(0, "/lab0")
from lab import D, HELD_OUT, adp  # noqa: E402
JOBS = os.environ.get("JOBS", "/lab/jobs.txt")
BUNDLES = {l.split()[0]: l.split()[2].split(",") for l in open(JOBS)}
import csv, os
from collections import defaultdict
from pdp_engine.data import WindowStore

COMBOS = {"d1": lambda r1, r2: r1, "d2": lambda r1, r2: r2, "max": np.maximum}
for w in (0.8, 2 / 3, 0.5, 1 / 3, 0.2):
    COMBOS[f"w1={w:.2f}"] = (lambda w: (lambda r1, r2: w * r1 + (1 - w) * r2))(w)
for ds in sys.argv[1:]:
    assert ds not in HELD_OUT, "held out"
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
        z = np.load(f"/data/lab/{eid}/{b}.npz")
        ids = z["ids"].astype(np.int64)
        n = int(ids.max()) + 1
        for name, f in COMBOS.items():
            v = f(z["r1"].astype(np.float64), z["r2"].astype(np.float64))
            s = np.full(n, -np.inf); np.maximum.at(s, ids, v)
            nodes = np.where(np.isfinite(s))[0]
            uu = [reg[int(i)].uuid for i in nodes]
            lab = np.array([u in all_gt for u in uu]); na = [{k for k, g in gt.items() if u in g} for u in uu]
            out[name].append(adp(s[nodes], lab, na))
    for name, v in out.items():
        print(f"{ds:10s} {name:10s} ADP mean {np.mean(v):.3f} min {np.min(v):.3f} max {np.max(v):.3f}  {[round(x, 2) for x in v]}", flush=True)
