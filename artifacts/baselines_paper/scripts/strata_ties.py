"""STRATA 0.10 (P2) triage-order ADP under different tie orders, from anchor13.py's per-node dumps
(/nodes/nodes-<set>.npz: tier, our learned score, label, attacks). Key = tier x 1e6 + score (as res13/adp13)."""
import glob, json, os, sys
import numpy as np
from pdp_server.tools.darpa_eval import adp
out = {}
for f in sorted(glob.glob("/nodes/nodes-*.npz")):
    s = os.path.basename(f)[6:-4]; z = np.load(f)
    key = z["tier"] * 1e6 + z["sc"]; lab = z["label"].astype(bool); na = [set(x.split(";")) if x else set() for x in z["att"]]
    stable = adp(key, lab, na)
    rng = np.random.default_rng(0)
    rnd = [adp(key + 0.0, lab, na) if False else None for _ in range(0)]
    vals = []
    for _ in range(20):          # random order within ties: permute nodes, then stable sort on the key
        p = rng.permutation(len(key))
        vals.append(adp(key[p], lab[p], [na[i] for i in p]))
    worst_p = np.lexsort((lab.astype(int), -key))           # within ties GT last: sort by -key, then label 0 first
    worst = adp(-np.arange(len(key), dtype=float), lab[worst_p], [na[i] for i in worst_p])
    best_p = np.lexsort((-lab.astype(int), -key))
    best = adp(-np.arange(len(key), dtype=float), lab[best_p], [na[i] for i in best_p])
    u, inv, cnt = np.unique(key, return_inverse=True, return_counts=True)
    benign_in = np.bincount(inv, weights=(~lab).astype(float), minlength=len(u)) > 0
    gt_tied = int(np.sum(lab & benign_in[inv]))
    gt_tied_alerted = int(np.sum(lab & benign_in[inv] & (z["tier"] > 0)))
    out[s] = {"nodes": int(len(key)), "gt_nodes": int(lab.sum()), "adp_stable": round(stable, 4),
              "adp_random_mean20": round(float(np.mean(vals)), 4), "adp_random_sd": round(float(np.std(vals)), 4),
              "adp_worst_gt_last": round(worst, 4), "adp_best_gt_first": round(best, 4),
              "gt_in_tie_with_benign": gt_tied, "share_gt_in_tie_with_benign": round(gt_tied / max(1, lab.sum()), 3),
              "of_which_alerted": gt_tied_alerted}
    print(s, out[s], flush=True)
json.dump(out, open("/out/strata_ties.json", "w"), indent=1)
