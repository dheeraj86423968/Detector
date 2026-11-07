"""Anatomy of BL scores on a dev set: GT nodes' scores and the top false positives (labels shown)."""
import sys, numpy as np
from pdp_engine.data import WindowStore
from common import D
z = np.load(sys.argv[2]); eid = D[sys.argv[1]][0]
reg = WindowStore(f"/data/endpoints/{eid}/eval-test").load_registry()
ix, raw, lab = z["ix"], z["raw"], z["labels"]
o = np.argsort(-raw)
print("score distribution of GT nodes:", np.round(np.sort(raw[lab])[::-1], 1).tolist())
print("rank of GT nodes (first 30):", np.where(lab[o])[0][:30].tolist())
print("== top 40")
for j in o[:40]:
    print(int(lab[j]), round(float(raw[j]), 1), reg.entities[int(ix[j])].label[:140])
print("== GT nodes")
for j in np.where(lab)[0][:40]:
    print(round(float(raw[j]), 1), reg.entities[int(ix[j])].label[:140])
