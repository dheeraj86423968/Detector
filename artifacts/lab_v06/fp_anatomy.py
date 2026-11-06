"""Development sets only: which (rule, key) produce the false-positive alerts of the frozen 0.4 layers (one bundle)."""
import csv, json, os, sys
from collections import Counter, defaultdict
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.layers import DeterministicLayers, LayerConfig, fit_layers, EVIDENCE_RULES
sys.path.insert(0, "/lab"); from lab import D, BUNDLES
ds = sys.argv[1]; assert ds in ("CADETS_E3", "THEIA_E3", "OPTC_H201"), "development sets only"
extra = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
eid, days, gtf = D[ds]
gt = set()
for f in gtf:
    for row in csv.reader(open(os.path.join("/gt", f))):
        if len(row) >= 3 and row[2].strip(): gt.add(row[2].strip())
b = BUNDLES[eid][0]
spec0 = json.load(open(f"/data/bundles/{eid}/{b}/layers.json")); nb = json.load(open(f"/data/bundles/{eid}/{b}/manifest.json"))["num_nodes"]
bst = WindowStore(f"/data/endpoints/{eid}/baseline")
cfg = LayerConfig(**extra)
spec = fit_layers(bst, spec0["fit_days"], bst.load_registry(), nb, cfg, log=lambda m: None)
st = WindowStore(f"/data/endpoints/{eid}/eval-test"); reg = st.load_registry()
L = DeterministicLayers(spec, nb)
fp = Counter(); tp = Counter(); ex = {}
for d in days:
    for w in st.windows(d):
        for h in L.process(w, reg, w.nodes()):
            if h.rule in EVIDENCE_RULES or h.rule == "novel_executable_repeat":
                continue
            for n in h.nodes:
                u = reg.entities[n].uuid
                k = (h.rule, h.key)
                (tp if u in gt else fp)[k] += 1
                ex.setdefault(k, h.detail[:160])
print(f"== {ds}: FP alerts by (rule, key) - top 25 (TP count alongside)")
for k, c in fp.most_common(25):
    print(f"{c:5d} FP {tp.get(k,0):4d} TP  {k[0]:24s} {k[1][:70]:70s} | {ex[k][:110]}")
print("rules FP total", sum(fp.values()), "TP total", sum(tp.values()))
