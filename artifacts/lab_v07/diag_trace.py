"""Post-hoc diagnosis (TRACE is seen from now on): detector-3 and fused scores of the ground-truth nodes vs the
thresholds, and how many validation / test nodes sit at the score ceiling."""
import csv, json, os, numpy as np
from collections import Counter
from pdp_engine.data import WindowStore
from pdp_engine.runtime import Runtime
H = "/data/heldout/TRACE_E3/trace"; B7 = "/data/lab07/heldout/TRACE_E3/trace/b07"
man = json.load(open(H + "/manifest.json"))
gt = {}
for n, g in man["ground_truth"].items():
    gt[n] = {r[2].strip() for r in csv.reader(open("/gt/" + g["csv"])) if len(r) >= 3 and r[2].strip()}
st = WindowStore(H + "/eval-test"); reg = st.load_registry()
rt = Runtime(B7, reg, device="cuda", feat_device="cuda")
cal = json.load(open(B7 + "/calibration.json")); print("detector-3", cal["detector-3"], "final", cal["final"]["threshold"])
gtid = {reg.get(u): n for n, us in gt.items() for u in us if reg.get(u) is not None}
own_max = {}; fused_max = {}; allr3 = []
for d in man["test_days"]:
    for w in st.windows(d):
        r = rt.score(w)
        for i, n in enumerate(r.node_ids.tolist()):
            if n in gtid:
                own_max[n] = max(own_max.get(n, 0), float(r.r3[i])); fused_max[n] = max(fused_max.get(n, 0), float(r.fused[i]))
        allr3.append(r.r3)
a = np.concatenate(allr3)
print("test r3 quantiles", np.percentile(a, [99, 99.9, 99.99, 100]).round(3), "nodes >= 0.999:", int((a >= 0.999).sum()))
for n, att in sorted(gtid.items(), key=lambda x: -own_max.get(x[0], 0))[:36]:
    print(att[:22], round(own_max.get(n, -1), 3), round(fused_max.get(n, -1), 3), reg.entities[n].label[:90])
