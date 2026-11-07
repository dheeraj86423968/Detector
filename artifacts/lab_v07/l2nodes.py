"""Product alert sets with the 0.6 layer defaults re-fitted on the baseline, with and without layer 1 (novelty), for
the 0.5 bundle in jobs05.txt; saved as node masks aligned with the registry. Usage: l2nodes.py DATASET"""
import dataclasses, json, sys, time
from collections import defaultdict
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.layers import EVIDENCE_RULES, DeterministicLayers, LayerConfig, TagParams, fit_layers
from pdp_engine.runtime import AlertPolicy, alert_tier
from common import D, log

ds = sys.argv[1]; eid, days, _ = D[ds]
b = {l.split()[0]: l.split()[2] for l in open("/lab/jobs05.txt")}[eid]
st = WindowStore(f"/data/endpoints/{eid}/eval-test"); reg = st.load_registry()
wins = [w for d in days for w in st.windows(d)]
z = np.load(f"/data/lab/{eid}/{b}.npz"); off = np.concatenate([[0], np.cumsum(z["wlen"])])
man = json.load(open(f"/data/bundles/{eid}/{b}/manifest.json")); nb = man["num_nodes"]
spec0 = json.load(open(f"/data/bundles/{eid}/{b}/layers.json"))
bst = WindowStore(f"/data/endpoints/{eid}/baseline"); breg = bst.load_registry()
out = {}
for name, nov in (("prod06", True), ("prod06_nonovelty", False)):
    cfg = LayerConfig(novelty=nov)                       # 0.6 frozen defaults
    spec = fit_layers(bst, spec0["fit_days"], breg, nb, cfg, log=log)
    L = DeterministicLayers(spec, nb)
    cal = man["calibration"]["fusion"]; pol = man.get("learned_policy") or {}
    corr = float(cal["percentiles"].get(pol.get("corroboration_percentile", "99.9"), cal["threshold"])) / cal["threshold"]
    P = AlertPolicy(None, int(pol.get("daily_budget", 20)), corr, evidence_rules=spec["config"].get("evidence_rules", EVIDENCE_RULES))
    mask = np.zeros(len(reg), bool)
    for k, w in enumerate(wins):
        hits = L.process(w, reg, w.nodes())
        _, reasons, _ = P.apply(w, reg, z["ids"][off[k]:off[k + 1]].astype(np.int64), z["fused"][off[k]:off[k + 1]], hits)
        for n, rs in reasons.items():
            if alert_tier(rs) > 0:
                mask[n] = True
    out[name] = mask
    log(f"{ds} {name}: {mask.sum()} alerted nodes")
np.savez(f"/lab/l2-{ds}.npz", **out)
