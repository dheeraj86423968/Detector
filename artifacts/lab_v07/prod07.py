"""End-to-end check of the 0.7 product path on a dataset: upgrade the 0.5 bundle with pdp_engine.trainer.upgrade_bundle_07
(the code the server runs), then score the test days with pdp_engine.runtime.Runtime (layers on), and report the
product alerts. Usage: prod07.py DATASET [--name v07]"""
import argparse, json, os, time
from collections import Counter
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.runtime import Runtime
from pdp_engine.trainer import upgrade_bundle_07, TrainConfig
from common import D, BUNDLES, log, load_gt, at

ap = argparse.ArgumentParser(); ap.add_argument("dataset"); ap.add_argument("--name", default="v07")
ap.add_argument("--no-prop", action="store_true"); ap.add_argument("--budget", type=int, default=10)
ap.add_argument("--daily", type=int, default=20); ap.add_argument("--corr", type=float, default=None); ap.add_argument("--tag", default=""); ap.add_argument("--grouped", action="store_true"); ap.add_argument("--nov-ev", type=int, default=0); ap.add_argument("--novelty-alert", action="store_true")
a = ap.parse_args()
eid, days, gtf = D[a.dataset]
src = f"/data/bundles/{eid}/{BUNDLES[eid][0]}"
out = f"/data/lab07/{eid}/{a.name}"
cfg = TrainConfig(device="cuda", propagation=not a.no_prop, calibration_budget=a.budget, learned_daily_budget=a.daily, d3_grouped=a.grouped, novelty_as_evidence=bool(a.nov_ev) and not a.novelty_alert, layer_novelty=bool(a.nov_ev) or a.novelty_alert)
base = WindowStore(f"/data/endpoints/{eid}/baseline")
t0 = time.time()
if not os.path.exists(out):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    upgrade_bundle_07(src, out, base, cfg)
log(f"upgrade {time.time()-t0:.0f}s; calibration final {json.load(open(out + '/calibration.json'))['final']}")
st = WindowStore(f"/data/endpoints/{eid}/eval-test"); reg = st.load_registry()
rt = Runtime(out, reg, device="cuda", feat_device="cuda")
log(f"corroboration threshold {rt.corroboration:.3f}")
if a.corr is not None:
    rt.corroboration = a.corr; rt.policy.corroboration = a.corr
alerted = {}; by_layer = Counter(); learned_max = np.full(len(reg) + 10_000_000, -np.inf)
for d in days:
    for w in st.windows(d):
        r = rt.score(w)
        np.maximum.at(learned_max, r.node_ids, r.fused)
        for n in r.alerts.tolist():
            if n not in alerted:
                alerted[n] = r.layer_of(n); by_layer[alerted[n]] += 1
log(f"scored {time.time()-t0:.0f}s, alerts {len(alerted)} by layer {dict(by_layer)}")
gt = load_gt(gtf); allgt = set().union(*gt.values())
seen = np.zeros(len(reg), bool)
for d in days:
    for w in st.windows(d):
        seen[w.src] = True; seen[w.dst] = True
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in allgt for u in uu]); na = [{k for k, v in gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
pred = np.zeros(len(ix), bool)
layer_of = {}
for n, l in alerted.items():
    if n in pos:
        pred[pos[n]] = True; layer_of[pos[n]] = l
res = {"product": at(pred, labels, na), "n_attacks": len(gt), "gt_nodes": int(labels.sum()), "days": len(days)}
res["product"]["FP/day"] = round(res["product"]["FP"] / len(days), 1)
for l in set(layer_of.values()):
    m = np.array([layer_of.get(j) == l for j in range(len(ix))])
    res[f"layer:{l}"] = at(m, labels, na)
print(json.dumps(res, indent=1))
json.dump(res, open(f"/lab/prod07-{a.name}{a.tag}-{a.dataset}.json", "w"), indent=1)
