"""End to end on one set: upgrade the set's source bundle (0.5 / 0.6-configured) with the product trainer
(upgrade_bundle_07 = what the server runs; TrainConfig defaults + overrides), then score the test days with
pdp_engine.runtime.Runtime (layers on, streaming) and report product alerts against the ground truth.
Usage: prod08.py SET --name v08 [--cfg key=value ...]"""
import argparse, json, os, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from pdp_engine.trainer import upgrade_bundle_07, TrainConfig
from common8 import Set, log, at

ap = argparse.ArgumentParser(); ap.add_argument("set"); ap.add_argument("--name", default="v08")
ap.add_argument("--cfg", nargs="*", default=[]); ap.add_argument("--heldout-root", default="/data/heldout")
ap.add_argument("--out", default=None)
a = ap.parse_args()
S = Set(a.set, a.heldout_root)
over = {}
for kv in a.cfg:
    k, v = kv.split("=", 1)
    t = type(getattr(TrainConfig(), k))
    over[k] = (v.lower() in ("1", "true", "yes")) if t is bool else t(v)
cfg = TrainConfig(**{**TrainConfig(device="cuda").__dict__, **over})
out = f"{S.work}/{a.name}"
t0 = time.time()
if not os.path.exists(out + "/manifest.json"):
    if os.path.exists(out):
        import shutil; shutil.rmtree(out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    upgrade_bundle_07(S.src, out, S.base_store(), cfg)
cal = json.load(open(out + "/calibration.json"))
log(f"upgrade {time.time()-t0:.0f}s; d3 {cal['detector-3']}; final {cal['final']['threshold']:.3f}")
st = S.eval_store(); reg = st.load_registry()
rt = Runtime(out, reg, device="cuda", feat_device="cuda")
alerted = {}; by_layer = Counter(); seen = np.zeros(0, bool)
for d in S.test_days:
    for w in st.windows(d):
        r = rt.score(w)
        for n in r.alerts.tolist():
            if n not in alerted:
                alerted[n] = r.layer_of(n); by_layer[alerted[n]] += 1
        if len(seen) < len(reg):
            seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
log(f"scored {time.time()-t0:.0f}s, alerts {len(alerted)} by layer {dict(by_layer)}")
ix = np.where(seen)[0]
uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{k for k, v in S.gt.items() if u in v} for u in uu]
pos = {int(i): j for j, i in enumerate(ix)}
pred = np.zeros(len(ix), bool); layer_of = {}
for n, l in alerted.items():
    if n in pos:
        pred[pos[n]] = True; layer_of[pos[n]] = l
res = {"set": a.set, "name": a.name, "cfg": over, "product": at(pred, labels, na), "n_attacks": len(S.gt),
       "gt_nodes": int(labels.sum()), "days": len(S.test_days)}
res["product"]["FP/day"] = round(res["product"]["FP"] / len(S.test_days), 1)
for l in sorted(set(layer_of.values())):
    m = np.array([layer_of.get(j) == l for j in range(len(ix))])
    res[f"layer:{l}"] = at(m, labels, na)
res["attacks_found"] = sorted({k for j in np.where(pred & labels)[0] for k in na[j]})
print(json.dumps(res))
json.dump(res, open(a.out or f"/lab/res-{a.name}-{a.set}.json", "w"), indent=1)
