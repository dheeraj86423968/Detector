"""Held-out run (once, after the 0.7 configuration is frozen): train a 0.6-configured bundle on the host's baseline
(training days + validation day, GPU), upgrade it to 0.7 with upgrade_bundle_07 (the same detectors 1-2, so the
comparison isolates the 0.7 changes), score the test days with each through the runtime, and report the product
alerts against the ground truth. Usage: heldout_eval.py /data/heldout/<DATASET>/<host> --out file.json"""
import argparse, csv, json, os, time
from collections import Counter
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.runtime import Runtime
from pdp_engine.trainer import TrainConfig, Trainer, upgrade_bundle_07
from common import log, at

ap = argparse.ArgumentParser(); ap.add_argument("host_dir"); ap.add_argument("--out", required=True); ap.add_argument("--name", default="b07"); ap.add_argument("--only", default="0.6,0.7"); ap.add_argument("--grouped", action="store_true"); ap.add_argument("--nov-ev", type=int, default=0); ap.add_argument("--novelty-alert", action="store_true"); ap.add_argument("--corr", type=float, default=None)
a = ap.parse_args()
man = json.load(open(os.path.join(a.host_dir, "manifest.json")))
gtd = man["ground_truth"]
gt = {}
for name, g in gtd.items():
    ids = set()
    for row in csv.reader(open(os.path.join("/gt", g["csv"]))):
        if len(row) >= 3 and row[2].strip():
            ids.add(row[2].strip())
    gt[name] = ids
allgt = set().union(*gt.values()) if gt else set()
base = WindowStore(os.path.join(a.host_dir, "baseline"))
work = f"/data/lab07/heldout/{man['dataset']}/{man['host']}"
os.makedirs(work, exist_ok=True)
b6, b7 = os.path.join(work, "b06"), os.path.join(work, a.name)
cfg7 = TrainConfig(device="cuda", d3_grouped=a.grouped, novelty_as_evidence=bool(a.nov_ev) and not a.novelty_alert, layer_novelty=bool(a.nov_ev) or a.novelty_alert)
cfg6 = TrainConfig(**{**cfg7.__dict__, "detector3": False, "layer_novelty": True, "novelty_as_evidence": False, "learned_alerts": False})
t0 = time.time()
if not os.path.exists(os.path.join(b6, "manifest.json")):
    Trainer(base, list(man["train_days"]), man["val_day"], cfg6, b6).run({"endpoint": f"{man['dataset']}/{man['host']}"})
log(f"0.6-config bundle {time.time()-t0:.0f}s")
if not os.path.exists(os.path.join(b7, "manifest.json")):
    upgrade_bundle_07(b6, b7, base, cfg7)
log(f"0.7 upgrade {time.time()-t0:.0f}s")
st = WindowStore(os.path.join(a.host_dir, "eval-test"))
days = list(man["test_days"])
res = {"dataset": man["dataset"], "host": man["host"], "test_days": days, "n_attacks": len(gt), "gt_nodes": len(allgt)}
for name, bdir in [x for x in (("0.6", b6), ("0.7", b7)) if x[0] in a.only.split(",")]:
    reg = st.load_registry()
    rt = Runtime(bdir, reg, device="cuda", feat_device="cuda")
    if a.corr is not None and name == "0.7":
        rt.corroboration = a.corr; rt.policy.corroboration = a.corr
    alerted = {}
    for d in days:
        for w in st.windows(d):
            r = rt.score(w)
            for n in r.alerts.tolist():
                alerted.setdefault(n, r.layer_of(n))
    seen = np.zeros(len(reg), bool)
    for d in days:
        for w in st.windows(d):
            seen[w.src] = True; seen[w.dst] = True
    ix = np.where(seen)[0]
    uu = [reg.entities[int(i)].uuid for i in ix]
    labels = np.array([u in allgt for u in uu]); na = [{k for k, v in gt.items() if u in v} for u in uu]
    pos = {int(i): j for j, i in enumerate(ix)}
    pred = np.zeros(len(ix), bool); lay = {}
    for n, l in alerted.items():
        if n in pos:
            pred[pos[n]] = True; lay[pos[n]] = l
    r0 = at(pred, labels, na); r0["FP/day"] = round(r0["FP"] / max(1, len(days)), 1)
    r0["by_layer"] = dict(Counter(lay.values()))
    r0["gt_in_test"] = int(labels.sum())
    res[name] = r0
    log(f"{name}: {r0}")
    del rt
print(json.dumps(res, indent=1))
json.dump(res, open(a.out, "w"), indent=1)
