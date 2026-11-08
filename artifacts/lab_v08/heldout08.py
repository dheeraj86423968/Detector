"""0.8 held-out run (once per host, configuration frozen in the commit named in PROTOCOL.md): train a 0.6-configured
bundle on the host's baseline (training days + validation day, GPU), upgrade it with the product trainer to
0.7 released (detector-3 max, layer 1 on) and to 0.8 (TrainConfig defaults: breadth, layer 1 off) - the same
detectors 1-2 for all three - then score the test days with each through the runtime and report product alerts
against the ground truth. Usage: heldout08.py /data/heldout/<DATASET>/<host> --out file.json"""
import argparse, csv, json, os, time
from collections import Counter
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.runtime import Runtime
from pdp_engine.trainer import TrainConfig, Trainer, upgrade_bundle_07
from common8 import log, at

ap = argparse.ArgumentParser(); ap.add_argument("host_dir"); ap.add_argument("--out", required=True)
a = ap.parse_args()
man = json.load(open(os.path.join(a.host_dir, "manifest.json")))
gt = {}
for name, g in man["ground_truth"].items():
    gt[name] = {r[2].strip() for r in csv.reader(open(os.path.join("/gt", g["csv"]))) if len(r) >= 3 and r[2].strip()}
allgt = set().union(*gt.values()) if gt else set()
base = WindowStore(os.path.join(a.host_dir, "baseline"))
work = f"/data/lab08/heldout/{man['dataset']}/{man['host']}"
os.makedirs(work, exist_ok=True)
cfg8 = TrainConfig(device="cuda")
cfg7 = TrainConfig(**{**cfg8.__dict__, "d3_breadth": False, "layer_novelty": True})
cfg6 = TrainConfig(**{**cfg8.__dict__, "detector3": False, "d3_breadth": False, "layer_novelty": True,
                      "novelty_as_evidence": False, "learned_alerts": False})
b6, b7, b8 = (os.path.join(work, x) for x in ("b06", "b07rel", "b08"))
t0 = time.time()
if not os.path.exists(os.path.join(b6, "manifest.json")):
    Trainer(base, list(man["train_days"]), man["val_day"], cfg6, b6).run({"endpoint": f"{man['dataset']}/{man['host']}"})
log(f"0.6-config bundle {time.time()-t0:.0f}s")
for bdir, cfg in ((b7, cfg7), (b8, cfg8)):
    if not os.path.exists(os.path.join(bdir, "manifest.json")):
        upgrade_bundle_07(b6, bdir, base, cfg)
log(f"upgrades {time.time()-t0:.0f}s")
st = WindowStore(os.path.join(a.host_dir, "eval-test"))
days = list(man["test_days"])
res = {"dataset": man["dataset"], "host": man["host"], "test_days": days, "n_attacks": len(gt), "gt_nodes": len(allgt)}
for name, bdir in (("0.6", b6), ("0.7", b7), ("0.8", b8)):
    reg = st.load_registry()
    rt = Runtime(bdir, reg, device="cuda", feat_device="cuda")
    alerted = {}; seen = np.zeros(0, bool)
    for d in days:
        for w in st.windows(d):
            r = rt.score(w)
            for n in r.alerts.tolist():
                alerted.setdefault(n, r.layer_of(n))
            if len(seen) < len(reg):
                seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
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
    r0["by_layer_tp"] = dict(Counter(l for j, l in lay.items() if labels[j]))
    r0["gt_in_test"] = int(labels.sum())
    r0["attacks_found"] = sorted({k for j in np.where(pred & labels)[0] for k in na[j]})
    res[name] = r0
    log(f"{name}: {r0}")
    del rt
print(json.dumps(res, indent=1))
json.dump(res, open(a.out, "w"), indent=1)
