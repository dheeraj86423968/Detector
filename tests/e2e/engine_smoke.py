"""Engine smoke test: baseline from Postgres replay -> train (short) -> bundle -> runtime on test days -> GT check.

python tests/e2e/engine_smoke.py CADETS_E3 --train 2018-04-02,2018-04-03 --val 2018-04-10 --test 2018-04-06 --epochs 2 --seeds 1
"""
import argparse
import csv
import os
import sys
import time

import numpy as np

sys.path.insert(0, "/home/platform/engine")
from pdp_engine.data import WindowStore, ingest_day  # noqa: E402
from pdp_engine.runtime import Runtime  # noqa: E402
from pdp_engine.schema import Registry  # noqa: E402
from pdp_engine.sources.pg_replay import PostgresReplay  # noqa: E402
from pdp_engine.trainer import TrainConfig, Trainer  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("dataset"); ap.add_argument("--train", required=True); ap.add_argument("--val", required=True)
ap.add_argument("--test", required=True); ap.add_argument("--epochs", type=int, default=2); ap.add_argument("--seeds", type=int, default=1)
ap.add_argument("--w2v_epochs", type=int, default=50); ap.add_argument("--root", default="/home/artifacts/platform_smoke")
a = ap.parse_args()
db = {"CADETS_E3": "cadets_e3", "THEIA_E3": "theia_e3"}[a.dataset]
gt_files = {"CADETS_E3": ["E3-CADETS/node_Nginx_Backdoor_06.csv", "E3-CADETS/node_Nginx_Backdoor_12.csv", "E3-CADETS/node_Nginx_Backdoor_13.csv"],
            "THEIA_E3": ["E3-THEIA/node_Browser_Extension_Drakon_Dropper.csv", "E3-THEIA/node_Firefox_Backdoor_Drakon_In_Memory.csv"]}[a.dataset]
t0 = time.time()


def log(m):
    print(f"[{time.time() - t0:7.1f}s] {m}", flush=True)


root = os.path.join(a.root, a.dataset)
store = WindowStore(root)
train_days, val_day, test_days = a.train.split(","), a.val, a.test.split(",")
src = PostgresReplay(db)
if os.path.exists(os.path.join(root, "registry.json")):
    reg = store.load_registry()
else:
    reg = Registry()
lookup = None
for d in train_days + [val_day] + test_days:
    if d in store.days():
        continue
    if lookup is None:
        lookup = src.entity_index(); log(f"{len(lookup)} entities in database")
    n = store.add_day(d, ingest_day(reg, src.events(d), lookup))
    log(f"{d}: {n} windows, registry {len(reg)}")
store.save_registry(reg)

cfg = TrainConfig(velox_epochs=a.epochs, orthrus_epochs=a.epochs, orthrus_seeds=tuple(range(a.seeds)), w2v_epochs=a.w2v_epochs)
bundle = os.path.join(root, "bundle")
Trainer(store, train_days, val_day, cfg, bundle).run({"endpoint": "smoke", "dataset": a.dataset})
log("bundle written")

rt = Runtime(bundle, store.load_registry(), device=cfg.device)
gt = set()
for f in gt_files:
    for row in csv.reader(open(os.path.join("/home/pids/Ground_Truth/orthrus", f))):
        i = reg.get(row[2])
        if i is not None:
            gt.add(i)
flagged, best = {}, {}
for d in test_days:
    for w in store.windows(d):
        r = rt.score(w)
        for nid, f in zip(r.node_ids, r.fused):
            best[int(nid)] = max(best.get(int(nid), -1.0), float(f))
        for nid in r.alerts:
            flagged[int(nid)] = True
tp = sum(1 for n in flagged if n in gt)
log(f"test: {len(best)} scored nodes, {len(gt)} GT nodes ({sum(1 for n in best if n in gt)} seen); alerts {len(flagged)}: TP {tp} FP {len(flagged) - tp}")
order = sorted(best.items(), key=lambda x: -x[1])
log(f"GT ranks among scored nodes: {[i for i, (n, _) in enumerate(order) if n in gt][:10]}")
log("SMOKE OK")
