"""How well does detection work after 1 hour, 1 day, ... of baseline? (maturity study)

  python -m pdp_server.tools.maturity_eval darpa --endpoint <id> --dataset CADETS_E3 --levels 1h,1d,3d,full
  python -m pdp_server.tools.maturity_eval host  --endpoint <id> --train-hours 1 --test-hours 6

darpa: from a benchmark endpoint's baseline store, a model is trained on only the first hour / day / ... of the
recorded windows (the last quarter of them as validation, as the product does for early models) and the same
attack days are scored with each, against the ORTHRUS ground truth: attacks detected, ground-truth nodes alerted,
other alerted nodes (false positives), by layer.

host: a live endpoint's raw telemetry (still in the telemetry store while its first day is open) is cut into
windows; a model is trained on the first N hours and the following hours are scored. Everything on the host is
benign activity, so every alert is a false alarm: the output is alerts per hour by layer.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import time

import numpy as np

from pdp_server import db
from pdp_server.worker import DATA_DIR, store_for

LEVEL_WINDOWS = {"1h": 4, "6h": 24, "1d": 96, "3d": 288, "full": None}


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def split_windows(paths: list[str]) -> tuple[list[str], list[str]]:
    """The product's early-model split: the last quarter (at least one window) validates, the rest trains."""
    n_val = max(1, int(round(len(paths) * 0.25)))
    return paths[:-n_val], paths[-n_val:]


def build_store(root: str, registry_json: str, train: list[str], val: list[str]):
    from pdp_engine.data import WindowStore
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(os.path.join(root, "windows", "train")); os.makedirs(os.path.join(root, "windows", "val"))
    shutil.copy(registry_json, os.path.join(root, "registry.json"))
    for label, ps in (("train", train), ("val", val)):
        for k, p in enumerate(ps):
            os.symlink(p, os.path.join(root, "windows", label, f"{k:05d}.npz"))
    return WindowStore(root)


def train(store, out: str, device: str, train_days=("train",), val_day="val", quick: bool = False) -> str:
    from pdp_engine.trainer import Trainer, TrainConfig
    cfg = TrainConfig(device=device)
    shutil.rmtree(out, ignore_errors=True); os.makedirs(out)
    t0 = time.time()
    Trainer(store, list(train_days), val_day, cfg, out).run({"bundle_id": os.path.basename(out), "window_ns": 900_000_000_000})
    log(f"trained {out} in {time.time() - t0:.0f}s")
    return out


def darpa(a):
    from pdp_server.tools.darpa_eval import DATASETS, load_gt, metrics, rescore
    D = DATASETS[a.dataset]
    gt = load_gt(a.gt_dir, D["gt"])
    all_gt = set().union(*gt.values())
    with db.conn() as c:
        ep = db.q(c, "SELECT * FROM endpoints WHERE id=%s", (a.endpoint,), one=True)
    base = store_for(a.endpoint)
    days = sorted(base.days())
    paths = [os.path.join(base.root, "windows", d, f) for d in days for f in sorted(os.listdir(os.path.join(base.root, "windows", d)))]
    out = {"dataset": a.dataset, "baseline_days": days, "baseline_windows": len(paths), "levels": []}
    for level in a.levels.split(","):
        root = os.path.join(DATA_DIR, "endpoints", a.endpoint, "maturity", level)
        if level == "full":                            # the product's normal split: last baseline day validates
            store, tr, va = base, days[:-1], days[-1]
            nwin = len(paths)
        else:
            nwin = min(LEVEL_WINDOWS[level], len(paths))
            tr_p, va_p = split_windows(paths[:nwin])
            store = build_store(os.path.join(root, "store"), os.path.join(base.root, "registry.json"), tr_p, va_p)
            tr, va = ["train"], "val"
        log(f"{a.dataset} {level}: {nwin} baseline windows ({nwin / 4:.1f} h)")
        bdir = train(store, os.path.join(root, "bundle"), a.device, tr, va)
        reg, seen, best = rescore(a.endpoint, ep, bdir, D["test"], a.device)
        ids = np.where(seen)[0]
        uu = [reg[int(x)].uuid for x in ids]
        labels = np.array([u in all_gt for u in uu])
        node_attacks = [{k for k, v in gt.items() if u in v} for u in uu]
        fl = {k: v[ids] for k, v in best["layers"].items()}
        prod = fl["novelty"] | fl["rules"] | fl["corroborated"] | fl["learned"]
        row = {"level": level, "baseline_hours": round(nwin / 4, 1), "product": metrics(prod, labels, node_attacks, len(gt)),
               "by_layer": {k: {"alerts": int(v.sum()), "TP": int((v & labels).sum())} for k, v in fl.items()},
               "deterministic_only": metrics(fl["novelty"] | fl["rules"], labels, node_attacks, len(gt))}
        out["levels"].append(row)
        log(json.dumps(row))
    return out


def host(a):
    """Train on the first N hours of a live endpoint's raw telemetry, score the next hours."""
    from pdp_engine.data import WindowStore, ingest_day
    from pdp_server.worker import extend_registry, load_registry
    root = os.path.join(DATA_DIR, "endpoints", a.endpoint, "maturity", f"host-{a.train_hours}h")
    shutil.rmtree(root, ignore_errors=True)
    full = WindowStore(os.path.join(root, "all"))
    reg = load_registry(a.endpoint, full)
    extend_registry(a.endpoint, reg)
    with db.conn(db.TELEMETRY_DSN) as c:
        t = db.q(c, f"SELECT min(ts_ns) AS lo, max(ts_ns) AS hi FROM {db.tschema(a.endpoint)}.events", one=True)
    lo, hi = int(t["lo"]), int(t["hi"])
    H = 3600 * 10**9
    end = min(hi, lo + (a.train_hours + a.test_hours) * H)
    log(f"telemetry {((hi - lo) / H):.1f} h available; using {((end - lo) / H):.1f} h")
    # events in time order, cut into 15-minute windows (the worker's ingest path, over a time range)
    def events():
        with db.conn(db.TELEMETRY_DSN) as c:
            with c.cursor(name="mat") as cur:
                cur.itersize = 200_000
                cur.execute(f"SELECT ts_ns, src, op, dst, event_uuid FROM {db.tschema(a.endpoint)}.events WHERE ts_ns < %s ORDER BY ts_ns", (end,))
                from pdp_engine.schema import Event
                for r in cur:
                    yield Event(int(r[0]), r[1], r[2], r[3], r[4])
    n = full.add_day("all", ingest_day(reg, events(), None, window_ns=900_000_000_000))
    full.save_registry(reg)
    paths = [os.path.join(full.root, "windows", "all", f) for f in sorted(os.listdir(os.path.join(full.root, "windows", "all")))]
    ntrain = a.train_hours * 4
    tr_p, va_p = split_windows(paths[:ntrain])
    test = paths[ntrain:]
    log(f"{n} windows: {len(tr_p)} train, {len(va_p)} validation, {len(test)} test")
    store = build_store(os.path.join(root, "store"), os.path.join(full.root, "registry.json"), tr_p, va_p)
    bdir = train(store, os.path.join(root, "bundle"), a.device)
    from pdp_engine.runtime import Runtime
    tdir = os.path.join(store.root, "windows", "test"); os.makedirs(tdir)
    for k, p in enumerate(test):
        os.symlink(p, os.path.join(tdir, f"{k:05d}.npz"))
    rt = Runtime(bdir, reg, device=a.device, feat_device=a.device)
    per_hour, examples = [], {}
    for k, w in enumerate(store.windows("test")):
        r = rt.score(w)
        h = k // 4
        while len(per_hour) <= h:
            per_hour.append({"hour": len(per_hour) + 1, "alerts": 0, "by_layer": {}})
        for nd in r.alerts:
            lay = r.layer_of(int(nd))
            per_hour[h]["alerts"] += 1
            per_hour[h]["by_layer"][lay] = per_hour[h]["by_layer"].get(lay, 0) + 1
            e = reg[int(nd)]
            key = (lay, (r.reasons.get(int(nd)) or [{}])[0].get("rule"), e.label.split(" ")[1] if e.label.startswith("subject ") and " " in e.label else e.label[:60])
            examples[key] = examples.get(key, 0) + 1
    top = sorted(examples.items(), key=lambda x: -x[1])[:25]
    out = {"endpoint": a.endpoint, "train_hours": a.train_hours, "test_hours": round(len(test) / 4, 2), "per_hour": per_hour,
           "total_alerts": sum(h["alerts"] for h in per_hour), "top": [{"layer": k[0], "rule": k[1], "what": k[2], "n": v} for k, v in top]}
    log(json.dumps(out)[:3000])
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("darpa"); d.add_argument("--endpoint", required=True); d.add_argument("--dataset", required=True)
    d.add_argument("--levels", default="1h,1d,full"); d.add_argument("--gt-dir", default="/data/gt/orthrus")
    h = sub.add_parser("host"); h.add_argument("--endpoint", required=True); h.add_argument("--train-hours", type=int, default=1)
    h.add_argument("--test-hours", type=int, default=6)
    for p in (d, h):
        p.add_argument("--device", default="cuda"); p.add_argument("--json")
    a = ap.parse_args()
    res = darpa(a) if a.cmd == "darpa" else host(a)
    if a.json:
        json.dump(res, open(a.json, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
