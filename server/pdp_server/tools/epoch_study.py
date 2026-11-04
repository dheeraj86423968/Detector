"""Research diagnostic: detector-1 (Velox) test ADP after every training epoch vs. its validation loss.

  python -m pdp_server.tools.epoch_study --endpoint <id> --dataset CADETS_E3 [--epochs 12] [--seed 0] [--lr ...]

The product selects the epoch with the lowest validation loss (no test data). PIDSMaker's released default
(`best_model_selection: best_adp`) instead keeps the epoch with the best *test* ADP. This tool shows both on the same
training run, to tell an implementation problem (bad at every epoch) from an epoch-selection effect (good at some
epoch, not the one validation loss picks). Test-selected numbers are an upper bound, not a deployable result.
Needs the test days ingested by darpa_eval (eval-test store).
"""
from __future__ import annotations

import argparse
import json
import os

import numpy as np
import torch

from pdp_server import db
from pdp_server.tools.darpa_eval import DATASETS, adp, load_gt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True); ap.add_argument("--dataset", required=True, choices=list(DATASETS))
    ap.add_argument("--gt-dir", default="/data/gt/orthrus"); ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--seed", type=int, default=0); ap.add_argument("--lr", type=float); ap.add_argument("--out-dim", type=int)
    ap.add_argument("--json")
    a = ap.parse_args()
    from pdp_engine.data import WindowStore
    from pdp_engine.featurizer import Word2VecFeaturizer
    from pdp_engine.models import VeloxModel, seed_everything, window_degrees
    from pdp_engine.scoring import node_scores
    from pdp_engine.trainer import TrainConfig, Trainer
    from pdp_engine.windows import batches
    from pdp_server.worker import DATA_DIR, store_for
    with db.conn() as c:
        ep = db.q(c, "SELECT config, current_bundle FROM endpoints WHERE id=%s", (a.endpoint,), one=True)
        man = db.q(c, "SELECT path, manifest FROM bundles WHERE id=%s", (ep["current_bundle"],), one=True)
    m = man["manifest"]
    over = dict(ep["config"].get("train", {}))
    cfg = TrainConfig(device="cuda", **{k: v for k, v in over.items() if k.startswith("velox") or k in ("emb_dim", "weight_decay", "batch_size")})
    lr = a.lr or cfg.velox_lr; out_dim = a.out_dim or cfg.velox_out_dim
    test = WindowStore(os.path.join(DATA_DIR, "endpoints", a.endpoint, "eval-test"))
    reg_test = test.load_registry()
    tr = Trainer(store_for(a.endpoint), m["train_days"], m["val_day"], cfg, "/tmp/epoch-study")
    tr.feat = Word2VecFeaturizer.load(os.path.join(man["path"], "featurizer"))       # the deployed featuriser
    dev = torch.device("cuda")
    x_test = torch.from_numpy(tr.feat.features(reg_test.labels(), reg_test.types())).to(dev)
    tr.x = x_test[: tr.N]                                                             # baseline rows are a prefix
    D = DATASETS[a.dataset]; gt = load_gt(a.gt_dir, D["gt"]); all_gt = set().union(*gt.values())

    def scores(model, store, days, x, n):
        model.eval(); s = np.full(n, -np.inf, np.float32)
        with torch.no_grad():
            for d in days:
                for w in store.windows(d):
                    src, dst, et = (torch.from_numpy(z).to(dev) for z in (w.src, w.dst, w.etype))
                    xs, xd = x[src], x[dst]
                    if cfg.velox_degree_features:   # the same structural input as the trainer / runtime
                        ds, dd = window_degrees(src, dst, et)
                        xs, xd = torch.cat([xs, ds], 1), torch.cat([xd, dd], 1)
                    l = torch.cat([model.losses(xs[i:j], xd[i:j], et[i:j]) for i, j in batches(w)]).cpu().numpy()
                    node_scores(n, w.src, w.dst, l, s)
        return s

    seed_everything(a.seed)
    model = VeloxModel(tr.velox_in_dim, out_dim).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=cfg.weight_decay)
    rows = []
    for e in range(a.epochs):
        trl = tr._velox_epoch(model, opt, tr.train_days, True)
        val = tr._velox_epoch(model, None, [tr.val_day], False)
        sv = scores(model, tr.store, [tr.val_day], tr.x, tr.N); thr = float(sv[np.isfinite(sv)].max())
        st = scores(model, test, D["test"], x_test, len(reg_test))
        ids = np.where(np.isfinite(st))[0]; uu = [reg_test[int(i)].uuid for i in ids]
        lab = np.array([u in all_gt for u in uu]); na = [{k for k, v in gt.items() if u in v} for u in uu]
        pred = st[ids] > thr
        row = {"epoch": e, "train_loss": round(trl, 4), "val_loss": round(val, 4), "test_ADP": round(adp(st[ids], lab, na), 3),
               "TP": int((pred & lab).sum()), "FP": int((pred & ~lab).sum())}
        rows.append(row); print(json.dumps(row), flush=True)
    sel = min(rows, key=lambda r: r["val_loss"]); best = max(rows, key=lambda r: r["test_ADP"])
    out = {"lr": lr, "out_dim": out_dim, "seed": a.seed, "epochs": rows, "selected_by_val_loss": sel, "selected_by_test_ADP": best}
    print(json.dumps({"selected_by_val_loss": sel, "selected_by_test_ADP (upper bound)": best}))
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
