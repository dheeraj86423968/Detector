"""Detector-1 lab: train Velox with a given input variant on an endpoint's baseline, select the epoch by validation
loss (no test data), and report test ADP / TP / FP of the selected epoch per seed and of the seed ensemble.
Per-epoch test ADP is logged as a diagnostic only (never used for selection).

  d1lab.py <eid> <dataset> <variant> [seeds=0,1,2] [lr=1e-4] [out_dim=256] [epochs=12]

variants: win    - current product (window degree features appended)
          none   - node features only
          reidx  - PIDSMaker's reindexer input: per 1024-edge batch, a node that is both a source and a destination
                   in the batch gets its features scaled by (1 + 1/k), k = its in-count in the batch
          batch  - explicit per-batch role features appended: log1p(out-count), log1p(in-count), is-src&dst, 1/k
"""
import json, os, sys, time
import numpy as np
import torch
from pdp_engine.data import WindowStore
from pdp_engine.featurizer import Word2VecFeaturizer
from pdp_engine.models import VeloxModel, seed_everything, window_degrees
from pdp_engine.scoring import node_scores
from pdp_engine.windows import batches
from pdp_server.tools.darpa_eval import DATASETS, adp, load_gt

eid, ds, variant = sys.argv[1], sys.argv[2], sys.argv[3]
seeds = [int(s) for s in (sys.argv[4] if len(sys.argv) > 4 else "0,1,2").split(",")]
lr = float(sys.argv[5]) if len(sys.argv) > 5 else 1e-4
out_dim = int(sys.argv[6]) if len(sys.argv) > 6 else 256
EPOCHS = int(sys.argv[7]) if len(sys.argv) > 7 else 12
PATIENCE = 3
dev = torch.device("cuda")
bid = [l.split()[2].split(",")[0] for l in open("/lab/jobs.txt") if l.startswith(eid)][0]
bdir = f"/data/bundles/{eid}/{bid}"
man = json.load(open(f"{bdir}/manifest.json"))
base = WindowStore(f"/data/endpoints/{eid}/baseline")
test = WindowStore(f"/data/endpoints/{eid}/eval-test")
reg_test = test.load_registry()
N = len(base.load_registry())
feat = Word2VecFeaturizer.load(f"{bdir}/featurizer")
x_all = torch.from_numpy(feat.features(reg_test.labels(), reg_test.types())).to(dev)
x_base = x_all[:N]
D = DATASETS[ds]; gt = load_gt("/gt", D["gt"]); all_gt = set().union(*gt.values())
EXTRA = {"win": 4, "none": 0, "reidx": 0, "batch": 4}[variant]


def batch_role(s, d):
    B = s.shape[0]
    nodes, inv = torch.unique(torch.cat([s, d]), return_inverse=True)
    U = nodes.shape[0]; si, di = inv[:B], inv[B:]
    one = torch.ones(B, device=s.device)
    cin = torch.zeros(U, device=s.device).index_add_(0, di, one)
    cout = torch.zeros(U, device=s.device).index_add_(0, si, one)
    both = (cin > 0) & (cout > 0)
    return si, di, cin, cout, both


def inputs(x, w):
    src, dst, et = (torch.from_numpy(a).to(dev) for a in (w.src, w.dst, w.etype))
    if variant == "win":
        dgs, dgd = window_degrees(src, dst, et)
    for a, b in batches(w):
        s, d = src[a:b], dst[a:b]
        xs, xd = x[s], x[d]
        if variant == "win":
            xs, xd = torch.cat([xs, dgs[a:b]], 1), torch.cat([xd, dgd[a:b]], 1)
        elif variant == "reidx":
            si, di, cin, cout, both = batch_role(s, d)
            scale = torch.where(both, 1.0 + 1.0 / cin.clamp(min=1), torch.ones_like(cin))
            xs, xd = xs * scale[si, None], xd * scale[di, None]
        elif variant == "batch":
            si, di, cin, cout, both = batch_role(s, d)
            f = torch.stack([torch.log1p(cout) / 7, torch.log1p(cin) / 7, both.float(),
                             torch.where(both, 1.0 / cin.clamp(min=1), torch.zeros_like(cin))], 1)
            xs, xd = torch.cat([xs, f[si]], 1), torch.cat([xd, f[di]], 1)
        yield a, b, xs, xd, et[a:b]


def epoch(model, opt, store, days, x, train):
    model.train(train); tot = n = 0.0
    for dday in days:
        for w in store.windows(dday):
            for a, b, xs, xd, et in inputs(x, w):
                with torch.set_grad_enabled(train):
                    loss = model.losses(xs, xd, et, reduce=True)
                if train:
                    opt.zero_grad(); loss.backward(); opt.step()
                tot += float(loss) * (b - a); n += b - a
    return tot / max(n, 1)


@torch.no_grad()
def scores(model, store, days, x, n):
    model.eval(); s = np.full(n, -np.inf, np.float32)
    for dday in days:
        for w in store.windows(dday):
            l = torch.cat([model.losses(xs, xd, et) for a, b, xs, xd, et in inputs(x, w)]).cpu().numpy()
            node_scores(n, w.src, w.dst, l, s)
    return s


def evaluate(st, thr):
    ids = np.where(np.isfinite(st))[0]; uu = [reg_test[int(i)].uuid for i in ids]
    lab = np.array([u in all_gt for u in uu]); na = [{k for k, v in gt.items() if u in v} for u in uu]
    pred = st[ids] > thr
    det = set().union(*[a for a, p in zip(na, pred) if p]) if pred.any() else set()
    return {"ADP": round(adp(st[ids], lab, na), 3), "TP": int((pred & lab).sum()), "FP": int((pred & ~lab).sum()),
            "attacks": f"{len(det)}/{len(gt)}"}


t0 = time.time()
res = {"eid": eid, "dataset": ds, "variant": variant, "lr": lr, "out_dim": out_dim, "seeds": []}
ratios = []
for seed in seeds:
    seed_everything(seed)
    model = VeloxModel(x_all.shape[1] + EXTRA, out_dim).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    best, best_sd, bad, rows = float("inf"), None, 0, []
    for e in range(EPOCHS):
        tr = epoch(model, opt, base, man["train_days"], x_base, True)
        va = epoch(model, None, base, [man["val_day"]], x_base, False)
        sv = scores(model, base, [man["val_day"]], x_base, N); thr = float(sv[np.isfinite(sv)].max())
        diag = evaluate(scores(model, test, D["test"], x_all, len(reg_test)), thr)
        rows.append({"epoch": e, "train": round(tr, 4), "val": round(va, 4), **diag})
        print(variant, seed, json.dumps(rows[-1]), f"{time.time()-t0:.0f}s", flush=True)
        if va < best:
            best, bad = va, 0; best_sd = {k: v.detach().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= PATIENCE:
                break
    model.load_state_dict(best_sd)
    sv = scores(model, base, [man["val_day"]], x_base, N); thr = float(sv[np.isfinite(sv)].max())
    st = scores(model, test, D["test"], x_all, len(reg_test))
    sel = evaluate(st, thr)
    r = st / thr; r[~np.isfinite(r)] = 0.0; ratios.append(r)
    res["seeds"].append({"seed": seed, "selected": sel, "epochs": rows})
    print(variant, seed, "SELECTED", json.dumps(sel), flush=True)
ens = np.mean(ratios, axis=0); ens[ens == 0] = -np.inf
res["ensemble"] = evaluate(ens, 1.0)
res["ensemble_ratio_file"] = f"/lab/r1-{ds}-{variant}-{lr}-{out_dim}.npy"
np.save(res["ensemble_ratio_file"], np.mean(ratios, axis=0).astype(np.float32))
print(variant, "ENSEMBLE", json.dumps(res["ensemble"]), f"{time.time()-t0:.0f}s", flush=True)
json.dump(res, open(f"/lab/d1-{ds}-{variant}-{lr}-{out_dim}.json", "w"), indent=1)
