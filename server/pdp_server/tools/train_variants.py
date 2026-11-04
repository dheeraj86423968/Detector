"""Train extra, differently seeded bundles for an endpoint (run-to-run variance studies, as in Bilot et al. SC5).

  python -m pdp_server.tools.train_variants --endpoint <id> --runs 1,2,3,4 [--parallel 4] [--device cuda]

Run r uses disjoint seed sets - detector-1 seeds v*r .. v*r+v-1 and detector-2 seeds k*r .. k*r+k-1 (v, k = the
configured ensemble sizes, 3 and 5 by default) - otherwise the endpoint's own training
configuration and baseline window store (the same days as its deployed bundle). Each bundle is signed and recorded
in `bundles`, but the endpoint keeps its deployed bundle — nothing changes for the agent. Evaluate all of them with
`pdp_server.tools.darpa_eval --bundles all`.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import time


def train_one(eid: str, r: int, device: str) -> str:
    from pdp_engine.bundle import sha256, sign_manifest
    from pdp_engine.trainer import TrainConfig, Trainer
    from pdp_server import db, pki
    from pdp_server.worker import DATA_DIR, store_for, window_ns
    with db.conn() as c:
        ep = db.q(c, "SELECT config, current_bundle FROM endpoints WHERE id=%s", (eid,), one=True)
        base = db.q(c, "SELECT manifest FROM bundles WHERE id=%s", (ep["current_bundle"],), one=True)["manifest"]
    over = dict(ep["config"].get("train", {}))
    v = int(over.get("velox_runs", TrainConfig.velox_runs))
    k = len(over.get("orthrus_seeds", TrainConfig.orthrus_seeds))
    over.update({"velox_seed": v * r, "orthrus_seeds": tuple(range(k * r, k * r + k))})
    if "fusion_weights" in over:
        over["fusion_weights"] = tuple(over["fusion_weights"])
    cfg = TrainConfig(device=device, **over)
    bid = pki.new_id()
    out = os.path.join(DATA_DIR, "bundles", eid, bid)
    t0 = time.time()
    Trainer(store_for(eid), base["train_days"], base["val_day"], cfg, out).run(
        {"endpoint": eid, "bundle_id": bid, "window_ns": window_ns(ep["config"]), "variant_run": r, "trained_on": device})
    sign_manifest(out, pki.signing_private_pem())
    manifest = json.load(open(os.path.join(out, "manifest.json")))
    with db.conn() as c:
        db.q(c, "INSERT INTO bundles (id, endpoint_id, path, sha256, manifest) VALUES (%s,%s,%s,%s,%s)",
             (bid, eid, out, sha256(os.path.join(out, "manifest.json")), json.dumps(manifest)))
    print(f"run {r}: bundle {bid} in {time.time() - t0:.0f}s", flush=True)
    return bid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--runs", default="1,2,3,4")
    ap.add_argument("--parallel", type=int, default=4)
    ap.add_argument("--device", default="cuda")
    a = ap.parse_args()
    runs = [int(x) for x in a.runs.split(",")]
    ctx = mp.get_context("spawn")       # CUDA needs spawned (not forked) workers
    with ctx.Pool(min(a.parallel, len(runs))) as pool:
        bids = pool.starmap(train_one, [(a.endpoint, r, a.device) for r in runs])
    print(json.dumps({"endpoint": a.endpoint, "bundles": bids}))


if __name__ == "__main__":
    main()
