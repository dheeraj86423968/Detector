"""Add (or re-fit) the deterministic detection layers of an existing bundle, without retraining the detectors.

  python -m pdp_server.tools.add_layers --endpoint <id> [--bundle <id> | --bundles all] [--deploy]

Layers 1 (executable novelty) and 2 (information-flow tags with benign-calibrated alarms) are fitted on the bundle's
own baseline days (training + validation; pdp_engine.layers.fit_layers) - a few seconds per endpoint. The result is
written into a copy of the bundle with the default learned-alert policy, signed and registered as a new bundle; with
--deploy it becomes the endpoint's current bundle (the agent fetches and verifies it on its next poll). This is the
upgrade path for endpoints protected by a pre-0.3 bundle, and for 0.3 bundles to the 0.4 layers (re-fitted with the
current defaults; the learned layer becomes ranking-only unless the endpoint turns its alerts on).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import time


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def layer_bundle(eid: str, src: dict, deploy: bool = False) -> str:
    from pdp_engine.bundle import sha256, write_manifest
    from pdp_engine.layers import fit_layers
    from pdp_engine.trainer import TrainConfig
    from pdp_server import db, pki
    from pdp_server.worker import store_for
    man = json.load(open(os.path.join(src["path"], "manifest.json")))
    store = store_for(eid)
    reg = store.load_registry()
    spec = fit_layers(store, list(man["train_days"]) + [man["val_day"]], reg, int(man["num_nodes"]), log=log)
    bid = pki.new_id()
    out = os.path.join(os.path.dirname(src["path"].rstrip("/")), bid)
    shutil.copytree(src["path"], out)
    sig = os.path.join(out, "signature.json")
    if os.path.exists(sig):
        os.remove(sig)
    json.dump(spec, open(os.path.join(out, "layers.json"), "w"))
    meta = {k: v for k, v in man.items() if k not in ("sha256", "format", "created")}
    meta.update({"bundle_id": bid, "layers_added_to": str(src["id"]),
                 "layers": {"file": "layers.json", "novelty": True, "rules": True, "known_executables": len(spec["known_executables"]),
                            "benign_alarm_keys": {r: len(v) for r, v in spec["thresholds"].items()}}})
    # the current learned-alert default comes with the current layers (0.4: ranking only; an endpoint setting overrides it)
    meta["learned_policy"] = dict({"daily_budget": TrainConfig.learned_daily_budget, "corroboration_percentile": TrainConfig.corroboration_percentile},
                                  **(meta.get("learned_policy") or {}), learned_alerts=TrainConfig.learned_alerts)
    write_manifest(out, meta)
    pki.sign_bundle(out)
    manifest = json.load(open(os.path.join(out, "manifest.json")))
    with db.conn() as c:
        db.q(c, "INSERT INTO bundles (id, endpoint_id, path, sha256, manifest) VALUES (%s,%s,%s,%s,%s)",
             (bid, eid, out, sha256(os.path.join(out, "manifest.json")), json.dumps(manifest)))
        if deploy:
            db.q(c, "UPDATE endpoints SET current_bundle=%s WHERE id=%s", (bid, eid))
    log(f"bundle {src['id']} -> {bid} with layers" + (" (deployed)" if deploy else ""))
    return bid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--bundle", help="bundle id (default: the endpoint's current bundle)")
    ap.add_argument("--bundles", help="'all' or comma-separated ids: one new layered bundle per source bundle")
    ap.add_argument("--deploy", action="store_true", help="make the (single) new bundle the endpoint's current bundle")
    a = ap.parse_args()
    from pdp_server import db
    with db.conn() as c:
        ep = db.q(c, "SELECT current_bundle FROM endpoints WHERE id=%s", (a.endpoint,), one=True)
        if a.bundles == "all":
            srcs = db.q(c, "SELECT id, path FROM bundles WHERE endpoint_id=%s ORDER BY created_at", (a.endpoint,))
        elif a.bundles:
            srcs = [db.q(c, "SELECT id, path FROM bundles WHERE id=%s", (b,), one=True) for b in a.bundles.split(",")]
        else:
            srcs = [db.q(c, "SELECT id, path FROM bundles WHERE id=%s", (a.bundle or ep["current_bundle"],), one=True)]
    if a.deploy and len(srcs) != 1:
        raise SystemExit("--deploy needs exactly one source bundle")
    out = [layer_bundle(a.endpoint, s, a.deploy) for s in srcs]
    print(json.dumps({"endpoint": a.endpoint, "bundles": out}))


if __name__ == "__main__":
    main()
