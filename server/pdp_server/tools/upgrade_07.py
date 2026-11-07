"""Upgrade an endpoint's bundle to the 0.7 detection without retraining detectors 1-2 (no GPU training).

  python -m pdp_server.tools.upgrade_07 --endpoint <id> [--bundle <id>] [--deploy]

pdp_engine.trainer.upgrade_bundle_07 on a copy of the bundle: detector-3 (behavioural likelihood) fitted on the
bundle's training days, thresholds at the validation budget, learned-seeded propagation, layers 1-2 re-fitted with the
0.7 defaults (layer 1 no longer alerts on its own), learned alerts on within the daily budget, and the final threshold
calibrated by replaying the validation day through the runtime. What this endpoint's unreleased alerts point at stays
out of detector-3 and of the layers (pdp_server.learning). The result is signed and registered as a new bundle; with
--deploy it becomes the current bundle. Agents older than 0.7.0 refuse such bundles (manifest "requires":
detector-3, propagation) and keep running their current one.
"""
from __future__ import annotations

import argparse
import json
import os
import time


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def upgrade(eid: str, src: dict, deploy: bool = False, device: str | None = None) -> str:
    from pdp_engine.bundle import sha256
    from pdp_engine.trainer import upgrade_bundle_07
    from pdp_server import db, learning, pki
    from pdp_server.worker import store_for
    man = json.load(open(os.path.join(src["path"], "manifest.json")))
    store = store_for(eid)
    with db.conn() as c:
        tz = (db.q(c, "SELECT config FROM endpoints WHERE id=%s", (eid,), one=True) or {}).get("config", {}).get("tz", "UTC")
        ex = learning.exclusions(c, eid, learning.day_end_ns(list(man["train_days"]) + [man["val_day"]], tz))
    reg = store.load_registry()
    nodes = learning.exclude_nodes(reg, ex) if any(ex.values()) else None
    bid = pki.new_id()
    out = os.path.join(os.path.dirname(src["path"].rstrip("/")), bid)
    upgrade_bundle_07(src["path"], out, store, node_exclude=nodes, layer_exclude=ex if any(ex.values()) else None, device=device)
    m = json.load(open(os.path.join(out, "manifest.json")))
    m.update({"bundle_id": bid, "upgraded_from": str(src["id"])})
    from pdp_engine.bundle import write_manifest
    write_manifest(out, {k: v for k, v in m.items() if k not in ("sha256", "format", "created")})
    pki.sign_bundle(out)
    manifest = json.load(open(os.path.join(out, "manifest.json")))
    with db.conn() as c:
        db.q(c, "INSERT INTO bundles (id, endpoint_id, path, sha256, manifest) VALUES (%s,%s,%s,%s,%s)",
             (bid, eid, out, sha256(os.path.join(out, "manifest.json")), json.dumps(manifest)))
        if deploy:
            db.q(c, "UPDATE endpoints SET current_bundle=%s WHERE id=%s", (bid, eid))
    log(f"bundle {src['id']} -> {bid} (0.7: detector-3, propagation, learned alerts)" + (" deployed" if deploy else ""))
    return bid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--bundle", help="source bundle id (default: the endpoint's current bundle)")
    ap.add_argument("--deploy", action="store_true")
    ap.add_argument("--device", default=None, help="cuda | cpu for the validation replay (default: the training default)")
    a = ap.parse_args()
    from pdp_server import db
    with db.conn() as c:
        ep = db.q(c, "SELECT current_bundle FROM endpoints WHERE id=%s", (a.endpoint,), one=True)
        src = db.q(c, "SELECT id, path FROM bundles WHERE id=%s", (a.bundle or ep["current_bundle"],), one=True)
    print(json.dumps({"endpoint": a.endpoint, "bundle": upgrade(a.endpoint, src, a.deploy, a.device)}))


if __name__ == "__main__":
    main()
