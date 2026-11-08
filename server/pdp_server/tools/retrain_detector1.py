"""Retrain only detector-1 (Velox) of existing bundles with the current detector-1 settings, keeping everything else.

  python -m pdp_server.tools.retrain_detector1 --endpoint <id> --bundles <id,...> [--reuse-detector1] [--deploy]

For each source bundle: detector-1 is trained again on the bundle's own baseline days with TrainConfig's current
detector-1 defaults (0.5: batch_scale input, lr 1e-3, mean of the 3 best epochs; the endpoint's own `train` overrides
of velox_* settings are ignored, so the result is what a client endpoint gets), using the bundle's featuriser and the
same seed set as the bundle's run (variant_run r -> seeds v*r .. v*r+v-1). Detector-2, the neighbour state, layers 1-2
and the alert policy are copied unchanged; the detector-1 thresholds and the fusion are re-calibrated on the bundle's
validation day (detector-2's validation scores are recomputed with its own models and stored thresholds), with the
current fusion default (0.5: max). --reuse-detector1 keeps the source bundle's detector-1 (already retrained) and only
re-calibrates the fusion. The new
bundle is signed and registered; --deploy makes it current. Used to measure the 0.5 detector-1 change in isolation
on the published benchmark bundles (artifacts/lab_v05), and as the upgrade path that needs no detector-2 GPU time.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import time

import numpy as np


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def retrain(eid: str, src: dict, device: str, deploy: bool = False, reuse: bool = False) -> str:
    import torch
    from pdp_engine.bundle import detector1_file, load_state_dict, requirements, save_state_dict, sha256, write_manifest
    from pdp_engine.featurizer import Word2VecFeaturizer
    from pdp_engine.models import OrthrusModel, TGNState, VeloxModel, load_tgn_state
    from pdp_engine.scoring import Calibration, FusionCalibration, fill_missing
    from pdp_engine.trainer import TrainConfig, Trainer
    from pdp_server import db, pki
    from pdp_server.worker import store_for
    man = json.load(open(os.path.join(src["path"], "manifest.json")))
    if (man.get("detectors") or {}).get("detector-3"):
        # the copy would keep detector-3's calibration (learned unit = the fusion's budget threshold, final threshold
        # after propagation) against a re-calibrated fusion, and drop its manifest "requires" (0.7 agents would load
        # a 0.8 bundle without its breadth evidence): retrain the pre-0.7 bundle, then upgrade it (tools.upgrade_08)
        raise SystemExit(f"bundle {src['id']} has detector-3 (0.7+): retrain detector-1 on its pre-0.7 source bundle "
                         "and upgrade the result with pdp_server.tools.upgrade_08")
    d2 = man["detectors"]["detector-2"]
    run = int(man.get("variant_run") or 0)
    cfg = TrainConfig(device=device)
    v = cfg.velox_runs
    tr = Trainer(store_for(eid), list(man["train_days"]), man["val_day"], cfg, "/tmp/unused")
    tr.feat = Word2VecFeaturizer.load(os.path.join(src["path"], "featurizer"))
    tr.x = torch.from_numpy(tr.feat.features(tr.reg.labels(), tr.reg.types())).to(tr.dev)
    if tr.N != int(man["num_nodes"]):
        raise SystemExit(f"baseline registry has {tr.N} nodes, bundle {man['num_nodes']}: not the bundle's baseline")
    models, cal1s, ratios1 = [], [], []
    d1src = man["detectors"]["detector-1"]
    if reuse and d1src.get("input") != tr.velox_input:
        raise SystemExit(f"--reuse-detector1: source detector-1 input is {d1src.get('input')}, current default {tr.velox_input}")
    for k in range(v):
        seed = v * run + k
        if reuse:
            m = VeloxModel(d1src["in_dim"], d1src["out_dim"]).to(tr.dev)
            m.load_state_dict(load_state_dict(os.path.join(src["path"], detector1_file(tr.velox_input, k))))
        else:
            m = tr.train_velox(seed)
        sc = tr.velox_val_scores(m)
        c = Calibration.from_validation(sc)
        models.append(m); cal1s.append(c); ratios1.append(fill_missing(c.ratio(sc)))
        log(f"detector-1 seed {seed}: threshold {c.threshold:.3f}")
    # detector-2 validation ratios with the bundle's own models, stored thresholds and seed weights
    cal = man["calibration"]
    ratios2 = []
    for k, c2 in enumerate(cal["detector-2"]):
        om = OrthrusModel(d2["in_dim"], hid_dim=d2["hid_dim"], out_dim=d2["out_dim"], dropout=d2["dropout"]).to(tr.dev)
        om.load_state_dict(load_state_dict(os.path.join(src["path"], f"detector-2-s{k}.npz")))
        st = TGNState(tr.N, d2["neighbor_size"], tr.dev)
        st.load_state(load_tgn_state(os.path.join(src["path"], "tgn_state_val_start.npz")))
        sc = np.full(tr.N, -np.inf, dtype=np.float32)
        with torch.no_grad():
            tr._orthrus_pass(om, None, [man["val_day"]], st, False, collect=sc)
        ratios2.append(fill_missing(sc / c2["threshold"]))
    agg = (cal.get("detector-2-aggregate") or {}).get("weights") or [1.0 / len(ratios2)] * len(ratios2)
    r1, r2 = np.mean(ratios1, axis=0), np.average(ratios2, axis=0, weights=agg)
    fcal = FusionCalibration.from_validation(r1, r2, cfg.fusion_weights, cfg.fusion_mode)
    log(f"fusion {cfg.fusion_mode} threshold {fcal.threshold:.3f}")

    bid = pki.new_id()
    out = os.path.join(os.path.dirname(src["path"].rstrip("/")), bid)
    shutil.copytree(src["path"], out)
    for f in glob.glob(os.path.join(out, "detector-1*.npz")) + [os.path.join(out, "signature.json")]:
        if os.path.exists(f):
            os.remove(f)
    for k, m in enumerate(models):
        save_state_dict(os.path.join(out, detector1_file(tr.velox_input, k)), m.state_dict())
    cal = dict(cal)
    cal["detector-1"] = {"threshold": cal1s[0].threshold, "percentiles": cal1s[0].percentiles}
    cal["detector-1-seeds"] = [{"threshold": c.threshold, "percentiles": c.percentiles} for c in cal1s]
    cal["fusion"] = {"weights": list(fcal.weights), "threshold": fcal.threshold, "percentiles": fcal.percentiles, "mode": fcal.mode}
    json.dump(cal, open(os.path.join(out, "calibration.json"), "w"), indent=1)
    meta = {k: x for k, x in man.items() if k not in ("sha256", "format", "created")}
    meta["detectors"] = dict(man["detectors"])
    meta["detectors"]["detector-1"] = d1src if reuse else {
        "in_dim": tr.velox_in_dim, "out_dim": cfg.velox_out_dim, "seeds": v, "degree_features": tr.velox_input == "window_degrees",
        "input": tr.velox_input, "lr": cfg.velox_lr, "average_top": cfg.velox_average_top}
    meta.update({"bundle_id": bid, "calibration": cal, "requires": requirements(tr.velox_input, cfg.fusion_mode),
                 ("fusion_recalibrated_from" if reuse else "detector1_retrained_from"): str(src["id"])})
    write_manifest(out, meta)
    pki.sign_bundle(out)
    manifest = json.load(open(os.path.join(out, "manifest.json")))
    with db.conn() as c:
        db.q(c, "INSERT INTO bundles (id, endpoint_id, path, sha256, manifest) VALUES (%s,%s,%s,%s,%s)",
             (bid, eid, out, sha256(os.path.join(out, "manifest.json")), json.dumps(manifest)))
        if deploy:
            db.q(c, "UPDATE endpoints SET current_bundle=%s WHERE id=%s", (bid, eid))
    log(f"bundle {src['id']} -> {bid} ({'fusion re-calibrated' if reuse else 'detector-1 retrained'})" + (" (deployed)" if deploy else ""))
    del models, tr
    torch.cuda.empty_cache()
    return bid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--bundles", required=True, help="comma-separated source bundle ids")
    ap.add_argument("--reuse-detector1", action="store_true", help="keep the source's detector-1, re-calibrate the fusion only")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--deploy", action="store_true")
    a = ap.parse_args()
    from pdp_server import db
    with db.conn() as c:
        srcs = [db.q(c, "SELECT id, path FROM bundles WHERE id=%s", (b,), one=True) for b in a.bundles.split(",")]
    if a.deploy and len(srcs) != 1:
        raise SystemExit("--deploy needs exactly one source bundle")
    out = [retrain(a.endpoint, s, a.device, a.deploy, a.reuse_detector1) for s in srcs]
    print(json.dumps({"endpoint": a.endpoint, "bundles": out}))


if __name__ == "__main__":
    main()
