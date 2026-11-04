"""Calibrate the detector fusion of a bundle with simulated attacks on its benign validation day (no test data).

  python -m pdp_server.tools.calibrate_fusion --endpoint <id> [--bundle <id>] [--runs 140] [--per-pass 4] [--seed 0]

The default fusion weights detector-1 : detector-2 as 2 : 1 for every endpoint. Which detector separates attacks
better depends on the endpoint (CADETS vs THEIA differ), so this picks the weighting per bundle, label-free with
respect to real attacks:

  1. Candidates w1 : w2 in {1:0, 3:1, 2:1, 1:1, 1:2, 1:3, 0:1}.
  2. Threshold of each candidate exactly as the trainer calibrates the deployed fusion: the maximum over the
     validation-day nodes of (w1 r1 + w2 r2) / (w1 + w2), with r = node score / detector threshold (per-node maxima
     over the day). By construction no candidate alerts on the benign validation day.
  3. A randomised campaign of *synthetic* attack families (pdp_sim.attacks; no DARPA transplants, which come from the
     evaluation datasets) at all evasion levels, injected into the validation day and scored with the bundle; an
     attack counts as detected under a candidate if a malicious node's per-window fused score exceeds its threshold.
  4. The candidate with the highest detection rate wins (ties: larger median margin, then closest to 2 : 1).

A new bundle is written with the chosen fusion (weights + threshold + percentiles), signed and registered; with
--deploy it becomes the endpoint's current bundle (the agent fetches and verifies it on its next poll).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import time

import numpy as np

CANDIDATES = [(1.0, 0.0), (3.0, 1.0), (2.0, 1.0), (1.0, 1.0), (1.0, 2.0), (1.0, 3.0), (0.0, 1.0)]
SYNTHETIC = ["web_backdoor", "browser_dropper", "lotl_recon", "priv_esc_lateral", "exfiltration", "ransomware", "script_c2"]
LEVELS = ["none", "low", "medium", "high", "stealth"]


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def fuse(w, r1, r2):
    return (w[0] * r1 + w[1] * r2) / (w[0] + w[1])


def calibrate(store, bundle_dir: str, runs: int = 140, per_pass: int = 4, seed: int = 0, device: str = "cuda") -> dict:
    from pdp_sim.campaign import Campaign, Spec
    from pdp_sim.inject import LabelIndex, inject
    from pdp_engine.scoring import ALERT_MARGIN
    spec = Spec(days=["validation"], runs=runs, attacks_per_pass=per_pass, families=SYNTHETIC, evasion_levels=LEVELS, seed=seed, horizon_windows=6)
    camp = Campaign(spec, store, bundle_dir, device=device, log=log)
    day = camp.val_day
    ws = camp.windows(day)
    # ---- clean validation pass: per-node maxima of r1, r2 (the trainer's calibration statistic)
    rt = camp.rt
    rt.reset(camp._copy_registry(), at="validation")
    m1, m2 = {}, {}
    for w in ws:
        r = rt.score(w)
        for n, a, b in zip(r.node_ids.tolist(), r.r1.tolist(), r.r2.tolist()):
            m1[n] = max(m1.get(n, 0.0), a); m2[n] = max(m2.get(n, 0.0), b)
    nodes = list(m1)
    R1 = np.array([m1[n] for n in nodes]); R2 = np.array([m2[n] for n in nodes])
    thr = {w: float(fuse(w, R1, R2).max()) for w in CANDIDATES}
    log(f"clean validation pass: {len(nodes)} nodes; thresholds " + ", ".join(f"{int(a)}:{int(b)}={t:.3f}" for (a, b), t in thr.items()))
    # ---- attack passes: per attack, the (r1, r2) pairs of its malicious nodes in the horizon windows
    attacks = []
    for pi, ps in enumerate(camp.plan()):
        reg = camp._copy_registry(); index = LabelIndex(reg)
        placed = [camp.build(dict(a, day=day), ws, reg, index, f"cal{pi}-{a['window_index']}") + (a,) for a in ps["attacks"]]
        rebuilt = inject(ws, [e for p, g, a in placed for e in p.edges])
        ws2 = [rebuilt.get(i, w) for i, w in enumerate(ws)]
        rt.reset(reg, at="validation")
        pairs = [[] for _ in placed]
        for i, w in enumerate(ws2):
            r = rt.score(w)
            pos = {int(n): j for j, n in enumerate(r.node_ids)}
            for k, (p, g, a) in enumerate(placed):
                if p.window_index <= i <= p.window_index + spec.horizon_windows:
                    for mnode in p.malicious_ids:
                        j = pos.get(mnode)
                        if j is not None:
                            pairs[k].append((float(r.r1[j]), float(r.r2[j])))
        for (p, g, a), pr in zip(placed, pairs):
            attacks.append({"family": a["family"], "evasion": a["evasion"], "pairs": np.array(pr) if pr else np.zeros((0, 2))})
        if (pi + 1) % 5 == 0:
            log(f"pass {pi + 1}: {len(attacks)} attacks scored")
    # ---- choose the weighting
    table = []
    for w in CANDIDATES:
        margins = [float(fuse(w, x["pairs"][:, 0], x["pairs"][:, 1]).max() / thr[w]) if len(x["pairs"]) else 0.0 for x in attacks]
        det = [mg > 1.0 + ALERT_MARGIN for mg in margins]
        table.append({"weights": list(w), "threshold": thr[w], "detection_rate": round(float(np.mean(det)), 4),
                      "median_margin": round(float(np.median(margins)), 4),
                      "by_family": {f: round(float(np.mean([d for d, x in zip(det, attacks) if x["family"] == f])), 2) for f in SYNTHETIC}})
    dist = lambda w: abs(np.log((w[0] + 1e-3) / (w[1] + 1e-3)) - np.log(2.0))
    best = max(table, key=lambda t: (t["detection_rate"], t["median_margin"], -dist(t["weights"])))
    fz = fuse(tuple(best["weights"]), R1, R2)
    best["percentiles"] = {p: float(np.percentile(fz, float(p))) for p in ("99", "99.9", "99.99")}
    return {"validation_day": day, "attacks": len(attacks), "candidates": table, "chosen": best}


def apply_to_bundle(bundle_dir: str, res: dict, source_bundle: str | None = None) -> None:
    """Write a calibration result into an (unsigned) bundle directory: calibration.json + manifest digests."""
    from pdp_engine.bundle import write_manifest
    ch = res["chosen"]
    man = json.load(open(os.path.join(bundle_dir, "manifest.json")))
    cal = man["calibration"]
    cal["fusion"] = {"weights": ch["weights"], "threshold": ch["threshold"], "percentiles": ch["percentiles"],
                     "calibrated_by": "simulation", "source_bundle": source_bundle}
    json.dump(cal, open(os.path.join(bundle_dir, "calibration.json"), "w"), indent=1)
    meta = {k: v for k, v in man.items() if k not in ("sha256", "format", "created")}
    meta.update({"calibration": cal, "fusion_calibration": {k: res[k] for k in ("validation_day", "attacks", "candidates")}})
    sig = os.path.join(bundle_dir, "signature.json")
    if os.path.exists(sig):
        os.remove(sig)
    write_manifest(bundle_dir, meta)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True); ap.add_argument("--bundle")
    ap.add_argument("--runs", type=int, default=140); ap.add_argument("--per-pass", type=int, default=4)
    ap.add_argument("--seed", type=int, default=0); ap.add_argument("--device", default="cuda")
    ap.add_argument("--deploy", action="store_true"); ap.add_argument("--json")
    a = ap.parse_args()
    from pdp_engine.bundle import sha256, write_manifest
    from pdp_server import db, pki
    from pdp_server.worker import store_for
    with db.conn() as c:
        ep = db.q(c, "SELECT current_bundle FROM endpoints WHERE id=%s", (a.endpoint,), one=True)
        src = db.q(c, "SELECT id, path FROM bundles WHERE id=%s", (a.bundle or ep["current_bundle"],), one=True)
    res = calibrate(store_for(a.endpoint), src["path"], a.runs, a.per_pass, a.seed, a.device)
    for t in res["candidates"]:
        log(f"  w {t['weights']}: detection {t['detection_rate']:.3f} median margin {t['median_margin']:.3f}")
    ch = res["chosen"]
    log(f"chosen fusion weights {ch['weights']} (synthetic detection {ch['detection_rate']:.3f})")
    # ---- new signed bundle with the calibrated fusion
    bid = pki.new_id()
    out = os.path.join(os.path.dirname(src["path"].rstrip("/")), bid)
    shutil.copytree(src["path"], out)
    apply_to_bundle(out, res, source_bundle=str(src["id"]))
    man = json.load(open(os.path.join(out, "manifest.json")))
    man["bundle_id"] = bid
    write_manifest(out, {k: v for k, v in man.items() if k not in ("sha256", "format", "created")})
    pki.sign_bundle(out)
    manifest = json.load(open(os.path.join(out, "manifest.json")))
    with db.conn() as c:
        db.q(c, "INSERT INTO bundles (id, endpoint_id, path, sha256, manifest) VALUES (%s,%s,%s,%s,%s)",
             (bid, a.endpoint, out, sha256(os.path.join(out, "manifest.json")), json.dumps(manifest)))
        if a.deploy:
            db.q(c, "UPDATE endpoints SET current_bundle=%s WHERE id=%s", (bid, a.endpoint))
    res["bundle"] = bid
    print(json.dumps({"bundle": bid, "chosen": ch["weights"], "candidates": [(t["weights"], t["detection_rate"]) for t in res["candidates"]]}))
    if a.json:
        json.dump(res, open(a.json, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
