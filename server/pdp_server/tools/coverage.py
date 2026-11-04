"""Detection coverage per release: run the same offline simulation campaign (sim/: synthetic and transplanted DARPA
attack graphs injected into a reference endpoint's recorded benign windows and scored by the real detector; nothing
is executed on any host) with a fixed suite and seed at every release, keep the result, and compare releases.

  python -m pdp_server.tools.coverage record --release 0.6.1 --endpoint <reference endpoint id> [--suite FILE] [--seed 20261104]
  python -m pdp_server.tools.coverage compare [--release 0.6.1]          exit 1 on a regression
  python -m pdp_server.tools.coverage list

A comparison is only made between releases measured with the same suite (spec hash) on the same endpoint. A
regression: overall detection down by more than max(5 points, the confidence interval half-width), any attack family
down by 20 points or more, or false positives per day up by more than 50% (and at least 1 per day).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

DEFAULT_SUITE = os.environ.get("PDP_COVERAGE_SUITE", "/opt/pdp/sim/suites/client_acceptance.json")
DEFAULT_SEED = 20261104


def regressions(prev: dict, cur: dict) -> list[str]:
    """Human-readable regressions of `cur` against `prev` (coverage_history rows: detection_rate, ci, fp_per_day,
    by_family [{family, fused: {rate}}])."""
    out = []
    p, c = prev.get("detection_rate"), cur.get("detection_rate")
    if p is not None and c is not None:
        ci = cur.get("ci") or [c, c]
        half = (ci[1] - ci[0]) / 2 if ci and None not in ci else 0.0
        if p - c > max(0.05, half):
            out.append(f"overall detection {p:.0%} -> {c:.0%}")
    pf = {f["family"]: (f.get("fused") or {}).get("rate") for f in prev.get("by_family") or []}
    for f in cur.get("by_family") or []:
        a, b = pf.get(f["family"]), (f.get("fused") or {}).get("rate")
        if a is not None and b is not None and a - b >= 0.20:
            out.append(f"{f['family']}: {a:.0%} -> {b:.0%}")
    fa, fb = prev.get("fp_per_day"), cur.get("fp_per_day")
    if fa is not None and fb is not None and fb > max(fa * 1.5, fa + 1):
        out.append(f"false positives per day {fa:.1f} -> {fb:.1f}")
    return out


def _db():
    from pdp_server import db
    return db


def record(release: str, endpoint: str, suite: str, seed: int, timeout_h: float = 6) -> dict:
    from pdp_server import pki
    db = _db()
    spec = json.load(open(suite))
    spec["seed"] = seed
    cid = pki.new_id()
    with db.conn() as c:
        ep = db.q(c, "SELECT id, current_bundle, agent_version FROM endpoints WHERE id=%s", (endpoint,), one=True)
        if not ep or not ep["current_bundle"]:
            sys.exit("the reference endpoint does not exist or has no trained model")
        db.q(c, "INSERT INTO sim_campaigns (id, name, endpoint_id, bundle_id, spec, seed, state) VALUES (%s,%s,%s,%s,%s,%s,'queued')",
             (cid, f"coverage {release}", endpoint, ep["current_bundle"], json.dumps(spec), seed))
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, params) VALUES (%s,%s,'sim',%s)", (pki.new_id(), endpoint, json.dumps({"campaign_id": cid})))
    print(f"campaign {cid} queued (suite {os.path.basename(suite)}, seed {seed}); waiting for the worker", flush=True)
    end = time.time() + timeout_h * 3600
    while time.time() < end:
        with db.conn() as c:
            camp = db.q(c, "SELECT state, spec FROM sim_campaigns WHERE id=%s", (cid,), one=True)
            job = db.q(c, "SELECT state, error FROM jobs WHERE params->>'campaign_id'=%s", (cid,), one=True)
        if camp["state"] == "done":
            break
        if job and job["state"] == "failed":
            sys.exit(f"campaign failed: {job.get('error')}")
        time.sleep(30)
    else:
        sys.exit("timed out waiting for the campaign")
    s = camp["spec"]["summary"]
    row = {"release": release, "campaign_id": cid, "endpoint_id": endpoint, "bundle_id": str(ep["current_bundle"]),
           "spec_hash": s.get("spec_hash"), "detection_rate": s.get("detection_rate"), "ci": s.get("detection_rate_ci"),
           "fp_per_day": s.get("fp_per_day"), "by_family": s.get("by_family"), "by_evasion": s.get("by_evasion"), "agent_version": ep["agent_version"]}
    with db.conn() as c:
        db.q(c, "INSERT INTO coverage_history (release, campaign_id, endpoint_id, bundle_id, spec_hash, detection_rate, ci, fp_per_day, by_family, by_evasion, agent_version) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (release, endpoint_id) DO UPDATE SET campaign_id=excluded.campaign_id, "
                "bundle_id=excluded.bundle_id, spec_hash=excluded.spec_hash, detection_rate=excluded.detection_rate, ci=excluded.ci, "
                "fp_per_day=excluded.fp_per_day, by_family=excluded.by_family, by_evasion=excluded.by_evasion, agent_version=excluded.agent_version, created_at=now()",
             (release, cid, endpoint, row["bundle_id"], row["spec_hash"], row["detection_rate"], json.dumps(row["ci"]), row["fp_per_day"],
              json.dumps(row["by_family"], default=str), json.dumps(row["by_evasion"], default=str), row["agent_version"]))
    return row


def history() -> list[dict]:
    db = _db()
    with db.conn() as c:
        return db.q(c, "SELECT * FROM coverage_history ORDER BY created_at")


def previous(rows: list[dict], cur: dict) -> dict | None:
    same = [r for r in rows if r["endpoint_id"] == cur["endpoint_id"] and r["spec_hash"] == cur["spec_hash"] and r["created_at"] < cur["created_at"]]
    return same[-1] if same else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record"); r.add_argument("--release", required=True); r.add_argument("--endpoint", required=True)
    r.add_argument("--suite", default=DEFAULT_SUITE); r.add_argument("--seed", type=int, default=DEFAULT_SEED)
    c = sub.add_parser("compare"); c.add_argument("--release")
    sub.add_parser("list")
    a = ap.parse_args(argv)
    if a.cmd == "record":
        row = record(a.release, a.endpoint, a.suite, a.seed)
        print(f"{a.release}: detection {row['detection_rate']:.0%} (CI {row['ci']}), {row['fp_per_day']:.1f} false positives/day")
        return 0
    rows = history()
    if a.cmd == "list":
        for x in rows:
            print(f"{x['release']:<10} {x['created_at']:%Y-%m-%d}  detection {x['detection_rate']:.0%}  fp/day {x['fp_per_day']:.1f}  "
                  f"endpoint {str(x['endpoint_id'])[:8]}  suite {str(x['spec_hash'])[:8]}")
        return 0
    cur = [x for x in rows if x["release"] == a.release] if a.release else rows[-1:]
    if not cur:
        sys.exit("no coverage recorded for that release")
    cur = cur[-1]
    prev = previous(rows, cur)
    if not prev:
        print(f"{cur['release']}: first measurement with this suite and endpoint; nothing to compare")
        return 0
    bad = regressions(prev, cur)
    print(f"{prev['release']} -> {cur['release']}: detection {prev['detection_rate']:.0%} -> {cur['detection_rate']:.0%}, "
          f"fp/day {prev['fp_per_day']:.1f} -> {cur['fp_per_day']:.1f}")
    for b in bad:
        print("REGRESSION", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
