"""Benchmark evaluation of a benchmark endpoint's reported alerts against the DARPA ground truth.

  python -m pdp_server.tools.bench_eval --endpoint <id> --dataset CADETS_E3 [--days 2018-04-06,2018-04-11,2018-04-12,2018-04-13]

Ground-truth node ids come from the transplant files (sim/attacks/<dataset>_*.json, entities with gt=true), whose
uuids are the framework index ids the benchmark agent uses as entity uuids.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from pdp_server import db

TEST_DAYS = {"CADETS_E3": ["2018-04-06", "2018-04-11", "2018-04-12", "2018-04-13"], "THEIA_E3": ["2018-04-10", "2018-04-12", "2018-04-13"]}
ATTACK_DIR = os.environ.get("PDP_ATTACK_DIR", "/opt/pdp/sim/attacks")


def bounds(day: str, tz: str):
    d0 = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=ZoneInfo(tz))
    return int(d0.timestamp() * 1e9), int((d0 + timedelta(days=1)).timestamp() * 1e9)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True); ap.add_argument("--dataset", required=True); ap.add_argument("--days"); ap.add_argument("--json")
    a = ap.parse_args()
    days = a.days.split(",") if a.days else TEST_DAYS[a.dataset]
    gt = {}
    for f in sorted(glob.glob(os.path.join(ATTACK_DIR, f"{a.dataset}_*.json"))):
        d = json.load(open(f))
        gt[d["name"]] = {u for u, e in d["entities"].items() if e.get("gt")}
    all_gt = set().union(*gt.values()) if gt else set()
    with db.conn() as c:
        ep = db.q(c, "SELECT config FROM endpoints WHERE id=%s", (a.endpoint,), one=True)
        tz = ep["config"].get("tz", "UTC")
        flagged, per_day, windows = {}, {}, {}
        for day in days:
            t0, t1 = bounds(day, tz)
            rows = db.q(c, "SELECT node_uuid, label, max(fused) AS fused, max(r1) AS r1, max(r2) AS r2 FROM alerts WHERE endpoint_id=%s AND window_start_ns >= %s AND window_start_ns < %s GROUP BY node_uuid, label", (a.endpoint, t0, t1))
            w = db.q(c, "SELECT count(*) AS n, coalesce(sum(alerts),0) AS alerts FROM windows WHERE endpoint_id=%s AND start_ns >= %s AND start_ns < %s", (a.endpoint, t0, t1), one=True)
            windows[day] = dict(w)
            per_day[day] = [dict(r) for r in rows]
            for r in rows:
                flagged[r["node_uuid"]] = dict(r)
    tp = {u for u in flagged if u in all_gt}
    fp = {u for u in flagged if u not in all_gt}
    res = {"endpoint": a.endpoint, "dataset": a.dataset, "days": days, "windows": windows, "flagged_nodes": len(flagged), "gt_nodes": len(all_gt),
           "tp": len(tp), "fp": len(fp), "precision": len(tp) / len(flagged) if flagged else None, "recall": len(tp) / len(all_gt) if all_gt else None,
           "attacks": {name: {"gt": len(ids), "flagged": len(ids & set(flagged)), "detected": bool(ids & set(flagged))} for name, ids in gt.items()},
           "per_day_alerts": {d: len(v) for d, v in per_day.items()}, "fp_labels": sorted({flagged[u]["label"][:60] for u in fp})[:40]}
    print(json.dumps(res, indent=1, default=str))
    if a.json:
        json.dump(res, open(a.json, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
