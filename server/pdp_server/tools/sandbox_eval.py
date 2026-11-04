"""Evaluate a sandbox (strace) live endpoint: classify its reported alerts as attack indicators or benign
false positives by signature, and report detection per attack scenario and the benign false-positive rate.

  python -m pdp_server.tools.sandbox_eval --endpoint <id> [--json out.json]

The sandbox scenarios are harmless but reproduce DARPA provenance shapes; their distinctive nodes are the only
ground truth available on a live endpoint (which never uploads telemetry). Signatures below match those nodes.
"""
from __future__ import annotations

import argparse
import json
import re

from pdp_server import db

# Realistic attack indicators (the nodes a defender would act on): the dropped payload, the recon shell, the
# external command-and-control endpoints. These decide whether a scenario was detected.
INDICATORS = [
    ("dropper", re.compile(r"update\.sh")),
    ("dropper", re.compile(r"203\.0\.113\.\d+ 4444")),
    ("backdoor", re.compile(r"/etc/shadow")),
    ("backdoor", re.compile(r"203\.0\.113\.\d+ 8080")),
    ("exfil", re.compile(r"arch\.tar")),
    ("exfil", re.compile(r"(203\.0\.113|198\.51\.100)\.\d+ 443")),
    ("lotl", re.compile(r"(203\.0\.113|198\.51\.100)\.\d+ 53")),
    ("lotl", re.compile(r"subject \S*/(whoami|uname) ")),
]
# Attack-context nodes: shared executables and the harness driver that only alerted inside the attack subgraph.
# They are neither realistic indicators nor benign false positives; the honest FP measure is benign-window alerts.
CONTEXT = re.compile(r"sandbox\.workloads (dropper|backdoor|exfil|lotl)|/bin/sh$|/usr/bin/id$|subject \S*/id id")
SCENARIOS = ["dropper", "backdoor", "exfil", "lotl"]


def classify(label: str):
    for scenario, rx in INDICATORS:
        if rx.search(label):
            return scenario
    if CONTEXT.search(label):
        return "context"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()
    with db.conn() as c:
        rows = db.q(c, "SELECT node_uuid, label, ntype, max(fused) AS fused, min(window_start_ns) AS w FROM alerts WHERE endpoint_id=%s GROUP BY node_uuid, label, ntype", (a.endpoint,))
        wins = db.q(c, "SELECT count(*) AS n, coalesce(sum(alerts),0) AS alerts, max(max_fused) AS mx FROM windows WHERE endpoint_id=%s", (a.endpoint,), one=True)
    alerts = [dict(r, fused=float(r["fused"])) for r in rows]
    tagged = [(r, classify(r["label"])) for r in alerts]
    indicators = [r for r, s in tagged if s and s != "context"]
    context = [r for r, s in tagged if s == "context"]
    unknown = [r for r, s in tagged if not s]
    detected = {s for _, s in tagged if s and s != "context"}
    # a window is "benign" if none of its alerts are attack indicators; alerts there are genuine false positives
    attack_windows = {r["w"] for r in indicators} | {r["w"] for r in context}
    benign_fp = [r for r in alerts if r["w"] not in attack_windows]
    res = {
        "endpoint": a.endpoint,
        "windows": dict(wins),
        "alerts": len(alerts),
        "attack_indicator_nodes": len(indicators),
        "attack_context_nodes": len(context),
        "benign_window_false_positives": len(benign_fp),
        "unclassified_nodes": len(unknown),
        "scenarios_detected": {s: s in detected for s in SCENARIOS},
        "detection_count": sum(1 for s in SCENARIOS if s in detected),
        "indicators": sorted({f"{classify(r['label'])}: {r['label'][:70]} (fused {r['fused']:.2f})" for r in indicators}),
        "context_labels": sorted({r["label"][:70] for r in context}),
        "benign_fp_labels": sorted({r["label"][:70] for r in benign_fp}),
    }
    print(json.dumps(res, indent=1, default=str))
    if a.json:
        json.dump(res, open(a.json, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
