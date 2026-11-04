"""Score an endpoint's alerts against client attack-suite manifests (sim/pdp_sim/suite).

  python -m pdp_server.tools.suite_eval --endpoint <id> --manifest suite-manifest.json [--manifest more.json] [--live] [--json out.json]

Ground truth is label-based: every scenario run records *markers* — strings that occur only in the labels of its own
attack entities (its private scratch path, the binaries it dropped or masqueraded as, its C2 address:port). An alert
whose entity label contains a marker of a run is an *indicator* of that run; a run is detected when at least one of
its indicators alerted. Alerts on entities that are not themselves attack artefacts but whose window-local provenance
neighbourhood (the context subgraph stored with the alert) contains attack entities — a system binary the attack
executed, the suite's own harness process — are attack *context*. Every other alert is a false positive.

--live (suite run on a real endpoint, wall-clock time): additionally reports time-to-alert = when the alert reached
the server minus the scenario start (this includes the agent's window close, up to one detection window), and only
counts false positives raised while the suite was running (± one window).
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict

from pdp_server import db

WINDOW_NS = 15 * 60 * 10**9


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n; den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (round(max(0.0, c - h), 3), round(min(1.0, c + h), 3))


def load_runs(paths: list[str]) -> list[dict]:
    runs = []
    for p in paths:
        m = json.load(open(p))
        runs.extend(m.get("runs", []))
    return runs


def _template_matcher():
    """Processes whose command line is built only from the suite's recon vocabulary (pdp_sim.suite.scenarios), e.g.
    'sh -c cat /etc/issue; uname -a; ls /tmp' or 'uname -a': run only by the attack scenarios (the benign sandbox
    workloads never execute them), but their labels carry no run marker. Returns (match(label), vocabulary)."""
    import os
    import re
    try:
        from pdp_sim.suite.scenarios import COMMAND_VOCABULARY
    except ImportError:
        return (lambda label: False), []
    voc = set(COMMAND_VOCABULARY)

    def norm(cmd: str) -> str:
        cmd = re.sub(r"\s*(2>&1|2>/dev/null|>/dev/null|>\s*\S+|\|\s*head -1)\s*", " ", cmd).strip()
        parts = cmd.split()
        if parts and parts[0].startswith("/"):
            parts[0] = os.path.basename(parts[0])
        return " ".join(parts)

    def match(label: str) -> bool:
        if not label.startswith("subject "):
            return False
        argv = label.split(" ", 2)[2] if label.count(" ") >= 2 else ""
        m = re.match(r"^(/bin/|/usr/bin/)?sh -c (.+)$", argv)
        cmds = [x for x in m.group(2).split(";")] if m else [argv]
        return bool(cmds) and all(norm(x) in voc for x in cmds if x.strip())

    return match, sorted(voc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--manifest", action="append", required=True)
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()
    runs = load_runs(a.manifest)
    with db.conn() as c:
        alerts = db.q(c, "SELECT a.node_uuid, a.label, a.ntype, a.fused, a.window_start_ns, extract(epoch from a.created_at) AS at, a.context, "
                         "coalesce(a.layer, 'learned') AS layer, a.rule FROM alerts a WHERE a.endpoint_id=%s",
                      (a.endpoint,))
    if a.live and runs:
        lo = min(r["start_ns"] for r in runs) - WINDOW_NS; hi = max(r["end_ns"] for r in runs) + 2 * WINDOW_NS
        alerts = [x for x in alerts if lo <= int(x["window_start_ns"]) <= hi]
    hits = defaultdict(list)           # run index -> alerts
    fps, context, template = [], [], []
    is_template, _voc = _template_matcher()
    template_exes = set()
    for al in alerts:
        lab = al["label"] or ""
        owners = [i for i, r in enumerate(runs) if any(m and m in lab for m in r["markers"])]
        for i in owners:
            hits[i].append(al)
        if not owners:
            # attack context: the alerted entity is not itself an attack artefact (e.g. /bin/sh executed by the attack,
            # the suite harness) but its window-local provenance neighbourhood contains this window's attack entities
            ctx_labels = [n.get("label", "") for n in ((al.get("context") or {}).get("nodes") or [])]
            linked = [i for i, r in enumerate(runs) if any(m and m in cl for cl in ctx_labels for m in r["markers"])]
            if linked or "pdp_sim.suite" in lab or "pdp_sim.sandbox" in lab:
                context.append(al)
            elif is_template(lab):
                template.append(al)
                parts = lab.split(" ")
                template_exes.add(f"file {parts[1]}")
            else:
                fps.append(al)
    # the binaries those recon commands executed (e.g. 'file /usr/bin/uname'), flagged next to them
    moved = [x for x in fps if x["label"] in template_exes]
    fps = [x for x in fps if x["label"] not in template_exes]
    template += moved
    rows, by_sc, by_tac = [], defaultdict(lambda: [0, 0]), defaultdict(lambda: [0, 0])
    for i, r in enumerate(runs):
        h = hits.get(i, [])
        det = bool(h)
        row = {"scenario": r["scenario"], "tactic": r["tactic"], "techniques": r["techniques"], "detected": det,
               "indicators": sorted({x["label"][:90] for x in h})[:6], "max_fused": round(max((float(x["fused"]) for x in h), default=0.0), 2),
               "layers": sorted({x["layer"] for x in h}), "rules": sorted({x["rule"] for x in h if x["rule"]})}
        if a.live and det:
            row["time_to_alert_s"] = round(min(float(x["at"]) for x in h) - r["start_ns"] / 1e9, 1)
        rows.append(row)
        by_sc[r["scenario"]][0] += det; by_sc[r["scenario"]][1] += 1
        by_tac[r["tactic"]][0] += det; by_tac[r["tactic"]][1] += 1
    k, n = sum(x["detected"] for x in rows), len(rows)
    out = {"endpoint": a.endpoint, "scenario_runs": n, "detected": k, "detection_rate": round(k / n, 3) if n else None,
           "detection_rate_ci95": wilson(k, n),
           "by_scenario": {s: {"detected": v[0], "runs": v[1], "rate": round(v[0] / v[1], 2)} for s, v in sorted(by_sc.items())},
           "by_tactic": {t: {"detected": v[0], "runs": v[1], "rate": round(v[0] / v[1], 2)} for t, v in sorted(by_tac.items())},
           # which layer would have caught each run on its own (a run can be caught by several)
           "detected_by_layer": {l: sum(1 for x in rows if l in x["layers"]) for l in ("novelty", "rules", "corroborated", "learned")},
           "false_positive_nodes": len({x["node_uuid"] for x in fps}), "false_positive_labels": sorted({x["label"][:80] for x in fps})[:20],
           "false_positive_nodes_by_layer": {l: len({x["node_uuid"] for x in fps if x["layer"] == l}) for l in ("novelty", "rules", "corroborated", "learned")},
           "context_alerts": len(context), "context_nodes": len({x["node_uuid"] for x in context}),
           # attack recon processes recognised by the suite's command vocabulary (not counted as hits or false positives)
           "suite_command_nodes": len({x["node_uuid"] for x in template}),
           "suite_command_labels": sorted({x["label"][:70] for x in template})[:15],
           "context_labels": sorted({x["label"][:60] for x in context})[:15], "runs": rows}
    if a.live:
        tt = sorted(x["time_to_alert_s"] for x in rows if "time_to_alert_s" in x)
        out["median_time_to_alert_s"] = tt[len(tt) // 2] if tt else None
    print(json.dumps(out, indent=1, default=str))
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
