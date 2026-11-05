"""Evaluate a DARPA TC benchmark endpoint the way the research papers do (PIDSMaker node-level evaluation).

  python -m pdp_server.tools.darpa_eval --endpoint <id> --dataset CADETS_E3 --gt-dir /gt/orthrus [--bundles all] [--json out.json]

Two views, both against the ORTHRUS ground truth (one CSV per attack: uuid, labels, index_id):

  product   the alerts the endpoint's agent actually reported for the test days (what a customer sees)
  rescore   every test-day window re-scored with the same signed bundle on the GPU, giving each node's maximum score
            for the fused detector and for detector-1 / detector-2 alone; needed for the threshold-free metrics

Node-level protocol (PIDSMaker `node_evaluation`): the evaluated nodes are all nodes in the test-day windows; a
node's score is its maximum over those windows; it is predicted malicious when the score exceeds the threshold
(maximum validation-day score; 1.0 in the runtime's threshold units, plus the float32 margin); y_true = the node is
in the ground truth. Metrics: TP, FP, FN, TN, precision, recall, MCC, attacks with >= 1 TP, and ADP (area under the
"% of attacks detected vs precision" curve over the node ranking; PIDSMaker `plot_detected_attacks_vs_precision`).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import time
from collections import defaultdict

import numpy as np

from pdp_server import db

DATASETS = {
    "CADETS_E3": {"database": "cadets_e3", "test": ["2018-04-06", "2018-04-11", "2018-04-12", "2018-04-13"],
                  "gt": ["E3-CADETS/node_Nginx_Backdoor_06.csv", "E3-CADETS/node_Nginx_Backdoor_12.csv", "E3-CADETS/node_Nginx_Backdoor_13.csv"]},
    "THEIA_E3": {"database": "theia_e3", "test": ["2018-04-10", "2018-04-12", "2018-04-13"],
                 "gt": ["E3-THEIA/node_Browser_Extension_Drakon_Dropper.csv", "E3-THEIA/node_Firefox_Backdoor_Drakon_In_Memory.csv"]},
    # DARPA OpTC (Windows), PIDSMaker's split: train 2019-09-19..21, validation 09-22, test 09-23..25; one attack per host
    "OPTC_H201": {"database": "optc_201", "test": ["2019-09-23", "2019-09-24", "2019-09-25"], "gt": ["h201/node_h201_0923.csv"]},
    "OPTC_H501": {"database": "optc_501", "test": ["2019-09-23", "2019-09-24", "2019-09-25"], "gt": ["h501/node_h501_0924.csv"]},
    "OPTC_H051": {"database": "optc_051", "test": ["2019-09-23", "2019-09-24", "2019-09-25"], "gt": ["h051/node_h051_0925.csv"]},
}


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def load_gt(gt_dir: str, files: list[str]) -> dict[str, set[str]]:
    """attack name -> set of entity uuids (the framework index id, which the replay uses as the entity uuid)."""
    out = {}
    for f in files:
        ids = set()
        for row in csv.reader(open(os.path.join(gt_dir, f))):
            if len(row) >= 3 and row[2].strip():
                ids.add(row[2].strip())
        out[os.path.basename(f)[5:-4]] = ids
    return out


def adp(scores: np.ndarray, labels: np.ndarray, node_attacks: list[set]) -> float:
    """PIDSMaker's attack detection precision (area under % attacks detected vs precision)."""
    total = len(set().union(*[a for a in node_attacks if a])) or 1
    order = np.argsort(-scores, kind="stable")
    tp = fp = 0
    detected = set()
    prec_to_det = defaultdict(float)
    prec_to_det[0.0] = 0.0
    for i in order:
        if labels[i]:
            tp += 1
            detected |= node_attacks[i]
        else:
            fp += 1
        p = tp / (tp + fp)
        prec_to_det[p] = max(prec_to_det[p], 100.0 * len(detected) / total)
    xs = sorted(prec_to_det)
    ys = [prec_to_det[x] for x in xs]
    return float(np.trapz(ys, xs) / 100.0)


def metrics(pred: np.ndarray, labels: np.ndarray, node_attacks: list[set], n_attacks: int) -> dict:
    tp = int((pred & labels).sum()); fp = int((pred & ~labels).sum())
    fn = int((~pred & labels).sum()); tn = int((~pred & ~labels).sum())
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) or 1.0
    det = set()
    for i in np.where(pred & labels)[0]:
        det |= node_attacks[i]
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0,
            "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0, "MCC": round((tp * tn - fp * fn) / den, 3),
            "attacks_detected": f"{len(det)}/{n_attacks}"}


def rescore(eid: str, ep: dict, bundle_dir: str, test_days: list[str], device: str):
    """Max fused / r1 / r2 per node over the test-day windows, replaying the days in order from the bundle's state."""
    from pdp_engine.data import WindowStore, ingest_day
    from pdp_engine.runtime import Runtime
    from pdp_engine.sources.pg_replay import PostgresReplay
    from pdp_server.worker import DATA_DIR, store_for
    import shutil
    base = store_for(eid)
    bid = os.path.basename(bundle_dir.rstrip("/"))
    ev_root = os.path.join(DATA_DIR, "endpoints", eid, "eval-test")     # test days ingested once, shared by all bundles
    store = WindowStore(ev_root)
    if not os.path.exists(os.path.join(ev_root, "registry.json")):
        shutil.copy(os.path.join(base.root, "registry.json"), os.path.join(ev_root, "registry.json"))
    cfg = ep["config"]
    src = None
    for d in test_days:
        if d in store.days():
            continue
        src = src or PostgresReplay(cfg["dataset"], host=cfg.get("dataset_host", "postgres"))
        lookup = getattr(rescore, "_lookup", None) or src.entity_index(); rescore._lookup = lookup
        reg = store.load_registry()
        n = store.add_day(d, ingest_day(reg, src.events(d), lookup, window_ns=int(float(cfg.get("window_minutes", 15)) * 60e9)))
        store.save_registry(reg)
        log(f"ingested test day {d}: {n} windows, registry {len(reg)}")
    reg = store.load_registry()
    rt = Runtime(bundle_dir, reg, device=device, feat_device=device)
    best = {k: np.full(len(reg), -np.inf, dtype=np.float32) for k in ("fused", "r1", "r2")}
    flags = {k: np.zeros(len(reg), dtype=bool) for k in LAYERS}       # alerted by each layer (product policy)
    # the pre-registered policy (every layer-2 rule alarms on its own), on exactly the same learned scores
    pre = None
    if rt.layers is not None:
        from pdp_engine.layers import DeterministicLayers
        from pdp_engine.runtime import AlertPolicy
        pre = AlertPolicy(DeterministicLayers(rt.layers.spec, rt.m["num_nodes"]), rt.daily_budget, rt.corroboration, evidence_rules=())
    flags_pre = {k: np.zeros(len(reg), dtype=bool) for k in LAYERS}
    seen = np.zeros(len(reg), dtype=bool)
    nw = 0
    for d in test_days:
        for w in store.windows(d):
            r = rt.score(w)
            ids = r.node_ids
            seen[ids] = True
            for k, v in (("fused", r.fused), ("r1", r.r1), ("r2", r.r2)):
                np.maximum.at(best[k], ids, v.astype(np.float32))
            for n, rs in r.reasons.items():
                for x in rs:
                    if x["layer"] in flags:          # "evidence" entries explain a corroborated alert, they are not one
                        flags[x["layer"]][n] = True
            if pre is not None:
                for n, rs in pre.apply(w, reg, r.node_ids, r.fused)[1].items():
                    for x in rs:
                        if x["layer"] in flags_pre:
                            flags_pre[x["layer"]][n] = True
            nw += 1
    log(f"bundle {bid}: re-scored {nw} test windows, {int(seen.sum())} test nodes; layered alerts "
        + ", ".join(f"{k}={int(v.sum())}" for k, v in flags.items()) + ("" if rt.layers is not None else " (bundle without layers)"))
    best["layers"] = flags
    best["layers_pre"] = flags_pre
    best["has_layers"] = rt.layers is not None
    return reg, seen, best


LAYERS = ("novelty", "rules", "corroborated", "learned")


def product_priority(fused: np.ndarray, flags: dict) -> np.ndarray:
    """The product's triage order as a ranking score: deterministic alerts (novelty / rules) first, then corroborated,
    then budgeted learned alerts, then every other node; ties broken by the fused learned score."""
    f = np.where(np.isfinite(fused), fused, 0.0)
    tier = np.where(flags["novelty"] | flags["rules"], 3, np.where(flags["corroborated"], 2, np.where(flags["learned"], 1, 0)))
    return tier * 1e6 + np.clip(f, 0, 1e5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--dataset", required=True, choices=list(DATASETS))
    ap.add_argument("--gt-dir", default=os.environ.get("PDP_GT_DIR", "/gt/orthrus"))
    ap.add_argument("--bundles", default="current", help="current | all | comma-separated bundle ids")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--json")
    a = ap.parse_args()
    D = DATASETS[a.dataset]
    gt = load_gt(a.gt_dir, D["gt"])
    all_gt = set().union(*gt.values())
    with db.conn() as c:
        ep = db.q(c, "SELECT * FROM endpoints WHERE id=%s", (a.endpoint,), one=True)
        if a.bundles == "current":
            bundles = [db.q(c, "SELECT id, path, manifest FROM bundles WHERE id=%s", (ep["current_bundle"],), one=True)]
        elif a.bundles == "all":
            bundles = db.q(c, "SELECT id, path, manifest FROM bundles WHERE endpoint_id=%s ORDER BY created_at", (a.endpoint,))
        else:
            bundles = [db.q(c, "SELECT id, path, manifest FROM bundles WHERE id=%s", (b,), one=True) for b in a.bundles.split(",")]
        tz = ep["config"].get("tz", "US/Eastern")
        from datetime import datetime, timedelta
        from zoneinfo import ZoneInfo
        def bounds(day):
            d0 = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=ZoneInfo(tz))
            return int(d0.timestamp() * 1e9), int((d0 + timedelta(days=1)).timestamp() * 1e9)
        lo, hi = bounds(D["test"][0])[0], bounds(D["test"][-1])[1]
        alert_rows = db.q(c, "SELECT node_uuid, max(fused) AS fused, max(window_start_ns) AS w, bool_and(bundle_ok) AS ok FROM "
                             "(SELECT a.node_uuid, a.fused, a.window_start_ns, true AS bundle_ok FROM alerts a WHERE a.endpoint_id=%s "
                             " AND a.window_start_ns >= %s AND a.window_start_ns < %s) x GROUP BY node_uuid", (a.endpoint, lo, hi))
        windows = db.q(c, "SELECT count(*) AS n, coalesce(sum(alerts),0) AS alerts FROM windows WHERE endpoint_id=%s AND start_ns >= %s AND start_ns < %s",
                       (a.endpoint, lo, hi), one=True)
        used = db.q(c, "SELECT bundle_id, count(*) AS n FROM windows WHERE endpoint_id=%s AND start_ns >= %s AND start_ns < %s GROUP BY 1 ORDER BY 2 DESC",
                    (a.endpoint, lo, hi))
    scoring_bundle = str(used[0]["bundle_id"]) if used else None   # the bundle the agent scored the test days with
    out = {"endpoint": a.endpoint, "dataset": a.dataset, "test_days": D["test"], "gt_nodes_total": len(all_gt),
           "agent_windows": dict(windows), "agent_scoring_bundle": scoring_bundle, "runs": []}
    alerted = {r["node_uuid"] for r in alert_rows}

    for i, b in enumerate(bundles):
        reg, seen, best = rescore(a.endpoint, ep, b["path"], D["test"], a.device)
        ids = np.where(seen)[0]
        uu = [reg[int(x)].uuid for x in ids]
        labels = np.array([u in all_gt for u in uu])
        node_attacks = [{k for k, v in gt.items() if u in v} for u in uu]
        n_att = len(gt)
        run = {"bundle": str(b["id"]), "train": (b["manifest"] or {}).get("calibration", {}).get("detector-2-aggregate"),
               "test_nodes": int(len(ids)), "gt_nodes_in_test": int(labels.sum())}
        from pdp_engine.scoring import above
        for k in ("fused", "r1", "r2"):
            sc = best[k][ids]
            m = metrics(above(sc), labels, node_attacks, n_att)
            m["ADP"] = round(adp(sc, labels, node_attacks), 3)
            run[{"fused": "fused (learned ranker)" if best.get("has_layers") else "fused (product)", "r1": "detector-1 alone", "r2": "detector-2 alone"}[k]] = m
        # post-hoc alternatives (not the deployed rule): both are calibrated on the benign validation day only
        r1, r2 = best["r1"][ids], best["r2"][ids]
        m = metrics(above(r1) | above(r2), labels, node_attacks, n_att); m["ADP"] = round(adp(np.maximum(r1, r2), labels, node_attacks), 3)
        run["either detector (post-hoc)"] = m
        m = metrics(above(r1) & above(r2), labels, node_attacks, n_att); m["ADP"] = round(adp(np.minimum(r1, r2), labels, node_attacks), 3)
        run["both detectors (post-hoc)"] = m
        if best.get("has_layers"):
            fl = {k: v[ids] for k, v in best["layers"].items()}
            fused = best["fused"][ids]
            views = {"layer 1: novelty": fl["novelty"], "layer 2: rules": fl["rules"],
                     "layers 1+2 (deterministic)": fl["novelty"] | fl["rules"],
                     "layer 3 alone (budgeted)": fl["learned"] | fl["corroborated"],
                     "layered product": fl["novelty"] | fl["rules"] | fl["corroborated"] | fl["learned"]}
            for name, pred in views.items():
                m = metrics(pred, labels, node_attacks, n_att)
                if name == "layered product":
                    m["ADP"] = round(adp(product_priority(fused, fl), labels, node_attacks), 3)
                    m["by_layer"] = {k: {"alerts": int(v.sum()), "TP": int((v & labels).sum())} for k, v in fl.items()}
                run[name] = m
            fp_ = {k: v[ids] for k, v in best["layers_pre"].items()}
            for name, pred in (("layer 2: rules (pre-registered: all rules alarm)", fp_["rules"]),
                               ("layered product (pre-registered policy)", fp_["novelty"] | fp_["rules"] | fp_["corroborated"] | fp_["learned"])):
                m = metrics(pred, labels, node_attacks, n_att)
                if name.startswith("layered"):
                    m["ADP"] = round(adp(product_priority(fused, fp_), labels, node_attacks), 3)
                run[name] = m
        if str(b["id"]) == scoring_bundle:
            # the product's own output: the alerts the agent reported (scored with the deployed bundle)
            pred = np.array([u in alerted for u in uu])
            m = metrics(pred, labels, node_attacks, n_att)
            m["alerted_nodes_outside_rescored_set"] = len(alerted - set(uu))
            run["reported alerts (agent)"] = m
        log(json.dumps(run))
        out["runs"].append(run)

    if len(out["runs"]) > 1:   # mean / min / best over runs, as Bilot et al. report
        agg = {}
        keys = ["fused (product)", "fused (learned ranker)", "detector-1 alone", "detector-2 alone", "either detector (post-hoc)", "both detectors (post-hoc)",
                "layer 1: novelty", "layer 2: rules", "layers 1+2 (deterministic)", "layer 3 alone (budgeted)", "layered product",
                "layer 2: rules (pre-registered: all rules alarm)", "layered product (pre-registered policy)"]
        for k in keys:
            if not all(k in r for r in out["runs"]):
                continue
            vals = {m: [r[k][m] for r in out["runs"]] for m in ("ADP", "precision", "recall", "MCC", "TP", "FP") if all(m in r[k] for r in out["runs"])}
            agg[k] = {m: {"mean": round(float(np.mean(v)), 3), "min": round(float(np.min(v)), 3), "max": round(float(np.max(v)), 3)} for m, v in vals.items()}
        out["summary"] = agg
    print(json.dumps(out, indent=1, default=str))
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
