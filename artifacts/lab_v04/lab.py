"""Stage B: re-run layers 1-2 and the alert policy on cached learned scores, for several variants, and report the
PIDSMaker node-level metrics per bundle plus mean/min/max.

  lab.py DATASET variants.json [--bundles N]

variants.json: {"name": {"layers": {config overrides}, "policy": {attr: value}, "rank": "fused"|"tier"}, ...}
"""
import argparse, csv, hashlib, json, math, os, sys, time
from collections import defaultdict
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.layers import EVIDENCE_RULES, DeterministicLayers
from pdp_engine.runtime import AlertPolicy, alert_tier
from pdp_engine.scoring import above

D = {
    "CADETS_E3": ("5eafc637-14c7-4074-b4d3-4e611dea925e", ["2018-04-06", "2018-04-11", "2018-04-12", "2018-04-13"],
                  ["E3-CADETS/node_Nginx_Backdoor_06.csv", "E3-CADETS/node_Nginx_Backdoor_12.csv", "E3-CADETS/node_Nginx_Backdoor_13.csv"]),
    "THEIA_E3": ("b4021490-6dd4-4dfb-8628-b3e55af27b90", ["2018-04-10", "2018-04-12", "2018-04-13"],
                 ["E3-THEIA/node_Browser_Extension_Drakon_Dropper.csv", "E3-THEIA/node_Firefox_Backdoor_Drakon_In_Memory.csv"]),
    "OPTC_H201": ("f85bab6a-0fce-4b21-81d8-dd967b8d4395", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h201/node_h201_0923.csv"]),
    "OPTC_H501": ("18978a51-ac8f-4afd-8f7a-c3003fa744c2", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h501/node_h501_0924.csv"]),
    "OPTC_H051": ("6ca8a927-9474-45be-870a-52bd56133b0e", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h051/node_h051_0925.csv"]),
}
BUNDLES = {l.split()[0]: l.split()[2].split(",") for l in open("/lab/jobs.txt")}
HELD_OUT = {"OPTC_H501", "OPTC_H051"}


def log(m):
    print(time.strftime("%H:%M:%S"), m, file=sys.stderr, flush=True)


def adp(scores, labels, node_attacks):
    total = len(set().union(*[a for a in node_attacks if a])) or 1
    order = np.argsort(-scores, kind="stable")
    tp = fp = 0; detected = set(); p2d = defaultdict(float); p2d[0.0] = 0.0
    for i in order:
        if labels[i]:
            tp += 1; detected |= node_attacks[i]
        else:
            fp += 1
        p = tp / (tp + fp)
        p2d[p] = max(p2d[p], 100.0 * len(detected) / total)
    xs = sorted(p2d); ys = [p2d[x] for x in xs]
    return float(np.trapz(ys, xs) / 100.0)


def metrics(pred, labels, node_attacks, n_att):
    tp = int((pred & labels).sum()); fp = int((pred & ~labels).sum()); fn = int((~pred & labels).sum()); tn = int((~pred & ~labels).sum())
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) or 1.0
    det = set()
    for i in np.where(pred & labels)[0]:
        det |= node_attacks[i]
    return {"TP": tp, "FP": fp, "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0, "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
            "MCC": round((tp * tn - fp * fn) / den, 3), "attacks": len(det), "n_attacks": n_att}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset"); ap.add_argument("variants"); ap.add_argument("--bundles", type=int, default=5)
    ap.add_argument("--allow-held-out", action="store_true"); ap.add_argument("--out")
    a = ap.parse_args()
    if a.dataset in HELD_OUT and not a.allow_held_out:
        sys.exit(f"{a.dataset} is held out (PROTOCOL.md): pass --allow-held-out only for the final, frozen evaluation")
    eid, days, gtf = D[a.dataset]
    variants = json.load(open(a.variants))
    gt = defaultdict(set)
    for f in gtf:
        for row in csv.reader(open(os.path.join("/gt", f))):
            if len(row) >= 3 and row[2].strip():
                gt[os.path.basename(f)[5:-4]].add(row[2].strip())
    all_gt = set().union(*gt.values())
    st = WindowStore(f"/data/endpoints/{eid}/eval-test")
    reg = st.load_registry()
    wins = [w for d in days for w in st.windows(d)]
    log(f"{a.dataset}: {len(wins)} windows, registry {len(reg)}")
    bids = BUNDLES[eid][: a.bundles]
    cache = {}
    for b in bids:
        z = np.load(f"/data/lab/{eid}/{b}.npz")
        off = np.concatenate([[0], np.cumsum(z["wlen"])])
        assert len(z["wlen"]) == len(wins), (b, len(z["wlen"]), len(wins))
        cache[b] = (z["ids"], z["fused"], off, z["r1"], z["r2"])
    ids0, _, off0, _, _ = cache[bids[0]]
    for k in (0, len(wins) // 2, len(wins) - 1):
        assert np.array_equal(np.sort(ids0[off0[k]:off0[k + 1]]), np.sort(wins[k].nodes().astype(np.int32))), "cache / window mismatch"
    seen = np.zeros(len(reg), dtype=bool); seen[ids0] = True
    ix = np.where(seen)[0]
    uu = [reg.entities[int(i)].uuid for i in ix]
    labels = np.array([u in all_gt for u in uu])
    node_attacks = [{k for k, v in gt.items() if u in v} for u in uu]
    n_att = len(gt)
    spec0 = json.load(open(f"/data/bundles/{eid}/{bids[0]}/layers.json"))
    nb = json.load(open(f"/data/bundles/{eid}/{bids[0]}/manifest.json"))["num_nodes"]
    hit_cache = {}
    results = {}
    for vname, v in variants.items():
        lc = json.dumps(v.get("layers", {}), sort_keys=True)
        lc = lc + ("|refit" if v.get("refit") else "")
        if lc not in hit_cache:
            spec = json.loads(json.dumps(spec0)); spec["config"].update(v.get("layers", {}))
            if v.get("refit"):   # re-fit layers 1-2 on the baseline days with this configuration (keys may change)
                from pdp_engine.layers import LayerConfig, TagParams, fit_layers
                c0 = spec["config"]
                cfg = LayerConfig(novelty=c0.get("novelty", True), rules=c0.get("rules", True), tags=TagParams(**c0.get("tags", {})),
                                  evidence_rules=tuple(c0.get("evidence_rules", EVIDENCE_RULES)),
                                  **{k: c0[k] for k in ("normalize_programs", "novel_instances", "full_paths", "image_exec", "follow_channels", "local_multicast") if k in c0})
                bst = WindowStore(f"/data/endpoints/{eid}/baseline")
                t0 = time.time()
                spec = fit_layers(bst, spec0["fit_days"], bst.load_registry(), nb, cfg, log=log)
                log(f"refit {lc}: {time.time() - t0:.0f}s")
            L = DeterministicLayers(spec, nb)
            t0 = time.time()
            hit_cache[lc] = (spec, [L.process(w, reg, w.nodes()) for w in wins])
            log(f"layers {lc}: {sum(len(h) for h in hit_cache[lc][1])} hits, {time.time() - t0:.0f}s")
        spec, hits = hit_cache[lc]
        runs = []
        for b in bids:
            ids, fused, off, r1c, r2c = cache[b]
            man = json.load(open(f"/data/bundles/{eid}/{b}/manifest.json"))
            cal = man["calibration"]["fusion"]
            pol = man.get("learned_policy") or {}
            corr = float(cal["percentiles"].get(pol.get("corroboration_percentile", "99.9"), cal["threshold"])) / cal["threshold"]
            P = AlertPolicy(None, int(pol.get("daily_budget", 20)), corr, evidence_rules=spec["config"].get("evidence_rules", EVIDENCE_RULES))
            for k2, val in v.get("policy", {}).items():
                if k2 == "corroboration" and val == "threshold":
                    val = 1.0 + 1e-4
                setattr(P, k2, val)
            tier = np.zeros(len(reg), dtype=np.int8)
            fmax = np.full(len(reg), -np.inf, dtype=np.float32)
            tb = {"fused": fused, "r2": r2c, "r1": r1c, "max": np.maximum(r1c, r2c)}[v.get("tiebreak", "fused")]
            np.maximum.at(fmax, ids, tb)
            by_layer = defaultdict(lambda: np.zeros(len(reg), dtype=bool))
            for k, w in enumerate(wins):
                wid, wf = ids[off[k]:off[k + 1]].astype(np.int64), fused[off[k]:off[k + 1]]
                _, reasons, _ = P.apply(w, reg, wid, wf, hits[k])
                for n, rs in reasons.items():
                    t = alert_tier(rs)
                    if t > tier[n]:
                        tier[n] = t
                    for x in rs:
                        if x["layer"] in ("novelty", "rules", "corroborated", "learned"):
                            by_layer[x["layer"]][n] = True
            T, F = tier[ix], np.where(np.isfinite(fmax[ix]), fmax[ix], 0.0)
            pred = T > 0
            run = {"bundle": b[:8], "product": metrics(pred, labels, node_attacks, n_att)}
            rank = v.get("rank", "fused")
            if rank == "tier":
                score = T * 1e6 + np.clip(F, 0, 1e5)
            else:   # 0.3 darpa_eval product_priority: deterministic first, then corroborated, then learned; ties by fused
                fl = {k: by_layer[k][ix] for k in ("novelty", "rules", "corroborated", "learned")}
                tt = np.where(fl["novelty"] | fl["rules"], 3, np.where(fl["corroborated"], 2, np.where(fl["learned"], 1, 0)))
                score = tt * 1e6 + np.clip(F, 0, 1e5)
            run["product"]["ADP"] = round(adp(score, labels, node_attacks), 3)
            run["by_layer"] = {k: [int(m[ix].sum()), int((m[ix] & labels).sum())] for k, m in by_layer.items()}
            run["fused_ADP"] = round(adp(F, labels, node_attacks), 3)
            runs.append(run)
        agg = {m: (round(float(np.mean([r["product"][m] for r in runs])), 3), round(float(np.min([r["product"][m] for r in runs])), 3),
                   round(float(np.max([r["product"][m] for r in runs])), 3)) for m in ("ADP", "MCC", "precision", "recall", "TP", "FP", "attacks")}
        results[vname] = {"runs": runs, "summary": agg}
        s = agg
        print(f"{a.dataset:10s} {vname:28s} ADP {s['ADP'][0]:.3f} (min {s['ADP'][1]:.3f})  MCC {s['MCC'][0]:.3f}  P {s['precision'][0]:.3f}  "
              f"R {s['recall'][0]:.3f}  TP {s['TP'][0]:.0f} FP {s['FP'][0]:.0f}  attacks {s['attacks'][1]:.0f}-{s['attacks'][2]:.0f}/{n_att}  "
              f"layers {runs[0]['by_layer']}", flush=True)
    if a.out:
        json.dump(results, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
