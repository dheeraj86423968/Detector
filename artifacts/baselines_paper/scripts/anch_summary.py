"""results/anchoring/anch-*.json -> results/anchoring_summary.{md,json}."""
import glob, json, os, re
R = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
rows, pool = [], {}
for f in sorted(glob.glob(os.path.join(R, "anchoring", "anch-*.json"))):
    d = json.load(open(f)); host = d["set"]
    if "-3att" in f:
        continue
    A, B = d["A0"], d["P2"]
    for k in [k for k in d if k.startswith("X:")]:
        m = re.match(r"X:(provfusion|velox|orthrus_non_snooped)_.+_s(\d)", k); sysn, seed = m.group(1), int(m.group(2))
        X = d[k]; Dd = X["system_alone"]
        r = {"host": host, "system": sysn, "seed": seed, "n_attacks": d["n_attacks"], "days": d["days"],
             "a_layers12": {x: A[x] for x in ("attacks", "TP", "FP", "FP/day")},
             "b_released": {x: B[x] for x in ("attacks", "TP", "FP", "FP/day")} | {"tp_only_via_learned": B["tp_only_via_learned"], "attacks_only_via_learned": B["attacks_only_via_learned"]},
             "c_anchored_original": {x: X[x] for x in ("attacks", "TP", "FP", "FP/day")} | {"tp_only_via_learned": X["tp_only_via_learned"], "attacks_only_via_learned": X["attacks_only_via_learned"]},
             "d_original_alone": {x: Dd[x] for x in ("attacks", "TP", "FP", "FP/day")},
             "ADP_tierC_original": X["ADP_tier_original"], "ADP_tierB_ours": B["ADP_tier_ours"],
             "ADP_tierA_random": A["ADP_tier_random20"], "ADP_tierC_random": X["ADP_tier_random20"],
             "ADP_tierB_random": B["ADP_tier_random20"]}
        rows.append(r)
        p = pool.setdefault(sysn, {"runs": 0, "host_days": 0, **{c: {"attacks": 0, "TP": 0, "FP": 0} for c in ("a_layers12", "b_released", "c_anchored_original", "d_original_alone")},
                                   "n_attacks": 0, "c_tp_only_via_learned": 0, "b_tp_only_via_learned": 0, "c_attacks_only_via_learned": 0, "b_attacks_only_via_learned": 0,
                                   "ADP": {"tierC_original": [], "tierB_ours": [], "tierA_random": [], "tierC_random": []}})
        p["runs"] += 1; p["host_days"] += d["days"]; p["n_attacks"] += d["n_attacks"]
        for c in ("a_layers12", "b_released", "c_anchored_original", "d_original_alone"):
            for x in ("attacks", "TP", "FP"):
                p[c][x] += r[c][x]
        p["c_tp_only_via_learned"] += X["tp_only_via_learned"]; p["b_tp_only_via_learned"] += B["tp_only_via_learned"]
        p["c_attacks_only_via_learned"] += len(X["attacks_only_via_learned"]); p["b_attacks_only_via_learned"] += len(B["attacks_only_via_learned"])
        for kk, v in (("tierC_original", r["ADP_tierC_original"]), ("tierB_ours", r["ADP_tierB_ours"]), ("tierA_random", r["ADP_tierA_random"]), ("tierC_random", r["ADP_tierC_random"])):
            p["ADP"][kk].append(v)
for p in pool.values():
    p["ADP_mean"] = {k: round(sum(v) / len(v), 3) for k, v in p["ADP"].items()}
    for c in ("a_layers12", "b_released", "c_anchored_original", "d_original_alone"):
        p[c]["FP/host-day"] = round(p[c]["FP"] / p["host_days"], 2)
json.dump({"runs": rows, "pooled": pool}, open(os.path.join(R, "anchoring_summary.json"), "w"), indent=1)
f3 = lambda c: f"{c['attacks']} / {c['TP']} / {c['FP']} ({c['FP/day']})"
L = ["# Anchoring STRATA 0.10 with the original systems' learned evidence (PROTOCOL part 5)", "",
     "Cells: attacks / TP / FP (FP per test day). (a) layers 1-2 only; (b) 0.10 as released (our learned evidence, = res13 P2);",
     "(c) layers 1-2 + anchored original alerts; (d) original system alone on the lab's test nodes. '+TP/+att' = TP nodes /",
     "attacks of (c) not in (a). ADP: tier x 1e6 then the original score [tier of (c)], our score [tier of (b), = res13],",
     "random tie order [tier of (a) / (c), mean of 20 shuffles].", "",
     "| host | system | seed | attacks | (a) L1-2 | (b) 0.10 | (c) L1-2 + anchored original | +TP / +att (c) | +TP / +att (b) | (d) original alone | ADP (c)+orig | ADP (b)+ours | ADP (a)+rnd | ADP (c)+rnd |",
     "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
for r in rows:
    L.append(f"| {r['host']} | {r['system']} | {r['seed']} | {r['n_attacks']} | {f3(r['a_layers12'])} | {f3(r['b_released'])} | {f3(r['c_anchored_original'])} | "
             f"{r['c_anchored_original']['tp_only_via_learned']} / {len(r['c_anchored_original']['attacks_only_via_learned'])} | "
             f"{r['b_released']['tp_only_via_learned']} / {len(r['b_released']['attacks_only_via_learned'])} | {f3(r['d_original_alone'])} | "
             f"{r['ADP_tierC_original']:.3f} | {r['ADP_tierB_ours']:.3f} | {r['ADP_tierA_random']:.3f} | {r['ADP_tierC_random']:.3f} |")
L += ["", "Pooled per system (sums over host-seed runs; (a) and (b) repeated once per run of that system so the columns are comparable; FP per host-day):", "",
      "| system | runs | attacks | (a) | (b) | (c) | +TP / +att (c) | +TP / +att (b) | (d) | mean ADP (c)+orig / (b)+ours / (a)+rnd / (c)+rnd |", "|---|---|---|---|---|---|---|---|---|---|"]
g = lambda c: f"{c['attacks']} / {c['TP']} / {c['FP']} ({c['FP/host-day']})"
for s, p in sorted(pool.items()):
    a = p["ADP_mean"]
    L.append(f"| {s} | {p['runs']} | {p['n_attacks']} | {g(p['a_layers12'])} | {g(p['b_released'])} | {g(p['c_anchored_original'])} | {p['c_tp_only_via_learned']} / {p['c_attacks_only_via_learned']} | "
             f"{p['b_tp_only_via_learned']} / {p['b_attacks_only_via_learned']} | {g(p['d_original_alone'])} | {a['tierC_original']} / {a['tierB_ours']} / {a['tierA_random']} / {a['tierC_random']} |")
open(os.path.join(R, "anchoring_summary.md"), "w").write("\n".join(L) + "\n")
print("\n".join(L))
