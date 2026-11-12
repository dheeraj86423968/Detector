"""Bootstrap 95 % intervals for 0.10 (P2) on the 16 development sets (PROTOCOL.md part 2). Pure Python, no scoring.
Inputs: lab_v10 results/res13-*.json (attacks, TP, FP, days) and results/inc13-final.json (P2/G2 false incidents).
Schemes: host (resample the 16 sets) and family (resample the 5 dataset families). Ratios of sums, percentile CIs.
Usage: python3 bootstrap.py LAB_V10_RESULTS OUT_PREFIX"""
import glob, json, random, sys

src, out = sys.argv[1], sys.argv[2]
B, SEED = 10_000, 20261112
FAMILY = {"CADETS_E3": "DARPA E3", "THEIA_E3": "DARPA E3", "CLEARSCOPE_E3": "DARPA E3", "FIVEDIRECTIONS_E3": "DARPA E3",
          "TRACE_E3-trace": "DARPA E3", "THEIA_E5-theia": "DARPA E5", "OPTC_H051": "OpTC", "OPTC_H201": "OpTC",
          "OPTC_H501": "OpTC", "ATLASV2_EDR-h1": "ATLASv2", "ATLASV2_EDR-h2": "ATLASv2"}
inc = json.load(open(f"{src}/inc13-final.json"))
units = {}
for f in sorted(glob.glob(f"{src}/res13-*.json")):
    r = json.load(open(f)); s = r["set"]
    n = 0 if r["gt_nodes"] == 0 else r["n_attacks"]       # ATLASv2 h2: no ground-truth node (summ13: 0 attacks)
    units[s] = {"attacks": n, "found": r["P2"]["attacks"], "TP": r["P2"]["TP"], "FP": r["P2"]["FP"], "days": r["days"],
                "fp_inc": inc[s]["P2/G2"]["fp_incidents"], "family": FAMILY.get(s, "CARBANAKv2")}
assert len(units) == 16 and sum(u["attacks"] for u in units.values()) == 30


def stats(us):
    a = sum(u["attacks"] for u in us); d = sum(u["days"] for u in us); tp = sum(u["TP"] for u in us); fp = sum(u["FP"] for u in us)
    return {"detection_rate": sum(u["found"] for u in us) / a if a else float("nan"),
            "fp_per_host_day": fp / d, "false_incidents_per_host_day": sum(u["fp_inc"] for u in us) / d,
            "precision": tp / (tp + fp) if tp + fp else float("nan")}


def pct(xs, q):
    xs = sorted(x for x in xs if x == x)
    k = (len(xs) - 1) * q; lo = int(k); hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


point = stats(list(units.values()))
res = {"B": B, "seed": SEED, "point": point, "units": units, "schemes": {}}
clusters = {"host": [[u] for u in units.values()]}
fam = {}
for s, u in units.items():
    fam.setdefault(u["family"], []).append(u)
clusters["family"] = list(fam.values())
for name, cl in clusters.items():
    rng = random.Random(SEED)
    draws = {k: [] for k in point}
    nan_draws = 0
    for _ in range(B):
        us = [u for c in (rng.choice(cl) for _ in range(len(cl))) for u in c]
        st = stats(us)
        nan_draws += st["detection_rate"] != st["detection_rate"]
        for k, v in st.items():
            draws[k].append(v)
    res["schemes"][name] = {"clusters": len(cl), "draws_without_attacks": nan_draws,
                            **{k: {"lo": pct(v, 0.025), "hi": pct(v, 0.975)} for k, v in draws.items()}}
json.dump(res, open(out + ".json", "w"), indent=1)

L = ["# Bootstrap 95 % intervals, STRATA 0.10 (P2), 16 development sets", "",
     f"{B:,} resamples, seed {SEED}, percentile intervals; every statistic is a ratio of sums over the resampled units "
     "(sets or families). Inputs: artifacts/lab_v10/results/res13-*.json, inc13-final.json (P2/G2 = 0.10 grouping). "
     f"Totals: {sum(u['found'] for u in units.values())}/30 attacks, TP {sum(u['TP'] for u in units.values())}, "
     f"FP {sum(u['FP'] for u in units.values())}, {sum(u['days'] for u in units.values())} host-days, "
     f"{sum(u['fp_inc'] for u in units.values())} false incidents.", "",
     "| statistic | point | host bootstrap (16 sets) | family bootstrap (5 families) |", "|---|---|---|---|"]
fmt = {"detection_rate": "{:.3f}", "fp_per_host_day": "{:.2f}", "false_incidents_per_host_day": "{:.2f}", "precision": "{:.3f}"}
for k in point:
    f = fmt[k]
    L.append(f"| {k.replace('_', ' ')} | {f.format(point[k])} | " + " | ".join(
        f"[{f.format(res['schemes'][n][k]['lo'])}, {f.format(res['schemes'][n][k]['hi'])}]" for n in ("host", "family")) + " |")
L += ["", "Family scheme: every family holds at least one attack, so every draw has a defined detection rate; with 5 "
      "clusters there are only 126 distinct resamples and the percentile interval understates uncertainty: read it as a "
      "sensitivity check, not a calibrated 95 % interval.",
      "Host scheme: CARBANAKv2 h1-h5 count as 5 attacks (one multi-host campaign, as res13 counts it); in the family "
      "scheme they move together. ATLASv2 h1 holds 10 of the 30 attacks; a draw without it shifts the rate strongly.", "",
      "| family | sets | attacks found | TP | FP | days | false incidents |", "|---|---|---|---|---|---|---|"]
for f_, us in fam.items():
    L.append(f"| {f_} | {len(us)} | {sum(u['found'] for u in us)}/{sum(u['attacks'] for u in us)} | {sum(u['TP'] for u in us)} | "
             f"{sum(u['FP'] for u in us)} | {sum(u['days'] for u in us)} | {sum(u['fp_inc'] for u in us)} |")
open(out + ".md", "w").write("\n".join(L) + "\n")
print("\n".join(L))
