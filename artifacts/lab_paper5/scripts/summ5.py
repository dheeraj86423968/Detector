"""paper5 summary (artifacts/lab_paper5/PROTOCOL.md): per host mean / sd / min / max over the completed runs, 16-set
totals per run, PROGRESS.md. Run 1 = lab_v10's original numbers (adp-*.json P2, inc13-final.json P2/G2); run 1's
per-detector numbers come from re-scoring its bundles with eval5.py (res5-*-r1.json)."""
import glob, json, os, statistics as stt, time

A = "/root/Desktop/platform/artifacts"
R = f"{A}/lab_paper5/results"
V = "/var/lib/docker/volumes/pdp_pdp_data/_data/paper5"
Q = "/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/p5"
DEV = ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "FIVEDIRECTIONS_E3", "TRACE_E3-trace", "THEIA_E5-theia", "OPTC_H201", "OPTC_H501",
       "OPTC_H051", "ATLASV2_EDR-h1", "ATLASV2_EDR-h2"] + [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)]
HO = "CLEARSCOPE_E5-clearscope"
PRIO = ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "THEIA_E5-theia", "OPTC_H051", "OPTC_H201", "OPTC_H501", HO, "TRACE_E3-trace",
        "FIVEDIRECTIONS_E3", "ATLASV2_EDR-h1", "ATLASV2_EDR-h2"] + [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)]
DARPA8 = ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "THEIA_E5-theia", HO, "OPTC_H051", "OPTC_H201", "OPTC_H501"]
INC1 = json.load(open(f"{A}/lab_v10/results/inc13-final.json"))


def load(p):
    return json.load(open(p)) if os.path.exists(p) else None


def metrics(s, r):
    """one run's numbers, or None. Run 1: original lab_v10 numbers + per-detector numbers of the re-scoring."""
    res = load(f"{R}/res5-{s}-r{r}.json")
    inc = load(f"{R}/inc5-{s}-r{r}.json")
    if r == 1:
        orig = load(f"{A}/lab_v10/results/adp/adp-{s}.json")
        if orig is None:
            return None
        p2 = orig["P2"]
        g = (INC1.get(s) or {}).get("P2/G2") or ((inc or {}).get(s) or {}).get("P2/G2")
        src = "lab_v10" if s in INC1 else "rescored"
        days = orig["days"]
        x3 = load(f"{A}/lab_v10/results/adp/adp-{s}-3att.json")
    else:
        if res is None or inc is None:
            return None
        p2, g, days, src, x3 = res["P2"], inc[s]["P2/G2"], res["days"], "paper5", None
    m = {"attacks": p2["attacks"], "n_attacks": None, "TP": p2["TP"], "FP": p2["FP"], "precision": round(p2["TP"] / max(1, p2["TP"] + p2["FP"]), 3),
         "ADP": p2["ADP"], "ADP_learned": p2["ADP_learned_only"], "days": days,
         "incidents": g["incidents"] if g else None, "false_incidents": g["fp_incidents"] if g else None,
         "buried": len(g["buried"]) if g else None, "incident_source": src if g else None}
    m["attacks_found"] = p2.get("attacks_found")
    if res is not None:
        m["n_attacks"] = res["n_attacks"]
        q = res["P2"]
        if "ADP_triage_time_tiebreak" in q:
            m["ADP_time"] = q["ADP_triage_time_tiebreak"]["mean"]
            l = q["layers12_only"]
            m.update({"L12_attacks": l["attacks"], "L12_TP": l["TP"], "L12_FP": l["FP"], "L12_ADP_time": l["ADP_time_tiebreak"]["mean"],
                      "L12_attacks_found": l["attacks_found"]})
        m["d1_attacks_found"] = res["detector-1"]["val_max"]["attacks_found"]; m["d2_attacks_found"] = res["detector-2"]["val_max"]["attacks_found"]
        for k, short in (("detector-1", "d1"), ("detector-2", "d2")):
            d = res[k]
            m.update({f"{short}_attacks": d["val_max"]["attacks"], f"{short}_TP": d["val_max"]["TP"], f"{short}_FP": d["val_max"]["FP"],
                      f"{short}_ADP": d["ADP"], f"{short}_r1_attacks": d["ratio_1"]["attacks"], f"{short}_r1_TP": d["ratio_1"]["TP"],
                      f"{short}_r1_FP": d["ratio_1"]["FP"]})
        if r == 1:   # re-scoring must reproduce run 1
            q = res["P2"]
            m["rescore_matches"] = all(q[k] == p2[k] for k in ("attacks", "TP", "FP", "ADP", "ADP_learned_only"))
            if not m["rescore_matches"]:
                m["rescore"] = {k: q[k] for k in ("attacks", "TP", "FP", "ADP", "ADP_learned_only")}
        ex = res.get("with_extra_gt")
        if ex:
            m["ADP_3att"] = ex["P2"]["ADP"]; m["ADP_learned_3att"] = ex["P2"]["ADP_learned_only"]
            if "ADP_triage_time_tiebreak" in ex["P2"]:
                m["ADP_time_3att"] = ex["P2"]["ADP_triage_time_tiebreak"]["mean"]
                m["L12_ADP_time_3att"] = ex["P2"]["layers12_only"]["ADP_time_tiebreak"]["mean"]
            m["attacks_3att"] = ex["P2"]["attacks"]; m["d1_ADP_3att"] = ex["detector-1"]["ADP"]; m["d2_ADP_3att"] = ex["detector-2"]["ADP"]
    if r == 1 and x3:
        m["ADP_3att"] = x3["P2"]["ADP"]; m["ADP_learned_3att"] = x3["P2"]["ADP_learned_only"]; m["attacks_3att"] = x3["P2"]["attacks"]
    return m


KEYS = ["ADP", "ADP_time", "L12_attacks", "L12_TP", "L12_FP", "L12_ADP_time", "ADP_time_3att", "L12_ADP_time_3att", "ADP_learned", "attacks", "TP", "FP", "precision", "incidents", "false_incidents", "buried",
        "d1_attacks", "d1_TP", "d1_FP", "d1_ADP", "d2_attacks", "d2_TP", "d2_FP", "d2_ADP",
        "ADP_3att", "ADP_learned_3att", "attacks_3att", "d1_ADP_3att", "d2_ADP_3att"]


def agg(vals):
    v = [x for x in vals if x is not None]
    if not v:
        return None
    return {"n": len(v), "mean": round(stt.mean(v), 3), "sd": round(stt.stdev(v), 3) if len(v) > 1 else None,
            "min": min(v), "max": max(v), "values": v}


def main():
    per = {s: {r: metrics(s, r) for r in range(1, 6)} for s in PRIO}
    hosts = {}
    for s in PRIO:
        runs = {r: m for r, m in per[s].items() if m is not None}
        sets = {}
        for k in ("attacks_found", "L12_attacks_found", "d1_attacks_found", "d2_attacks_found"):
            v = {r: m.get(k) for r, m in runs.items() if m.get(k) is not None}
            sets[k] = {"per_run": v, "same_in_all_runs": len({tuple(x) for x in v.values()}) <= 1}
        hosts[s] = {"runs_completed": sorted(runs), "runs": runs, "summary": {k: agg([m.get(k) for m in runs.values()]) for k in KEYS},
                    "detected_sets": sets}
    totals = {}
    for r in range(1, 6):
        ms = [per[s][r] for s in DEV]
        if all(m is not None for m in ms):
            days = sum(m["days"] for m in ms)
            t = {"attacks": sum(m["attacks"] for m in ms), "TP": sum(m["TP"] for m in ms), "FP": sum(m["FP"] for m in ms), "host_days": days}
            t["FP_per_host_day"] = round(t["FP"] / days, 2)
            if all(m["false_incidents"] is not None for m in ms):
                t["false_incidents"] = sum(m["false_incidents"] for m in ms); t["incidents"] = sum(m["incidents"] for m in ms)
                t["false_incidents_per_host_day"] = round(t["false_incidents"] / days, 2)
            for d in ("d1", "d2", "L12"):
                if all(m.get(f"{d}_attacks") is not None for m in ms):
                    for k in ("attacks", "TP", "FP"):
                        t[f"{d}_{k}"] = sum(m[f"{d}_{k}"] for m in ms)
            totals[r] = t
    tsum = {k: agg([t.get(k) for t in totals.values()]) for k in
            ("attacks", "TP", "FP", "FP_per_host_day", "incidents", "false_incidents", "false_incidents_per_host_day",
             "d1_attacks", "d1_TP", "d1_FP", "d2_attacks", "d2_TP", "d2_FP", "L12_attacks", "L12_TP", "L12_FP")}
    out = {"generated": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), "hosts": hosts, "dev16_totals_per_run": totals,
           "dev16_totals_summary": tsum}
    json.dump(out, open(f"{R}/summary.json", "w"), indent=1)

    def f(a, k, nd=2):
        x = a["summary"].get(k)
        if not x:
            return "-"
        fm = (lambda v: f"{v:.{nd}f}") if nd else (lambda v: f"{v:g}")
        sd = f" ± {x['sd']:.{max(nd, 1)}f}" if x["sd"] is not None else ""
        return f"{fm(x['mean'])}{sd} ({fm(x['min'])}–{fm(x['max'])})"

    L = [f"# paper5 summary (generated {out['generated']})", "",
         "Per host: mean ± sample sd (min–max) over the completed runs. Run 1 = lab_v10's original numbers; runs 2-5 = new "
         "seeds (PROTOCOL.md). Triage = 0.10 operating point (P2) and its triage order; d1 / d2 = detector-1 (Velox) / "
         "detector-2 (ORTHRUS) alone at their ensemble validation maximum.", ""]
    L.append("| host | runs | ADP triage | ADP learned | attacks | TP | FP | false incid. | d1 attacks | d1 TP | d1 FP | d1 ADP | d2 attacks | d2 TP | d2 FP | d2 ADP |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for s in PRIO:
        a = hosts[s]
        if not a["runs_completed"]:
            L.append(f"| {s} | 0 | " + " | ".join(["-"] * 14) + " |"); continue
        L.append(f"| {s}{' (held-out, seen)' if s == HO else ''} | {','.join(map(str, a['runs_completed']))} | {f(a, 'ADP')} | {f(a, 'ADP_learned')} | "
                 f"{f(a, 'attacks', 0)} | {f(a, 'TP', 0)} | {f(a, 'FP', 0)} | {f(a, 'false_incidents', 0)} | {f(a, 'd1_attacks', 0)} | {f(a, 'd1_TP', 0)} | "
                 f"{f(a, 'd1_FP', 0)} | {f(a, 'd1_ADP')} | {f(a, 'd2_attacks', 0)} | {f(a, 'd2_TP', 0)} | {f(a, 'd2_FP', 0)} | {f(a, 'd2_ADP')} |")
    L += ["", "## What the learned score adds to ranking (amendment 1)", "",
          "ADP triage = 0.10 triage order (tier, then learned score); ADP time = same tiers, tie-break by first alert time then "
          "random (mean of 20 seeds); L12 = layers 1-2 alone (no corroborated / learned alerts), time tie-break.", "",
          "| host | ADP triage | ADP time tie-break | L12 attacks | L12 TP | L12 FP | L12 ADP | detected set same in all runs (P2 / L12 / d1 / d2) |",
          "|---|---|---|---|---|---|---|---|"]
    for s in PRIO:
        a = hosts[s]
        if not a["runs_completed"]:
            continue
        ds = a["detected_sets"]
        same = " / ".join(("yes" if ds[k]["same_in_all_runs"] else "NO") if ds[k]["per_run"] else "-" for k in ("attacks_found", "L12_attacks_found", "d1_attacks_found", "d2_attacks_found"))
        L.append(f"| {s} | {f(a, 'ADP')} | {f(a, 'ADP_time')} | {f(a, 'L12_attacks', 0)} | {f(a, 'L12_TP', 0)} | {f(a, 'L12_FP', 0)} | {f(a, 'L12_ADP_time')} | {same} |")
    L += ["", "Detected attacks that differ between runs:"]
    for s in PRIO:
        for k, v in hosts[s]["detected_sets"].items():
            if not v["same_in_all_runs"]:
                L.append(f"- {s} {k}: " + "; ".join(f"r{r}: {', '.join(x) or 'none'}" for r, x in sorted(v["per_run"].items())))
    a = hosts[HO]
    if a["summary"].get("ADP_3att"):
        L += ["", f"{HO} with Bilot et al.'s third attack: ADP triage {f(a, 'ADP_3att')}, learned {f(a, 'ADP_learned_3att')}, "
              f"time tie-break {f(a, 'ADP_time_3att')}, L12 {f(a, 'L12_ADP_time_3att')}, attacks {f(a, 'attacks_3att', 0)}, d1 ADP {f(a, 'd1_ADP_3att')}, d2 ADP {f(a, 'd2_ADP_3att')}"]
    # mean ADP over the 8 DARPA comparison hosts, per run (only runs where all 8 exist)
    L += ["", "## Mean ADP over the 8 DARPA comparison hosts, per run (E5 ClearScope with 3 attacks, as in the paper's Table)", "",
          "| run | ADP triage | ADP time tie-break | L12 ADP | ADP learned | d1 ADP | d2 ADP |", "|---|---|---|---|---|---|---|"]
    for r in range(1, 6):
        ms = [per[s][r] for s in DARPA8]
        if all(m is not None for m in ms):
            def mean_of(k, k3=None):
                v = [(m.get(k3) if (s == HO and k3) else m.get(k)) for s, m in zip(DARPA8, ms)]
                return f"{stt.mean(v):.3f}" if all(x is not None for x in v) else "-"
            L.append(f"| {r} | {mean_of('ADP', 'ADP_3att')} | {mean_of('ADP_time', 'ADP_time_3att')} | {mean_of('L12_ADP_time', 'L12_ADP_time_3att')} | {mean_of('ADP_learned', 'ADP_learned_3att')} | {mean_of('d1_ADP', 'd1_ADP_3att')} | {mean_of('d2_ADP', 'd2_ADP_3att')} |")
    L += ["", "## 16 development sets, totals per run (71 host-days; only runs where all 16 sets completed)", "",
          "| run | attacks (of 30) | TP | FP | FP / host-day | incidents | false incidents | false incid. / host-day | L12 attacks / TP / FP | d1 attacks / TP / FP | d2 attacks / TP / FP |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r, t in totals.items():
        L.append(f"| {r} | {t['attacks']} | {t['TP']} | {t['FP']} | {t['FP_per_host_day']} | {t.get('incidents', '-')} | {t.get('false_incidents', '-')} | "
                 f"{t.get('false_incidents_per_host_day', '-')} | {t.get('L12_attacks', '-')} / {t.get('L12_TP', '-')} / {t.get('L12_FP', '-')} | {t.get('d1_attacks', '-')} / {t.get('d1_TP', '-')} / {t.get('d1_FP', '-')} | "
                 f"{t.get('d2_attacks', '-')} / {t.get('d2_TP', '-')} / {t.get('d2_FP', '-')} |")
    if totals:
        L.append("| mean (min–max) | " + " | ".join(
            (f"{tsum[k]['mean']:g} ({tsum[k]['min']:g}–{tsum[k]['max']:g})" if tsum.get(k) else "-")
            for k in ("attacks", "TP", "FP", "FP_per_host_day", "incidents", "false_incidents", "false_incidents_per_host_day")) + " | | | |")
    mism = [(s, r) for s in PRIO for r, m in [(1, per[s][1])] if m and m.get("rescore_matches") is False]
    L += ["", "Run-1 re-scoring (source of run 1's d1 / d2 numbers) reproduces run 1's operating point and ADP on: "
          + ", ".join(s for s in PRIO if per[s][1] and per[s][1].get("rescore_matches")) or "-"]
    if mism:
        L.append("Differs on: " + "; ".join(f"{s} {per[s][1]['rescore']}" for s, _ in mism))
    open(f"{R}/SUMMARY.md", "w").write("\n".join(L) + "\n")

    # progress
    P = [f"# paper5 progress (updated {out['generated']})", "",
         "Status per host: runs trained (bundle present) / scored. Runs 2-5 are new seeds; run 1 = lab_v10 (re-scored for d1/d2).", "",
         "| host | trained | scored | failed |", "|---|---|---|---|"]
    for s in PRIO:
        tr = [r for r in range(2, 6) if os.path.exists(f"{V}/{s}/r{r}/train5.json")]
        sc = [r for r in range(1, 6) if os.path.exists(f"{R}/res5-{s}-r{r}.json")]
        fl = [r for r in range(1, 6) if os.path.exists(f"{Q}/out/fail-{s}-r{r}")]
        try:
            fl += [int(l.split()[1]) for l in open(f"{Q}/failed.txt") if l.split()[0] == s]
        except OSError:
            pass
        P.append(f"| {s} | {','.join(map(str, tr)) or '-'} | {','.join(map(str, sc)) or '-'} | {','.join(map(str, sorted(set(fl)))) or '-'} |")
    P += ["", "Partial results: results/SUMMARY.md (regenerated after every scored run).", ""]
    open(f"{A}/lab_paper5/PROGRESS.md", "w").write("\n".join(P) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
