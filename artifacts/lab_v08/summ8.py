import json, sys, glob, os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sets = ["CADETS_E3", "THEIA_E3", "OPTC_H201", "OPTC_H501", "OPTC_H051", "CLEARSCOPE_E3", "FIVEDIRECTIONS_E3", "ATLASV2_EDR-h1", "ATLASV2_EDR-h2", "TRACE_E3-trace"]
for name in sys.argv[1:]:
    rows, fps, recs, att, tot = [], [], [], 0, 0
    for s in sets:
        f = f"res-{name}-{s}.json"
        if not os.path.exists(f):
            rows.append(f"{s[:12]:12s} -"); continue
        r = json.load(open(f)); p = r["product"]
        lay = {k[6:]: (v["TP"], v["FP"]) for k, v in r.items() if k.startswith("layer:")}
        rows.append(f"{s[:12]:12s} att {p['attacks']}/{r['n_attacks']} TP {p['TP']:4d} FP {p['FP']:4d} ({p['FP/day']:6.1f}/d) rec {p['recall']:.3f} {lay}")
        fps.append(p["FP/day"]); att += p["attacks"]; tot += r["n_attacks"]
        if r["gt_nodes"]: recs.append(p["recall"])
    print(f"== {name}: attacks {att}/{tot}, FP/day mean {sum(fps)/max(1,len(fps)):.1f} ({len(fps)} sets), recall mean {sum(recs)/max(1,len(recs)):.3f}")
    print("\n".join(rows))
