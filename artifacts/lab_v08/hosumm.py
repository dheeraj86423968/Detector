import json, glob, sys
tot = {k: [0, 0, 0, 0] for k in ("0.6", "0.7", "0.8")}
for f in sorted(glob.glob("ho-*.json")):
    r = json.load(open(f))
    print(f"== {r['dataset']} {r['host']}: {len(r['test_days'])} test days, {r['n_attacks']} attacks, gt nodes in test {r['0.8']['gt_in_test']}")
    for k in ("0.6", "0.7", "0.8"):
        x = r[k]
        print(f"  {k}: attacks {x['attacks']}  TP {x['TP']:4d}  FP {x['FP']:5d} ({x['FP/day']:6.1f}/d)  recall {x['recall']:.3f}  by layer {x['by_layer']}  TP by layer {x['by_layer_tp']}")
        t = tot[k]; t[0] += x["attacks"]; t[1] += r["n_attacks"] if x is r["0.8"] or True else 0; t[2] += x["TP"]; t[3] += x["FP"]
for k, t in tot.items():
    print(f"TOTAL {k}: attacks {t[0]}/{t[1]}  TP {t[2]}  FP {t[3]}")
