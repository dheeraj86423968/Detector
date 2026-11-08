"""Totals per variant over the 16 sets + the pre-registered acceptance rules (PROTOCOL.md)."""
import glob, json
DEV = ["CADETS_E3", "THEIA_E3", "OPTC_H201"]
rows = {json.load(open(f))["set"]: json.load(open(f)) for f in sorted(glob.glob("res9-*.json"))}
print(f"{len(rows)} sets")
tot = {}
for k in "RAB":
    att = sum(r[k]["attacks"] for r in rows.values()); n = sum(min(r["n_attacks"], 10) if r["set"] != "ATLASV2_EDR-h2" else 0 for r in rows.values())
    fp = sum(r[k]["FP"] for r in rows.values()); tp = sum(r[k]["TP"] for r in rows.values())
    days = sum(r["days"] for r in rows.values())
    rec = [r[k]["recall"] for r in rows.values() if r["gt_nodes"]]
    tot[k] = dict(att=att, n=n, tp=tp, fp=fp, fpd=fp / days, rec=sum(rec) / len(rec), prec=tp / max(1, tp + fp))
    print(f"{k}: attacks {att}/{n}  TP {tp}  FP {fp} ({fp/days:.1f}/day over {days} days)  precision {tot[k]['prec']:.3f}  mean node recall {tot[k]['rec']:.3f}")
for k in "AB":
    lost = [s for s, r in rows.items() if r[k]["attacks"] < r["R"]["attacks"]]
    r1, r2, r3 = not lost, tot[k]["fp"] < tot["R"]["fp"], tot[k]["rec"] >= 0.9 * tot["R"]["rec"]
    print(f"{k}: rule1 no attack lost {r1} {lost}; rule2 fewer FP {r2}; rule3 recall {tot[k]['rec']:.3f} >= {0.9*tot['R']['rec']:.3f} {r3}")
print(f"B vs A FP reduction {(1 - tot['B']['fp'] / tot['A']['fp']) * 100:.1f}% (B chosen only if >= 15%)")
for s, r in rows.items():
    print(f"{s:20s} " + " | ".join(f"{k} {r[k]['attacks']}/{r['n_attacks']} TP {r[k]['TP']:3d} FP {r[k]['FP']:4d}" for k in "RAB"))
