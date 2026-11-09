"""Lab 0.10 part 1: totals per prevalence variant over the 16 sets + the pre-registered rule (PROTOCOL.md)."""
import glob, json
rows = {json.load(open(f))["set"]: json.load(open(f)) for f in sorted(glob.glob("res13-*.json"))}
print(f"{len(rows)} sets")
V = ["P0", "P1", "P1e", "P2", "P2e"]
tot = {}
for k in V:
    att = sum(r[k]["attacks"] for r in rows.values()); n = sum(min(r["n_attacks"], 10) if r["set"] != "ATLASV2_EDR-h2" else 0 for r in rows.values())
    fp = sum(r[k]["FP"] for r in rows.values()); tp = sum(r[k]["TP"] for r in rows.values()); days = sum(r["days"] for r in rows.values())
    rec = [r[k]["recall"] for r in rows.values() if r["gt_nodes"]]
    nov = sum(r[k]["by_layer"].get("novelty", 0) - r[k]["by_layer_tp"].get("novelty", 0) for r in rows.values())
    tot[k] = dict(att=att, n=n, tp=tp, fp=fp, fpd=fp / days, rec=sum(rec) / len(rec), prec=tp / max(1, tp + fp), nov_fp=nov)
    print(f"{k:4s}: attacks {att}/{n}  TP {tp}  FP {fp} ({fp/days:.1f}/day, {days} days)  new-program FP {nov}  precision {tot[k]['prec']:.3f}  mean node recall {tot[k]['rec']:.3f}")
ok = {}
for k in V[1:]:
    lost = [s for s, r in rows.items() if set(r["P0"]["attacks_found"]) - set(r[k]["attacks_found"])]
    r3 = tot[k]["rec"] >= 0.9 * tot["P0"]["rec"]
    ok[k] = not lost and r3
    print(f"{k}: no attack lost {not lost} {lost}; recall {tot[k]['rec']:.3f} >= {0.9*tot['P0']['rec']:.3f} {r3} -> {'accepted' if ok[k] else 'rejected'}")
acc = [k for k in V[1:] if ok[k]]
if acc:
    best = min(tot[k]["fp"] for k in acc)
    pref = ["P2e", "P2", "P1e", "P1"]
    choice = next(k for k in pref if k in acc and tot[k]["fp"] <= best * 1.05)
    print(f"fewest FP among accepted: {best}; choice (most conservative within 5 %): {choice}")
else:
    print("no variant accepted: no prevalence change")
for s, r in rows.items():
    print(f"{s:20s} " + " | ".join(f"{k} {r[k]['attacks']}/{r['n_attacks']} TP {r[k]['TP']:3d} FP {r[k]['FP']:4d}" for k in V))
