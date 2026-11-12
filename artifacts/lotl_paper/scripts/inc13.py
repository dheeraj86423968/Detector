"""Lab 0.10 incidents: group the alert rows of eval13 with the server's grouping (pdp_server.incidents) and measure
incidents per day, false-positive incidents (no ground-truth alert), detected attacks and buried attacks (detected,
but every incident holding the attack's alerts has < 10 % ground-truth alerts).
Usage: inc13.py [--grouping G0,...] [--variants P0,...] rows13-*.json.gz > out.json"""
import argparse, gzip, importlib, json, sys
from collections import Counter, defaultdict
from pdp_server import incidents as inc

ap = argparse.ArgumentParser(); ap.add_argument("files", nargs="+"); ap.add_argument("--grouping", default="G0")
ap.add_argument("--variants", default="P0"); ap.add_argument("--detail", action="store_true")
a = ap.parse_args()

BURIED_SHARE = 0.10     # an attack is buried when every incident holding it is < 10 % ground-truth alerts
GROUPINGS = {"G0": inc.group}
try:
    import groupings13
    GROUPINGS.update(groupings13.GROUPINGS)
except ImportError:
    pass


def measure(groups, attacks_all, days):
    fp = tp = 0; att_inc = defaultdict(list); sizes = []
    for g in groups:
        top = min(g, key=inc._det_key)
        is_tp = any(r["gt"] for r in g)
        tp += is_tp; fp += not is_tp; sizes.append(len(g))
        share = sum(r["gt"] for r in g) / len(g)
        for x in {x for r in g for x in r["attacks"]}:
            att_inc[x].append(share >= BURIED_SHARE)
    det = sorted(att_inc)
    buried = sorted(x for x, tops in att_inc.items() if not any(tops))
    return {"incidents": len(groups), "fp_incidents": fp, "tp_incidents": tp, "fp_inc_per_day": round(fp / max(1, days), 2),
            "attacks": len(det), "attacks_found": det, "buried": buried, "max_alerts": max(sizes) if sizes else 0}


out = {}
for f in a.files:
    d = json.load(gzip.open(f, "rt"))
    out[d["set"]] = {"days": d["days"]}
    for v in a.variants.split(","):
        rows = sorted((dict(r, context=d["ctx"][r["ctx"]]) for r in d["rows"][v]), key=lambda r: (r["window_start_ns"], r["id"]))
        for gname in a.grouping.split(","):
            groups = GROUPINGS[gname](rows)
            m = measure(groups, d["attacks"], d["days"]); m["alerts"] = len(rows)
            if a.detail:
                m["list"] = [{"n": len(g), "gt": sum(r["gt"] for r in g), "top": (lambda t: f"{t['layer']}/{t['rule']} {t['label'][:90]}")(min(g, key=inc._det_key)),
                              "t0": g[0]["window_start_ns"], "t1": g[-1]["window_start_ns"],
                              "layers": dict(Counter(r["layer"] for r in g))} for g in groups]
            out[d["set"]][f"{v}/{gname}"] = m
            print(f"{d['set']:20s} {v}/{gname}: alerts {len(rows):5d} incidents {m['incidents']:4d} (FP {m['fp_incidents']:4d}, {m['fp_inc_per_day']}/day) "
                  f"attacks {m['attacks']} buried {len(m['buried'])}", file=sys.stderr)
json.dump(out, sys.stdout, indent=1)
