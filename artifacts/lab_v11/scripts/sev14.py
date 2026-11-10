"""Lab 0.11 exploration: the shipped 0.10 incidents (P2 rows of lab 0.10, product grouping incl. 7-day recurrence) with
the product's own severity (incidents.summarise with behaviours.analyse). Per set: incidents by severity, false-
positive incidents by severity, and per attack the highest severity of an incident that holds it (>= 10 % ground truth).
Usage: sev14.py rows13-*.json.gz > out.json"""
import gzip, json, sys
from collections import Counter, defaultdict
from pdp_server import incidents as inc, behaviours as beh

SEV = ["low", "medium", "high", "critical"]
out = {}
for f in sys.argv[1:]:
    d = json.load(gzip.open(f, "rt"))
    rows = sorted((dict(r, context=d["ctx"][r["ctx"]]) for r in d["rows"]["P2"]), key=lambda r: (r["window_start_ns"], r["id"]))
    for r in rows:
        r.setdefault("endpoint_name", d["set"]); r.setdefault("status", "open"); r.setdefault("display", None)
    groups = inc.group(rows)
    res = {"days": d["days"], "incidents": [], "attacks": {}}
    best = defaultdict(lambda: -1)
    for g in groups:
        s = inc.summarise(g, beh.analyse(g))
        gt = sum(r["gt"] for r in g); share = gt / len(g)
        atts = sorted({x for r in g for x in r["attacks"]})
        for x in atts:
            if share >= 0.10:
                best[x] = max(best[x], SEV.index(s["severity"]))
        res["incidents"].append({"sev": s["severity"], "n": len(g), "gt": gt, "attacks": atts, "title": s["title"][:120],
                                 "layers": dict(Counter(r["layer"] for r in g)), "rules": dict(Counter(r["rule"] for r in g)),
                                 "beh": [b["kind"] for b in s["behaviours"]], "t0": g[0]["window_start_ns"]})
    res["attacks"] = {x: SEV[v] if v >= 0 else "buried" for x, v in best.items()}
    out[d["set"]] = res
    fp = Counter(i["sev"] for i in res["incidents"] if not i["gt"])
    print(f"{d['set']:20s} days {d['days']:2d} FP by sev {dict(fp)} attacks {res['attacks']}", file=sys.stderr)
json.dump(out, sys.stdout)
