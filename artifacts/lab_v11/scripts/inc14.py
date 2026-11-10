"""Lab 0.11 part 1: the review digest (pdp_server.incidents.review_digest) on the lab 0.10 alert rows (P2 = released),
scored with the product's own grouping and severity. Variants D0 (off), D2 (new_programs), D4 (new_programs_and_learned).
Usage: inc14.py rows13-*.json.gz > inc14.json   (per-set lines on stderr)"""
import gzip, json, sys
from collections import Counter, defaultdict
from pdp_server import incidents as inc, behaviours as beh

SEV = ["low", "medium", "high", "critical"]
VARIANTS = {"D0": "off", "D2": "new_programs", "D4": "new_programs_and_learned"}
BURIED_SHARE = 0.10
out = {}
for f in sys.argv[1:]:
    d = json.load(gzip.open(f, "rt"))
    rows = sorted((dict(r, context=d["ctx"][r["ctx"]]) for r in d["rows"]["P2"]), key=lambda r: (r["window_start_ns"], r["id"]))
    for r in rows:
        r.setdefault("endpoint_name", d["set"]); r.setdefault("status", "open"); r.setdefault("display", None)
    out[d["set"]] = {"days": d["days"]}
    for v, mode in VARIANTS.items():
        inc.DIGEST = mode
        groups = inc.group(rows)
        m = Counter(); att = defaultdict(list); items = []
        for g in groups:
            dig = isinstance(g, inc.Digest)
            s = inc.summarise(g, None if dig else beh.analyse(g))
            gt = sum(r["gt"] for r in g); share = gt / len(g); sev = SEV.index(s["severity"])
            m["items"] += 1; m["digests"] += dig
            if not gt:
                m["fp"] += 1; m["fp_medium"] += sev >= 1; m["fp_high"] += sev >= 2; m["fp_digest"] += dig
            for x in {x for r in g for x in r["attacks"]}:
                att[x].append((share >= BURIED_SHARE, dig, sev))
            items.append({"digest": dig, "sev": s["severity"], "n": len(g), "gt": gt, "title": s["title"][:100]})
        res = dict(m)
        res["attacks"] = sorted(att)
        res["buried"] = sorted(x for x, l in att.items() if not any(ok for ok, _, _ in l))
        res["only_digest"] = sorted(x for x, l in att.items() if all(dg for ok, dg, _ in l if ok) and any(ok for ok, _, _ in l))
        res["attention"] = sorted(x for x, l in att.items() if any(ok and sev >= 1 for ok, _, sev in l))
        res["items_list"] = items
        out[d["set"]][v] = res
        print(f"{d['set']:20s} {v}: items {m['items']:4d} (digests {m['digests']:3d}) FP {m['fp']:4d} FP>=med {m['fp_medium']:4d} "
              f"FP>=high {m['fp_high']:3d} attacks {len(att)} buried {len(res['buried'])} only-digest {len(res['only_digest'])}", file=sys.stderr)
json.dump(out, sys.stdout)
