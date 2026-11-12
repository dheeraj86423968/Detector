import json, gzip, glob, sys
from collections import Counter, defaultdict
S = sys.argv[1]; tag = sys.argv[2] if len(sys.argv) > 2 else "res17"
FAM = {"CARBANAKV2": "CARBANAKv2", "OPTC": "OpTC", "ATLASV2": "ATLASv2", "THEIA_E5": "THEIA E5"}
fam = lambda s: next((v for k, v in FAM.items() if s.startswith(k)), "DARPA E3")
tot = defaultdict(Counter); pf = defaultdict(lambda: defaultdict(Counter)); att = defaultdict(set); det = defaultdict(set); V = None
rows = []
for f in sorted(glob.glob(f"{S}/{tag}-*.json.gz")):
    r = json.load(gzip.open(f)); s = r["set"]
    V = [k for k in r if k not in ("set", "fleet", "n_attacks", "gt_nodes", "days", "nodes")]
    line = f"{s:20}"
    for v in V:
        x = r[v]; tot[v]["TP"] += x["TP"]; tot[v]["FP"] += x["FP"]; pf[v][fam(s)]["FP"] += x["FP"]; pf[v][fam(s)]["TP"] += x["TP"]
        att[v] |= {(s, a) for a in x["attacks_found"]}; det[v] |= {(s, a) for a in x["attacks_det"]}
        line += f" | {x['attacks']:2} {x['TP']:4} {x['FP']:5}"
    rows.append(line)
print(f"{'set':20} | " + " | ".join(f"{v:>4}: att TP FP".ljust(13) for v in V)); print("\n".join(rows))
ref = sys.argv[3] if len(sys.argv) > 3 else "R0"
print("\nvariant attacks det-alone TP FP | lost vs %s | gained | family FP" % ref)
for v in V:
    print(f"{v:4} {len(att[v]):3} {len(det[v]):3} {tot[v]['TP']:5} {tot[v]['FP']:6} | lost {sorted(att[ref]-att[v])} | gained {sorted(att[v]-att[ref])} | " + ", ".join(f"{k} {pf[v][k]['FP']}" for k in sorted(pf[v])))
