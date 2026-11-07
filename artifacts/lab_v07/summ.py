import json, sys
tag = sys.argv[1]
rows = []
for d in ["CADETS_E3","THEIA_E3","OPTC_H201","OPTC_H501","OPTC_H051","CLEARSCOPE_E3","FIVEDIRECTIONS_E3"]:
    for nm in (f"prod07-{tag}-{d}.json",):
        try:
            r = json.load(open(nm)); p = r["product"]
            lay = {k[6:]: (v["TP"], v["FP"]) for k, v in r.items() if k.startswith("layer:")}
            print(f"{d:18s} TP {p['TP']:4d} FP {p['FP']:4d} ({p['FP/day']:6.1f}/d) rec {p['recall']:.3f} att {p['attacks']}/{r['n_attacks']}  {lay}")
        except Exception as e:
            print(d, "missing")
for h in ["ATLASV2_EDR-h1","ATLASV2_EDR-h2","TRACE_E3-trace"]:
    try:
        r = json.load(open(f"seen{tag[1:]}-{h}.json")); p = r["0.7"]
        print(f"{h:18s} TP {p['TP']:4d} FP {p['FP']:4d} ({p['FP/day']:6.1f}/d) rec {p['recall']:.3f} att {p['attacks']}/{r['n_attacks']}  {p['by_layer']}")
    except Exception as e:
        print(h, "missing", e)
