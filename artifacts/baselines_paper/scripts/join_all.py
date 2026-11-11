"""Join rates of all score files (scores/*.csv.gz) with the lab registries (index_id vs registry 'uuid').
Writes results/join_rates.json. Run in a container with the lab volume at /data and the paper dir at /o."""
import csv, glob, gzip, json, os, re
REG = {"CADETS_E3": "/data/endpoints/5eafc637-14c7-4074-b4d3-4e611dea925e/eval-test/registry.json",
       "FIVEDIRECTIONS_E3": "/data/endpoints/01ca45e0-721f-4181-a4cb-33682335812a/eval-test/registry.json",
       "THEIA_E3": "/data/endpoints/b4021490-6dd4-4dfb-8628-b3e55af27b90/eval-test/registry.json",
       "OPTC_H051": "/data/endpoints/6ca8a927-9474-45be-870a-52bd56133b0e/eval-test/registry.json",
       "TRACE_E3": "/data/heldout/TRACE_E3/trace/eval-test/registry.json",
       "ATLASV2_H1": "/data/heldout/ATLASV2_EDR/h1/eval-test/registry.json",
       **{f"CARBANAKV2_H{i}": f"/data/heldout/CARBANAKV2_EDR/h{i}/eval-test/registry.json" for i in range(1, 6)}}
out = {}
files = sorted(glob.glob("/o/scores/*.csv.gz"))
byhost = {}
for f in files:
    m = re.match(r"(provfusion|velox|orthrus_non_snooped)_(.+)_s\d+\.csv\.gz", os.path.basename(f))
    if m:
        byhost.setdefault(m.group(2), []).append(f)
for host, fs in byhost.items():
    ids = {e["uuid"] for e in json.load(open(REG[host]))["entities"]}
    for f in fs:
        n = j = g = gj = 0
        for r in csv.DictReader(gzip.open(f, "rt")):
            n += 1; ok = r["index_id"] in ids; j += ok
            if r["gt"] == "1":
                g += 1; gj += ok
        out[os.path.basename(f)] = {"lab_registry": REG[host], "rows": n, "rows_joined": j, "gt_rows": g, "gt_rows_joined": gj,
                                    "join_rate": round(j / n, 4) if n else None, "gt_join_rate": round(gj / g, 4) if g else None}
        print(os.path.basename(f), out[os.path.basename(f)]["join_rate"], out[os.path.basename(f)]["gt_join_rate"], flush=True)
json.dump(out, open("/o/results/join_rates.json", "w"), indent=1)
