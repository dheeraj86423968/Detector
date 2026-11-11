"""Join rate of a node-level score file (index_id column) with the lab's node ids (entity 'uuid' of the lab host's
eval-test registry = framework index_id). Usage: join_check.py SCORES.csv.gz REGISTRY.json [--test-days d1,d2 STORE]
Reports: rows, rows joined, GT rows (gt=1), GT rows joined; and, if a store is given, how many of the lab's test-day
nodes are covered by the score file."""
import csv, gzip, json, os, sys
import numpy as np
sf, reg = sys.argv[1], sys.argv[2]
ids = {e["uuid"] for e in json.load(open(reg))["entities"]}
n = j = g = gj = 0
for r in csv.DictReader(gzip.open(sf, "rt")):
    n += 1; ok = r["index_id"] in ids; j += ok
    if r["gt"] == "1":
        g += 1; gj += ok
out = {"scores": sf, "rows": n, "rows_joined": j, "gt_rows": g, "gt_rows_joined": gj,
       "join_rate": round(j / n, 4) if n else None, "gt_join_rate": round(gj / g, 4) if g else None}
print(json.dumps(out))
