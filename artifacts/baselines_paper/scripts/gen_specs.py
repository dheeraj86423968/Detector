"""Generate PIDSMaker (pm_) and ProvFusion (pf_) dataset specs for a converted lab host from its conversion report
(conv_<db>.json) - days = the lab's train / val / test lists, GT = the host's CSV subsets in /conv/gt_<x>/.
Usage: gen_specs.py CONV_JSON DS GTDIR_NAME OUTDIR"""
import json, os, sys
from collections import OrderedDict
rep = json.load(open(sys.argv[1])); DS, gtdir, out = sys.argv[2], sys.argv[3], sys.argv[4]
gts = sorted(k for k, v in rep["gt"].items() if v["in_host"] > 0)
rel = [f"../../../conv/{gtdir}/{g}" for g in gts]
tr, va, te = rep["train_days"], [rep["val_day"]], rep["test_days"]
alld = sorted(tr + va + te)
pm = {"raw_dir": "", "database": rep["db"], "database_all_file": rep["db"], "num_node_types": 3, "num_edge_types": 10,
      "timezone": "US/Eastern", "start_date": alld[0], "end_date": alld[-1], "train_dates": tr, "val_dates": va,
      "test_dates": te, "unused_dates": [], "ground_truth_relative_path": rel,
      "attack_to_time_window": [[r, f"{te[0]} 00:00:00", f"{te[-1]} 23:59:59"] for r in rel]}
months = OrderedDict()
for d in alld:
    months.setdefault(d[:7], []).append(int(d[8:]))
ranges = [[ym, min(v), max(v)] for ym, v in months.items()]
days = [int(d[8:]) for d in alld]
assert len(set(days)) == len(days), "day numbers repeat across months"
g = lambda ds_: [f"graph_{int(d[8:])}" for d in ds_]
pf = {"raw_dir": "", "database": rep["db"], "database_all_file": rep["db"], "num_node_types": 3, "num_edge_types": 10,
      "year_month": ranges[0][0], "start_end_day_range": [ranges[0][1], ranges[0][2] + 1], "month_ranges": ranges,
      "train_files": g(tr), "val_files": g(va), "test_files": g(te),
      "unused_files": [f"graph_{d}" for ym, a, b in ranges for d in range(a, b + 1) if f"graph_{d}" not in g(tr + va + te)],
      "ground_truth_relative_path": rel, "attack_to_time_window": []}
json.dump(pm, open(os.path.join(out, f"pm_{DS}.json"), "w"), indent=1)
json.dump(pf, open(os.path.join(out, f"pf_{DS}.json"), "w"), indent=1)
print(DS, ranges, len(gts), "GT files")
