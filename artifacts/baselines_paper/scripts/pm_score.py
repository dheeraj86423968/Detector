"""Score one PIDSMaker run from the per-epoch dumps written by pm_run.py. Headline = last evaluated epoch (no test
selection); reference = epoch with the best PIDSMaker ADP (= PIDSMaker's default best_adp pick, test-selected).
Attack map from the ORTHRUS CSVs (column 3 = index_id). Writes metrics JSON and, for the headline epoch, a node-level
score file index_id,score,alert,gt (.csv.gz).
Usage: pm_score.py DUMPDIR --gt-root /gt --gt rel1.csv rel2.csv --out out.json [--scores f.csv.gz] [--test_days N]"""
import argparse, csv, glob, gzip, json, os, pickle, re, sys
sys.path.insert(0, "/scripts")
import numpy as np
import metrics as M
ap = argparse.ArgumentParser(); ap.add_argument("dump"); ap.add_argument("--gt-root", default="/gt"); ap.add_argument("--gt", nargs="+")
ap.add_argument("--out", required=True); ap.add_argument("--scores", default=""); ap.add_argument("--test_days", type=int, default=0)
ap.add_argument("--label", default=""); a = ap.parse_args()
att = {}
for rel in a.gt:
    name = os.path.basename(rel)[:-4]
    for r in csv.reader(open(os.path.join(a.gt_root, rel))):
        if len(r) >= 3 and r[2].strip():
            att.setdefault(int(r[2]), set()).add(name)
files = sorted(glob.glob(os.path.join(a.dump, "model_epoch_*.pkl")), key=lambda f: int(re.findall(r"(\d+)\.pkl", f)[0]))
assert files, "no dumps"
per = []
for f in files:
    d = pickle.load(open(f, "rb")); res = d["results"]
    nodes = np.array(sorted(res)); sc = np.array([res[n][0] for n in nodes]); yh = np.array([res[n][1] for n in nodes], bool)
    yt = np.array([res[n][2] for n in nodes], bool)
    natt = [att.get(int(n), set()) if yt[i] else set() for i, n in enumerate(nodes)]
    n_att = len({x for s in natt for x in s})
    labels_match = all((int(n) in att) == bool(yt[i]) for i, n in enumerate(nodes))
    op = M.op_point(yh, yt, natt, len({x for s in att.values() for x in s}))
    if a.test_days:
        op["test_days"] = a.test_days; op["FP_per_test_day"] = round(op["FP"] / a.test_days, 2)
    adps = M.all_adps(sc, yt, natt, random_n=5)
    per.append({"epoch_file": os.path.basename(f), "thr": d["thr"], "operating_point": op, "adp": adps,
                "attacks_with_gt_in_test_graphs": n_att, "pidsmaker_labels_equal_csv_labels": labels_match,
                "_arrays": (nodes, sc, yh, yt)})
head = per[-1]; best = max(per, key=lambda p: p["adp"]["adp_pidsmaker"])
if a.scores:
    nodes, sc, yh, yt = head["_arrays"]
    with gzip.open(a.scores, "wt") as fh:
        fh.write("index_id,score,alert,gt\n")
        for n, s, h, t in zip(nodes.tolist(), sc.tolist(), yh.tolist(), yt.tolist()):
            fh.write(f"{n},{s:.6g},{int(h)},{int(t)}\n")
for p in per:
    p.pop("_arrays")
out = {"label": a.label, "headline_last_epoch": head, "reference_best_adp_epoch": best,
       "all_epochs": [{"epoch_file": p["epoch_file"], "adp_pidsmaker": p["adp"]["adp_pidsmaker"],
                       "TP": p["operating_point"]["TP"], "FP": p["operating_point"]["FP"],
                       "attacks": p["operating_point"]["attacks"]} for p in per]}
json.dump(out, open(a.out, "w"), indent=1)
print(json.dumps({k: out[k] for k in ("label", "all_epochs")}, indent=1))
print(json.dumps(head["operating_point"]), json.dumps(head["adp"]))
