"""lab7 shared: datasets, ground truth, metrics."""
import csv, json, math, os, sys, time
from collections import defaultdict
import numpy as np

D = {  # eid, test days, gt files  (dev sets; held-out sets are added only for the final frozen run)
    "CADETS_E3": ("5eafc637-14c7-4074-b4d3-4e611dea925e", ["2018-04-06", "2018-04-11", "2018-04-12", "2018-04-13"],
                  ["E3-CADETS/node_Nginx_Backdoor_06.csv", "E3-CADETS/node_Nginx_Backdoor_12.csv", "E3-CADETS/node_Nginx_Backdoor_13.csv"]),
    "THEIA_E3": ("b4021490-6dd4-4dfb-8628-b3e55af27b90", ["2018-04-10", "2018-04-12", "2018-04-13"],
                 ["E3-THEIA/node_Browser_Extension_Drakon_Dropper.csv", "E3-THEIA/node_Firefox_Backdoor_Drakon_In_Memory.csv"]),
    "OPTC_H201": ("f85bab6a-0fce-4b21-81d8-dd967b8d4395", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h201/node_h201_0923.csv"]),
    "OPTC_H501": ("18978a51-ac8f-4afd-8f7a-c3003fa744c2", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h501/node_h501_0924.csv"]),
    "OPTC_H051": ("6ca8a927-9474-45be-870a-52bd56133b0e", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h051/node_h051_0925.csv"]),
    # seen checks (0.6 held-out, now seen): telemetry-poor
    "CLEARSCOPE_E3": ("5ef60025-b74e-417a-8e48-7ab1c7dbcd67", ["2018-04-11", "2018-04-12"], ["E3-CLEARSCOPE/node_clearscope_e3_firefox_0411.csv"]),
    "FIVEDIRECTIONS_E3": ("01ca45e0-721f-4181-a4cb-33682335812a", ["2018-04-09", "2018-04-10", "2018-04-11"],
                          ["E3-FIVEDIRECTIONS/node_fivedirections_e3_excel_0409.csv", "E3-FIVEDIRECTIONS/node_fivedirections_e3_firefox_0411.csv"]),
}
BUNDLES = {l.split()[0]: l.split()[2].split(",") for l in open("/lab/jobs05.txt")}


def log(m):
    print(time.strftime("%H:%M:%S"), m, file=sys.stderr, flush=True)


def load_gt(files):
    gt = defaultdict(set)
    for f in files:
        for row in csv.reader(open(os.path.join("/gt", f))):
            if len(row) >= 3 and row[2].strip():
                gt[os.path.basename(f)[5:-4]].add(row[2].strip())
    return gt


def bundle_split(eid):
    m = json.load(open(f"/data/bundles/{eid}/{BUNDLES[eid][0]}/manifest.json"))
    return m["train_days"], m["val_day"]


def adp(scores, labels, node_attacks):
    total = len(set().union(*[a for a in node_attacks if a])) or 1
    order = np.argsort(-scores, kind="stable")
    tp = fp = 0; detected = set(); p2d = defaultdict(float); p2d[0.0] = 0.0
    for i in order:
        if labels[i]:
            tp += 1; detected |= node_attacks[i]
        else:
            fp += 1
        p = tp / (tp + fp)
        p2d[p] = max(p2d[p], 100.0 * len(detected) / total)
        if len(detected) == total and fp > 50000:
            break
    xs = sorted(p2d); ys = [p2d[x] for x in xs]
    return float(np.trapz(ys, xs) / 100.0)


def at(pred, labels, node_attacks):
    tp = int((pred & labels).sum()); fp = int((pred & ~labels).sum()); fn = int((~pred & labels).sum())
    det = set()
    for i in np.where(pred & labels)[0]:
        det |= node_attacks[i]
    return {"TP": tp, "FP": fp, "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0, "attacks": len(det)}


def budget(scores, labels, node_attacks, fp_budget):
    """recall / attacks when alerting the top nodes until fp_budget false positives (ties broken pessimistically)."""
    order = np.lexsort((labels.astype(int), -scores))      # among equal scores, benign first
    fp = 0; tp = 0; det = set()
    for i in order:
        if labels[i]:
            tp += 1; det |= node_attacks[i]
        else:
            fp += 1
            if fp > fp_budget:
                break
    return {"TP": tp, "recall": round(tp / max(1, labels.sum()), 3), "attacks": len(det)}


def report(name, scores, labels, node_attacks, n_att, ndays, thr=None):
    r = {"ADP": round(adp(scores, labels, node_attacks), 3), "n_attacks": n_att, "gt_nodes": int(labels.sum())}
    for b in (10, 50, 200):
        r[f"fp{b}/day"] = budget(scores, labels, node_attacks, b * ndays)
    if thr is not None:
        for k, t in thr.items():
            r[f"thr:{k}"] = at(scores > t, labels, node_attacks)
    return r
