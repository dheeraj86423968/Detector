"""lab8 shared: every development / seen set in one map (endpoint benchmarks and the seen held-out hosts)."""
import csv, json, os, sys, time
from collections import defaultdict
import numpy as np
from pdp_engine.data import WindowStore

_EP = {  # eid, test days, gt files
    "CADETS_E3": ("5eafc637-14c7-4074-b4d3-4e611dea925e", ["2018-04-06", "2018-04-11", "2018-04-12", "2018-04-13"],
                  ["E3-CADETS/node_Nginx_Backdoor_06.csv", "E3-CADETS/node_Nginx_Backdoor_12.csv", "E3-CADETS/node_Nginx_Backdoor_13.csv"]),
    "THEIA_E3": ("b4021490-6dd4-4dfb-8628-b3e55af27b90", ["2018-04-10", "2018-04-12", "2018-04-13"],
                 ["E3-THEIA/node_Browser_Extension_Drakon_Dropper.csv", "E3-THEIA/node_Firefox_Backdoor_Drakon_In_Memory.csv"]),
    "OPTC_H201": ("f85bab6a-0fce-4b21-81d8-dd967b8d4395", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h201/node_h201_0923.csv"]),
    "OPTC_H501": ("18978a51-ac8f-4afd-8f7a-c3003fa744c2", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h501/node_h501_0924.csv"]),
    "OPTC_H051": ("6ca8a927-9474-45be-870a-52bd56133b0e", ["2019-09-23", "2019-09-24", "2019-09-25"], ["h051/node_h051_0925.csv"]),
    "CLEARSCOPE_E3": ("5ef60025-b74e-417a-8e48-7ab1c7dbcd67", ["2018-04-11", "2018-04-12"], ["E3-CLEARSCOPE/node_clearscope_e3_firefox_0411.csv"]),
    "FIVEDIRECTIONS_E3": ("01ca45e0-721f-4181-a4cb-33682335812a", ["2018-04-09", "2018-04-10", "2018-04-11"],
                          ["E3-FIVEDIRECTIONS/node_fivedirections_e3_excel_0409.csv", "E3-FIVEDIRECTIONS/node_fivedirections_e3_firefox_0411.csv"]),
}
_HO = {"ATLASV2_EDR-h1": "ATLASV2_EDR/h1", "ATLASV2_EDR-h2": "ATLASV2_EDR/h2", "TRACE_E3-trace": "TRACE_E3/trace"}
BUNDLES = {l.split()[0]: l.split()[2].split(",") for l in open("/lab/jobs05.txt")}
ALL = list(_EP) + list(_HO)


class Set:
    """name, eval store, baseline store, train days, val day, test days, gt {attack: uuids}, source (0.5/0.6) bundle,
    work dir for upgraded bundles."""
    def __init__(self, name, heldout_root="/data/heldout"):
        self.name = name
        if name in _EP:
            eid, days, gtf = _EP[name]
            self.eval_dir, self.base_dir = f"/data/endpoints/{eid}/eval-test", f"/data/endpoints/{eid}/baseline"
            self.src = f"/data/bundles/{eid}/{BUNDLES[eid][0]}"
            m = json.load(open(self.src + "/manifest.json"))
            self.train_days, self.val_day, self.test_days = m["train_days"], m["val_day"], days
            self.gt = load_gt(gtf)
            self.work = f"/data/lab08/{eid}"
        else:
            h = os.path.join(heldout_root, _HO.get(name, name.replace("-", "/")))
            man = json.load(open(h + "/manifest.json"))
            self.eval_dir, self.base_dir = h + "/eval-test", h + "/baseline"
            self.train_days, self.val_day, self.test_days = man["train_days"], man["val_day"], man["test_days"]
            self.gt = load_gt([g["csv"] for g in man["ground_truth"].values()], names=list(man["ground_truth"]))
            self.work = f"/data/lab08/heldout/{man['dataset']}/{man['host']}"
            self.src = f"/data/lab07/heldout/{man['dataset']}/{man['host']}/b06"
        self.allgt = set().union(*self.gt.values()) if self.gt else set()

    def eval_store(self):
        return WindowStore(self.eval_dir)

    def base_store(self):
        return WindowStore(self.base_dir)


def log(m):
    print(time.strftime("%H:%M:%S"), m, file=sys.stderr, flush=True)


def load_gt(files, names=None):
    gt = defaultdict(set)
    for j, f in enumerate(files):
        k = names[j] if names else os.path.basename(f)[5:-4]
        for row in csv.reader(open(os.path.join("/gt", f))):
            if len(row) >= 3 and row[2].strip():
                gt[k].add(row[2].strip())
    return gt


def at(pred, labels, node_attacks):
    tp = int((pred & labels).sum()); fp = int((pred & ~labels).sum()); fn = int((~pred & labels).sum())
    det = set()
    for i in np.where(pred & labels)[0]:
        det |= node_attacks[i]
    return {"TP": tp, "FP": fp, "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0, "attacks": len(det)}
