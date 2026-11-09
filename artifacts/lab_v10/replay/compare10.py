"""Replay vs lab, per set: the lab's 0.10 result (res13 P2, as imported into the console as lab10-*) next to what the real
agent replay (replay10-*) reported. Node-level scoring as the lab (artifacts/lab_v10/scripts/eval13.py): an alerted
node is a TP when it is a ground-truth node, an attack is found when one of its nodes is alerted; FP = alerted nodes
that are not. Alerts and incidents as the console shows them (pdp_server.incidents.grouped); an incident is false
when none of its alerts is a ground-truth node.

  python3 artifacts/lab_v10/replay/compare10.py OUT.json        (host; reads the platform through the API container)
"""
import ast
import csv
import gzip
import json
import os
import subprocess
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..")
GT_ROOT = os.environ.get("PDP_GT_HOST_DIR", "/root/PIDSMaker/Ground_Truth/orthrus")
HELDOUT = "/var/lib/docker/volumes/pdp_pdp_data/_data/heldout"
SETS = json.load(open(os.path.join(LAB, "import", "sets10.json")))
HO = {"ATLASV2_EDR-h1": "ATLASV2_EDR/h1", "ATLASV2_EDR-h2": "ATLASV2_EDR/h2", "TRACE_E3-trace": "TRACE_E3/trace"}

EXPORT = r'''
import json, sys
from pdp_server import db, incidents as I
out = {}
with db.conn() as c:
    eps = db.q(c, "SELECT id, name FROM endpoints WHERE (name LIKE 'lab10-%%' OR name LIKE 'replay10-%%') AND phase <> 'retired'")
    for e in eps:
        rows = db.q(c, "SELECT id, node_uuid, layer, rule, window_start_ns FROM alerts WHERE endpoint_id=%s AND allowed_by IS NULL", (e["id"],))
        inc = I.grouped(c, [str(e["id"])])
        out[e["name"]] = {"alerts": [[r["id"], r["node_uuid"], r["layer"], r["rule"], int(r["window_start_ns"])] for r in rows],
                          "incidents": [[a["id"] for a in g] for g in inc]}
json.dump(out, sys.stdout)
'''


def load_gt(files, names=None):        # as artifacts/lab_v10/scripts/common8.load_gt
    gt = defaultdict(set)
    for j, f in enumerate(files):
        k = names[j] if names else os.path.basename(f)[5:-4]
        for row in csv.reader(open(os.path.join(GT_ROOT, f))):
            if len(row) >= 3 and row[2].strip():
                gt[k].add(row[2].strip())
    return gt


def gt_of(s):
    src = open(os.path.join(LAB, "scripts", "common8.py")).read()
    ep = ast.literal_eval(src[src.index("_EP = {") + 6:src.index("\n}\n", src.index("_EP = {")) + 2])
    if s in ep:
        return load_gt(ep[s][2])
    man = json.load(open(os.path.join(HELDOUT, HO.get(s, s.replace("-", "/")), "manifest.json")))
    return load_gt([g["csv"] for g in man["ground_truth"].values()], names=list(man["ground_truth"]))


def score(alerts, incidents, gt):
    allgt = set().union(*gt.values()) if gt else set()
    nodes = {a[1] for a in alerts}
    tp = nodes & allgt
    found = sorted({k for k, v in gt.items() if v & nodes})
    gtid = {a[0] for a in alerts if a[1] in allgt}
    return {"alerts": len(alerts), "TP": len(tp), "FP": len(nodes - allgt), "attacks": len(found), "attacks_found": found,
            "incidents": len(incidents), "fp_incidents": sum(1 for g in incidents if not set(g) & gtid),
            "by_layer": {l: sum(1 for a in alerts if a[2] == l) for l in sorted({a[2] for a in alerts})}}


def main(out):
    api = next(n for n in subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True).stdout.split()
               if n.startswith("pdp-api-"))
    exp = json.loads(subprocess.run(["docker", "exec", "-i", api, "python", "-"], input=EXPORT, capture_output=True, text=True,
                                    check=True).stdout)
    res, tot = {}, defaultdict(lambda: defaultdict(int))
    for s in SETS:
        gt = gt_of(s)
        lab_res = json.load(open(os.path.join(LAB, "results", f"res13-{s}.json")))["P2"]
        n = "-" + s.lower().replace("_", "-")
        r = {"n_attacks": len(gt), "gt_nodes": len(set().union(*gt.values())) if gt else 0,
             "lab": {k: lab_res[k] for k in ("attacks", "TP", "FP", "rows", "attacks_found")}}
        for k, ep in (("console_lab10", "lab10" + n), ("replay10", "replay10" + n)):
            if ep in exp:
                r[k] = score(exp[ep]["alerts"], exp[ep]["incidents"], gt)
        # self-check: the lab rows scored by this script give the lab's numbers
        rows = json.load(gzip.open(os.path.join(LAB, "results", f"rows13-{s}.json.gz"), "rt"))["rows"]["P2"]
        chk = score([[x["id"], x["node_uuid"], x["layer"], x["rule"], x["window_start_ns"]] for x in rows], [], gt)
        r["selfcheck_ok"] = (chk["TP"], chk["FP"], chk["attacks"]) == (lab_res["TP"], lab_res["FP"], lab_res["attacks"])
        res[s] = r
        for k in ("lab", "console_lab10", "replay10"):
            if k in r:
                for m in ("attacks", "TP", "FP", "alerts", "rows", "incidents", "fp_incidents"):
                    tot[k][m] += r[k].get(m, 0)
        rp = r.get("replay10")
        print(f"{s:20s} attacks {r['n_attacks']:2d} | lab {r['lab']['attacks']:2d} att TP {r['lab']['TP']:3d} FP {r['lab']['FP']:4d} | "
              + (f"replay {rp['attacks']:2d} att TP {rp['TP']:3d} FP {rp['FP']:4d} alerts {rp['alerts']:4d} inc {rp['incidents']:3d} "
                 f"(false {rp['fp_incidents']:3d})" if rp else "replay -") + ("" if r["selfcheck_ok"] else "  SELF-CHECK FAILED"))
    res["_totals"] = {k: dict(v) for k, v in tot.items()}
    print(json.dumps(res["_totals"]))
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main(sys.argv[1])
