"""Score one ProvFusion run. Recomputes, with ProvFusion's own functions and the same steps as
try_different_threshold.method_12_with_different_normalization (percentile normalisation, multi=1, alpha=5), the
per-node vote count of the 7 detectors on every test graph, then: operating point = vote >= 4 (unique nodes over
graphs, as ProvFusion counts), ranking score = max vote over test graphs (ProvFusion's ADP score), all ADP variants
of metrics.py, plus the label-free continuous tie-break 'votes, then max over graphs of A1+A2+A3_modified'.
Usage: pf_score.py RESULTS.pt DATA.pt GT_NIDS.pt ATTACK_MAP.pt --out out.json [--label run-name]"""
import argparse, json, sys
from collections import defaultdict
sys.path[:0] = ["/pf", "/scripts"]
import numpy as np, torch
from try_different_threshold import calibrate_scores_cpu, dynamic_weight_fusion, dynamic_weight_fusion_with_two
import metrics as M

ap = argparse.ArgumentParser(); ap.add_argument("res"); ap.add_argument("data"); ap.add_argument("gt"); ap.add_argument("amap")
ap.add_argument("--out", required=True); ap.add_argument("--label", default="")
ap.add_argument("--scores", default="", help="node-level score file (.csv.gz)"); ap.add_argument("--test_days", type=int, default=0); a = ap.parse_args()
(nd1, val_baseline, emb_baseline, nd3, total_uuid_to_max, edge_loss_baseline, A1b, A2b, A3b, max_A3) = torch.load(a.res, map_location="cpu")
graphs = torch.load(a.data, map_location="cpu")[0]
gt = set(int(x) for x in torch.load(a.gt))
amap = torch.load(a.amap)
b1 = val_baseline[0]; b2 = emb_baseline[0]; b3 = np.where(np.isinf(edge_loss_baseline), 0, edge_loss_baseline)
thr = 0.99999
st = np.stack([A1b, A2b, A3b], axis=1); st.sort(axis=1)
thr_top2 = np.max(np.sum(st[:, -2:], axis=1))
thr_three = np.max(A1b + A2b + A3b)
alpha = 5
thr_fused = np.max(dynamic_weight_fusion(A1b, A2b, A3b, alpha=alpha)[1])
thr_fused2 = np.max(dynamic_weight_fusion_with_two(st[:, -2], st[:, -1], alpha=alpha)[1])
votes = defaultdict(int); cont = defaultdict(lambda: -np.inf); alerted = set()
per_det = {k: set() for k in range(1, 8)}
for gi, g in enumerate(graphs["test"]):
    uids = g.ndata["uuid"].cpu().numpy()
    eb = np.array(list(total_uuid_to_max[gi].values())); eb = np.where(np.isinf(eb), 0, eb)
    A1 = calibrate_scores_cpu(b1, nd1[gi]); A2 = calibrate_scores_cpu(b2, nd3[gi]); A3c = calibrate_scores_cpu(b3, eb)
    A3m = np.where(A3c == 1.0, eb / max_A3, A3c)
    m = [None, A1 >= thr, A2 >= thr, A3c >= thr]
    s = np.stack([A1, A2, A3m], axis=1); s.sort(axis=1)
    m.append(np.sum(s[:, -2:], axis=1) >= thr_top2)
    m.append(dynamic_weight_fusion_with_two(s[:, -2], s[:, -1], alpha=alpha)[1] >= thr_fused2)
    three = A1 + A2 + A3m
    m.append(three > thr_three)
    m.append(dynamic_weight_fusion(A1, A2, A3m, alpha=alpha)[1] > thr_fused)
    v = sum(m[k].astype(np.int8) for k in range(1, 8))
    for k in range(1, 8):
        per_det[k].update(uids[m[k]].tolist())
    for u, vv, c in zip(uids.tolist(), v.tolist(), three.tolist()):
        if vv > votes[u] or u not in votes:
            votes[u] = max(votes.get(u, 0), vv)
        votes[u] = max(votes[u], vv); cont[u] = max(cont[u], c)
        if vv >= 4:
            alerted.add(u)
nodes = np.array(sorted(votes)); vote = np.array([votes[u] for u in nodes], float)
contv = np.array([cont[u] for u in nodes], float)
labels = np.array([u in gt for u in nodes])
node2att = defaultdict(set)
for k, v in amap.items():
    for n in v["nids"]:
        if int(n) in gt:
            node2att[int(n)].add(k)
natt = [node2att.get(int(u), set()) for u in nodes]
n_attacks = len({k for k, v in amap.items() if any(int(n) in gt for n in v["nids"])})
pred = np.array([u in alerted for u in nodes])
out = {"label": a.label, "results_file": a.res, "operating_point": M.op_point(pred, labels, natt, n_attacks),
       "adp_votes": M.all_adps(vote, labels, natt),
       "adp_votes_then_A123": M.all_adps(vote * 10.0 + contv, labels, natt, random_n=20),
       "gt_nodes_total": len(gt), "gt_nodes_in_test_graphs": int(labels.sum()),
       "attacks_with_gt_in_test_graphs": len({a_ for s_ in natt for a_ in s_}),
       "per_detector_alerts": {k: len(v) for k, v in per_det.items()},
       "vote_histogram": {int(k): int((vote == k).sum()) for k in range(8)}}
if a.test_days:
    out["operating_point"]["test_days"] = a.test_days
    out["operating_point"]["FP_per_test_day"] = round(out["operating_point"]["FP"] / a.test_days, 2)
if a.scores:
    import gzip
    with gzip.open(a.scores, "wt") as f:
        f.write("index_id,score,vote,a123_max,alert,gt\n")
        for u, v, c, p, l in zip(nodes.tolist(), vote.tolist(), contv.tolist(), pred.tolist(), labels.tolist()):
            f.write(f"{u},{v*10.0+c:.6g},{int(v)},{c:.6g},{int(p)},{int(l)}\n")
json.dump(out, open(a.out, "w"), indent=1)
print(json.dumps(out, indent=1))
