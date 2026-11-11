"""Shared metrics. adp_pidsmaker = PIDSMaker evaluation_utils.plot_detected_attacks_vs_precision (np.argsort order,
attacks counted on TP nodes only); adp13 = pdp_server.tools.darpa_eval.adp (copied: stable sort by -score);
adp_provfusion = ProvFusion try_different_threshold.plot_detected_attacks_vs_precision ordering (ties: GT first)."""
from collections import defaultdict
import numpy as np


def _curve(order_labels, order_attacks, total):
    """Vectorised version of the loop in PIDSMaker/adp13 (identical result): precision after each node, % attacks
    detected so far, max detected % per distinct precision value, trapezoid area."""
    lab = np.asarray(order_labels, dtype=bool)
    if len(lab) == 0:
        return 0.0
    tp = np.cumsum(lab); n = np.arange(1, len(lab) + 1); prec = tp / n
    det = set(); first_idx = {}
    for i in np.where(lab)[0]:
        for a in order_attacks[i]:
            if a not in first_idx:
                first_idx[a] = i
    newly = np.zeros(len(lab)); 
    for a, i in first_idx.items():
        newly[i] += 1
    detp = 100.0 * np.cumsum(newly) / total
    xs = np.concatenate([[0.0], prec]); ys = np.concatenate([[0.0], detp])
    ux, inv = np.unique(xs, return_inverse=True)
    my = np.full(len(ux), -np.inf); np.maximum.at(my, inv, ys)
    return float(np.trapz(my, ux) / 100.0)


def _curve_loop(order_labels, order_attacks, total):
    tp = fp = 0; det = set(); p2d = defaultdict(float); p2d[0.0] = 0.0
    for lab, att in zip(order_labels, order_attacks):
        if lab:
            tp += 1; det |= att
        else:
            fp += 1
        p = tp / (tp + fp)
        p2d[p] = max(p2d[p], 100.0 * len(det) / total)
    xs = sorted(p2d); ys = [p2d[x] for x in xs]
    return float(np.trapz(ys, xs) / 100.0)


def adp_order(scores, labels, node_attacks, order):
    total = len(set().union(*[a for a in node_attacks if a])) or 1
    return _curve([labels[i] for i in order], [node_attacks[i] if labels[i] else set() for i in order], total)


def adp_pidsmaker(scores, labels, node_attacks):
    return adp_order(scores, labels, node_attacks, np.argsort(scores)[::-1])


def adp13(scores, labels, node_attacks):
    return adp_order(scores, labels, node_attacks, np.argsort(-np.asarray(scores), kind="stable"))


def adp_provfusion(scores, labels, node_attacks):
    # sort_with_preferred_index_np: lexsort((priorities, values)) with priority 1 for label 1, then reversed
    pr = np.where(np.asarray(labels) == 1, 1, 0)
    order = np.lexsort((pr, np.asarray(scores)))[::-1]
    return adp_order(scores, labels, node_attacks, order)


def adp_worst(scores, labels, node_attacks):
    pr = np.where(np.asarray(labels) == 1, 0, 1)
    order = np.lexsort((pr, np.asarray(scores)))[::-1]
    return adp_order(scores, labels, node_attacks, order)


def adp_random_ties(scores, labels, node_attacks, n=200, seed=0):
    rng = np.random.default_rng(seed); s = np.asarray(scores, dtype=float); vals = []
    for _ in range(n):
        r = rng.random(len(s))
        order = np.lexsort((r, s))[::-1]
        vals.append(adp_order(scores, labels, node_attacks, order))
    return float(np.mean(vals)), float(np.std(vals))


def op_point(pred, labels, node_attacks, n_attacks):
    pred = np.asarray(pred, bool); labels = np.asarray(labels, bool)
    tp = int((pred & labels).sum()); fp = int((pred & ~labels).sum())
    det = set()
    for i in np.where(pred & labels)[0]:
        det |= node_attacks[i]
    return {"TP": tp, "FP": fp, "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0,
            "attacks": len(det), "n_attacks": n_attacks, "gt_nodes_evaluated": int(labels.sum()),
            "nodes_evaluated": int(len(labels))}


def all_adps(scores, labels, node_attacks, random_n=200):
    s = np.asarray(scores, dtype=float)
    out = {"adp_pidsmaker": round(adp_pidsmaker(s, labels, node_attacks), 4),
           "adp13": round(adp13(s, labels, node_attacks), 4),
           "adp_gt_first_ties": round(adp_provfusion(s, labels, node_attacks), 4),
           "adp_worst_ties": round(adp_worst(s, labels, node_attacks), 4),
           "distinct_scores": int(len(np.unique(s)))}
    m, sd = adp_random_ties(s, labels, node_attacks, n=random_n)
    out["adp_random_ties_mean"] = round(m, 4); out["adp_random_ties_sd"] = round(sd, 4)
    return out
