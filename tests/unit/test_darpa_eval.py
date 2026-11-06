"""darpa_eval: the ADP and node-level metrics match PIDSMaker's definitions on a worked example.
Run in the server image: PYTHONPATH=engine:server python tests/unit/test_darpa_eval.py"""
import sys

import numpy as np

try:
    from pdp_server.tools.darpa_eval import adp, metrics
except ImportError as e:   # agent image: no psycopg2 / server package
    print(f"SKIP ({e})"); print("FAILURES: 0"); sys.exit(0)

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


# ranking: malicious(A) 0.9, benign 0.8, malicious(B) 0.7, benign 0.1
scores = np.array([0.9, 0.8, 0.7, 0.1]); labels = np.array([True, False, True, False])
att = [{"A"}, set(), {"B"}, set()]
# PIDSMaker curve points (precision -> max % detected): 0->0, 1->50, 0.5->50, 2/3->100, 0.5 again ->100 at the 4th node
# sorted x: 0, 0.5, 0.667, 1 ; y: 0, 100, 100, 50  -> trapz = 0.5*50 + 0.1667*100 + 0.3333*75 = 25 + 16.67 + 25 = 66.67 -> 0.667
check(abs(adp(scores, labels, att) - 2 / 3) < 1e-3, f"ADP worked example = {adp(scores, labels, att):.3f} (expected 0.667)")
# perfect ranking among many benign nodes (as in DARPA: ~10^5-10^6 test nodes): the curve reaches 100 % at precision 1
# and stays there down to precision ~0, so ADP -> 1 (with one benign node it would be 0.667: the curve starts at (0, 0))
n = 10000
sc = np.concatenate([[0.9, 0.8], np.linspace(0.5, 0.0, n)]); lb = np.array([True, True] + [False] * n)
a2 = adp(sc, lb, [{"A"}, {"B"}] + [set()] * n)
check(a2 > 0.999, f"perfect ranking among {n} benign nodes -> ADP {a2:.4f}")
m = metrics(scores > 0.75, labels, att, 2)
check((m["TP"], m["FP"], m["FN"], m["TN"]) == (1, 1, 1, 1) and m["precision"] == 0.5 and m["attacks_detected"] == "1/2", f"metrics at threshold {m}")
check(metrics(np.array([True, False]), np.array([True, False]), [{"A"}, set()], 1)["MCC"] == 1.0, "MCC of a perfect classifier = 1")
from pdp_server.tools.darpa_eval import product_priority
fl = {k: np.array(v) for k, v in {"novelty": [True, False, False], "rules": [False, True, False], "corroborated": [False, False, False],
                                   "learned": [False, False, True]}.items()}
fz = np.array([5.0, 1.0, 9.0])
check(list(np.argsort(-product_priority(fz, fl))) == [0, 1, 2], "0.3 ranking: deterministic alerts first, ties by the learned score")
check(list(np.argsort(-product_priority(fz, fl, np.array([2, 4, 1])))) == [1, 0, 2],
      "0.4 ranking: severity tier first (critical rule above a new program), learned score only breaks ties")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
