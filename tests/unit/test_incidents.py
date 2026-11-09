"""Incident grouping (pdp_server.incidents): time grouping, split by provenance connectivity, same-program merge.
Run: PYTHONPATH=server:engine python tests/unit/test_incidents.py"""
import sys

from pdp_server import incidents as I

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


M = 60 * 10**9


def alert(i, node, t, layer="novelty", rule="novel_executable", reason=None, edges=(), label=None):
    ctx = {"nodes": [{"uuid": u, "label": l} for u, l in {**{node: label or f"subject /bin/{node} {node}"}, **{e[1]: e[2] for e in edges}}.items()],
           "edges": [{"src": node, "dst": e[1], "op": e[0], "ts_ns": t} for e in edges]}
    return {"id": i, "endpoint_id": "ep", "endpoint_name": "ep", "window_start_ns": t, "node_uuid": node, "ntype": "subject",
            "label": label or f"subject /bin/{node} {node}", "display": None, "layer": layer, "rule": rule,
            "reason": reason or f"runs /bin/{node}, which never ran during the baseline", "status": "open", "context": ctx}


# an attack chain (rules hit) and unrelated browsing at the same time, plus a later unrelated alert
rows = [
    alert(1, "nginx", 0, layer="rules", rule="untrusted_code_network", reason="XIM (loaded from untrusted netflow 1.2.3.4) sends to untrusted 5.6.7.8",
          edges=[("WRITE", "f:/tmp/XIM", "file /tmp/XIM")]),
    alert(2, "XIM", 1 * M, edges=[("CONNECT", "n:5.6.7.8", "netflow 5.6.7.8 80")]),
    alert(3, "links", 2 * M, label="subject /usr/local/bin/links links", reason="runs /usr/local/bin/links, which never ran during the baseline",
          edges=[("CONNECT", "n:dns", "netflow 10.0.0.1 53")]),
    alert(4, "links2", 3 * M, label="subject /usr/local/bin/links links", reason="runs /usr/local/bin/links, which never ran during the baseline",
          edges=[("CONNECT", "n:dns", "netflow 10.0.0.1 53")]),
    alert(5, "late", 120 * M),
]
rows[1]["context"]["edges"].append({"src": "f:/tmp/XIM", "dst": "XIM", "op": "EXECUTE", "ts_ns": M})
rows[1]["context"]["nodes"].append({"uuid": "f:/tmp/XIM", "label": "file /tmp/XIM"})
groups = I.group(rows)
by = {tuple(sorted(a["id"] for a in g)) for g in groups}
check((1, 2) in by, "the attack chain (connected through /tmp/XIM) is one incident")
check((3, 4) in by, "unconnected processes of the same program (via a DNS hub only) are one incident")
check((5,) in by, "alerts more than 30 min apart are separate incidents")
check(len(groups) == 3, f"3 incidents ({sorted(by)})")
inc = I.summarise(next(g for g in groups if g[0]["id"] == 1))
check(inc["severity"] == "critical" and inc["title"] == "Downloaded program XIM contacted 5.6.7.8", f"chain title names the program: {inc['title']}")
check(I.clean_reason("corroborated", "learned score 1.80 (above the validation 99.9th percentile)") .startswith("Closely connected"), "scores never reach the analyst")
# 0.10: the same finding coming back within the recurrence horizon joins its incident (ids stay those of the first)
H = 60 * M
rec = [alert(10, "zoom", 0), alert(11, "zoom", 5 * H), alert(12, "other", 6 * H), alert(13, "zoom", 40 * H)]
_r, I.RECUR_NS = I.RECUR_NS, 0
base = I.group(rec)
I.RECUR_NS = _r
mr = {tuple(a["id"] for a in g) for g in I.merge_recurring(base, 24 * H)}
check(mr == {(10, 11), (12,), (13,)}, f"merge_recurring: same subject within 24 h joins, a different subject or a later return does not ({sorted(mr)})")
check({tuple(a["id"] for a in g) for g in I.group(rec)} == {(10, 11, 13), (12,)}, "default (7 days): a finding that keeps coming back stays one incident")
unnamed = [alert(20, "u1", 0, label="subject None None", reason="runs None, which never ran during the baseline"),
           alert(21, "u2", 5 * H, label="subject None None", reason="runs None, which never ran during the baseline")]
check(len(I.group(unnamed)) == 2, "findings whose program was not recorded are not merged as the same finding")
_r, I.RECUR_NS = I.RECUR_NS, 0
check({tuple(a["id"] for a in g) for g in I.group(rec)} == {(10,), (11,), (12,), (13,)}, "RECUR_NS 0 keeps the 0.9 grouping")
I.RECUR_NS = _r
cr = I.clean_reason("corroborated", "runs C:/x/tool.exe, new on this endpoint but run during the baseline of 3 other endpoint(s); learned score 2.10 corroborates")
check(cr == "runs C:/x/tool.exe, new on this endpoint but run during the baseline of 3 other endpoint(s), and it behaves unusually for this endpoint"
      and "score" not in cr, f"corroborated evidence keeps its reason without the score ({cr})")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
