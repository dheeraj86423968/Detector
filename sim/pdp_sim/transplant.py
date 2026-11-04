"""Transplants of real DARPA attack subgraphs.

extract(): read one attack from a research database (PIDSMaker Postgres layout) using the ORTHRUS ground-truth
node list and the attack time window, keeping every event in the window that touches a ground-truth node.
Ground-truth nodes become malicious new entities; the other endpoints of those events are context entities that
the injector binds to existing nodes of the target endpoint with the same label (or creates when absent).
The result is a portable JSON file; load() turns it into an AttackGraph.
"""
from __future__ import annotations

import csv
import json
import os
import random

from pdp_engine.schema import REVERSED, Entity, normalise_op

from .attacks import AttackGraph

ROOT_PATTERNS = {"web": r"nginx|httpd|apache|lighttpd|sshd|smtpd|imapd", "browser": r"firefox|chrome|chromium|thunderbird"}


def extract(database: str, gt_csv: str, start_ns: int, end_ns: int, out_path: str, name: str, host: str = "postgres", cap: int = 20000) -> dict:
    import psycopg2
    con = psycopg2.connect(dbname=database, host=host, user="postgres", password="postgres")
    cur = con.cursor()
    gt_ids = {row[2] for row in csv.reader(open(gt_csv)) if row}
    ents: dict[str, dict] = {}
    for sql, kind in (("SELECT index_id, path, cmd FROM subject_node_table", "subject"), ("SELECT index_id, path, NULL FROM file_node_table", "file"),
                      ("SELECT index_id, dst_addr, dst_port FROM netflow_node_table", "netflow")):
        cur.execute(sql)
        for idx, a, b in cur:
            u = str(idx)
            if kind == "subject":
                e = Entity.process(u, str(a), str(b))
            elif kind == "file":
                e = Entity.file(u, str(a))
            else:
                e = Entity.socket(u, str(a), str(b))
            ents[u] = {"ntype": e.ntype, "label": e.label}
    cur.execute("SELECT src_index_id, operation, dst_index_id, event_uuid, timestamp_rec FROM event_table WHERE timestamp_rec >= %s AND timestamp_rec <= %s "
                "ORDER BY timestamp_rec, event_uuid", (start_ns, end_ns))
    events = []
    for s, op, d, eu, t in cur:
        s, d = str(s), str(d)
        if s not in gt_ids and d not in gt_ids:
            continue
        e = normalise_op(op, strict=True)
        if e is None or s not in ents or d not in ents:
            continue
        events.append((int(t), s, e, d))
    con.close()
    if len(events) > cap:   # keep order, sample uniformly
        rng = random.Random(0)
        keep = sorted(rng.sample(range(len(events)), cap))
        events = [events[i] for i in keep]
    t0 = events[0][0] if events else start_ns
    used = {u for e in events for u in (e[1], e[3])}
    out = {"name": name, "dataset": database, "source_window": [start_ns, end_ns], "n_gt": len(gt_ids & used),
           "entities": {u: dict(ents[u], gt=(u in gt_ids)) for u in used},
           "events": [[t - t0, s, op, d] for t, s, op, d in events]}
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    json.dump(out, open(out_path, "w"))
    return {"name": name, "entities": len(used), "gt": out["n_gt"], "events": len(events), "duration_s": (events[-1][0] - t0) / 1e9 if events else 0}


def load(path: str) -> AttackGraph:
    d = json.load(open(path))
    g = AttackGraph(f"transplant:{d['name']}")
    g.params["source"] = {"dataset": d["dataset"], "window": d["source_window"]}
    # the earliest ground-truth process is the root and is bound to a real host process of the target endpoint
    procs = [u for u, e in d["entities"].items() if e["gt"] and e["ntype"] == "subject"]
    first = {}
    for t, s, op, dd in d["events"]:
        for u in (s, dd):
            first.setdefault(u, t)
    root = min(procs, key=lambda u: first.get(u, 1 << 62)) if procs else None
    role = "any"
    if root:
        import re
        lab = d["entities"][root]["label"]
        for r, pat in ROOT_PATTERNS.items():
            if re.search(pat, lab):
                role = r
    for u, e in d["entities"].items():
        if u == root:
            continue
        key = f"$ctx:{u}" if not e["gt"] else f"$gt:{u}"
        g.entities[key] = Entity(key, e["ntype"], e["label"], {"transplant": True, "gt": e["gt"]})
        if e["gt"]:
            g.malicious.add(key)
    if root:
        host = g.placeholder("host", role)
        g.params["root_label"] = d["entities"][root]["label"]
    def key(u):
        if u == root:
            return host
        return f"$gt:{u}" if d["entities"][u]["gt"] else f"$ctx:{u}"
    g.events = [(int(t), key(s), op, key(dd)) for t, s, op, dd in d["events"]]
    return g
