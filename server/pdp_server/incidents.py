"""Incidents: alerts grouped into attack stories, with a readable attack graph.

An incident is a run of alerts on one endpoint with no gap longer than GAP_NS between consecutive alert windows.
Its id is the id of its first alert (stable: alerts arrive in time order). Nothing here shows detector scores; the
console explains *what* was detected and *why* (the detection's reason).

The attack graph merges the provenance context the agent stored with each alert, then makes it readable:
  * edges are aggregated per (source, target, operation) with a count and the first time; OPEN is dropped when the
    same pair also has READ/WRITE (it adds nothing); edges are numbered by first time (`order`)
  * library / runtime files a process only reads (shared objects, locale, python stdlib, /proc, /sys, /dev ...) are
    folded into one "system files" node per process - credential stores are never folded
  * beyond MAX_NODES the least relevant context (plain reads, then other context) is folded as well
"""
from __future__ import annotations

import os
import re

from . import db

GAP_NS = 30 * 60 * 1_000_000_000
WINDOW_NS = 15 * 60 * 1_000_000_000      # an alert covers its detection window
MAX_NODES = 150
MAX_STORY = 80

TYPE_RANK = {"rules": 0, "novelty": 1, "corroborated": 2, "evidence": 3, "learned": 4}
RULE_RANK = {"exfiltration": 0, "untrusted_code_network": 1, "untrusted_exec": 2, "novel_executable": 3,
             "tainted_modify": 4, "tainted_spawn": 5}
TACTIC = {"novel_executable": "Execution", "untrusted_exec": "Execution", "tainted_spawn": "Execution",
          "untrusted_code_network": "Command and control", "exfiltration": "Exfiltration",
          "tainted_modify": "Persistence"}
TACTIC_ORDER = ["Execution", "Persistence", "Command and control", "Exfiltration", "Unusual behaviour"]
STATUS_OF_ACTION = {"open": "open", "investigating": "ack", "true_positive": "true_positive",
                    "false_positive": "false_positive", "resolved": "closed"}
OP_LABEL = {"READ": "read", "WRITE": "wrote", "EXECUTE": "executed", "CLONE": "started", "CONNECT": "connected",
            "SENDTO": "sent", "SENDMSG": "sent", "RECVFROM": "received", "RECVMSG": "received", "OPEN": "opened"}
NET_OPS = {"CONNECT", "SENDTO", "SENDMSG", "RECVFROM", "RECVMSG"}

SYSTEM_RE = re.compile(r"^/(usr/)?(lib|lib32|lib64|libx32)/|^/usr/(share|local/lib|libexec)/|^/(proc|sys|dev|run/user)/|"
                       r"^/etc/(ld\.so|locale|nsswitch|host\.conf|gai\.conf|localtime|ssl/|ca-certificates|alternatives/|"
                       r"terminfo|magic|mime\.types|os-release|lsb-release|selinux|python3|bindresvport)|"
                       r"\.(so(\.\d+)*|pyc|py|mo|gz|cache)$|/site-packages/|/dist-packages/|/__pycache__/|^/opt/venv/|"
                       r"^/var/(cache|lib/dpkg|lib/apt)/|^/usr/bin/|^/bin/|^/sbin/|^/usr/sbin/")
SENSITIVE_RE = re.compile(r"/etc/(shadow|gshadow|sudoers)|/\.ssh/|_history$|/\.aws/|/\.gnupg/|/\.kube/|/Login Data|"
                          r"/\.git-credentials|/\.netrc|/\.docker/config\.json|/etc/ssl/private/")


UNKNOWN = (None, "", "None", "null")


# ---------------------------------------------------------------------------------------------- labels
def parse_label(ntype: str, label: str | None, uuid: str, display: dict | None = None) -> dict:
    """-> {type, label, title, details} for display."""
    label = label or uuid
    body = label.split(" ", 1)[1] if " " in label else label
    if ntype == "subject":
        parts = body.split(" ", 1)
        exe = parts[0] if parts and parts[0] not in UNKNOWN else None
        cmd = parts[1] if len(parts) > 1 and parts[1] not in UNKNOWN else ""
        if display:
            exe = display.get("exe_path") if display.get("exe_path") not in UNKNOWN else exe
            cmd = display.get("argv") if display.get("argv") not in UNKNOWN else cmd
        m = re.match(r"^proc:[^:]*:(\d+)", uuid)
        pid = (display or {}).get("pid") or (m.group(1) if m else None)
        name = os.path.basename(exe) if exe else (os.path.basename(cmd.split(" ", 1)[0]) if cmd else (f"process {pid}" if pid else "process"))
        det = {"Program": exe or "(not recorded by the collector)", "Command line": cmd or "(not recorded)"}
        if pid:
            det["PID"] = str(pid)
        return {"type": "process", "label": name, "title": cmd or exe or name, "details": det}
    if ntype == "netflow":
        p = body.split()
        addr, port = (p[0], p[1]) if len(p) >= 2 else (body, "")
        local = addr.startswith(("127.", "10.", "192.168.", "::1", "fe80", "0.0.0.0")) or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", addr)
        return {"type": "network", "label": f"{addr}:{port}" if port else addr, "title": f"{addr} port {port}" if port else addr,
                "details": {"Address": addr, "Port": port or "-", "Scope": "local network" if local else "external"}}
    path = body
    return {"type": "file", "label": os.path.basename(path.rstrip("/")) or path, "title": path, "details": {"Path": path}}


def _det_key(a: dict) -> tuple:
    return (TYPE_RANK.get(a["layer"], 9), RULE_RANK.get(a["rule"] or "", 9), a["window_start_ns"])


# ---------------------------------------------------------------------------------------------- grouping
def load_alerts(c, scope: list[str] | None, endpoint_id: str | None = None, with_context: bool = False) -> list[dict]:
    cols = ("a.id, a.endpoint_id, e.name AS endpoint_name, a.window_start_ns, a.node_uuid, a.ntype, a.label, a.display, "
            "coalesce(a.layer, 'learned') AS layer, a.rule, a.reason, a.status" + (", a.context" if with_context else ""))
    where, params = ["TRUE"], []
    if scope is not None:
        where.append("a.endpoint_id = ANY(%s::uuid[])"); params.append(scope)
    if endpoint_id:
        where.append("a.endpoint_id = %s"); params.append(endpoint_id)
    return db.q(c, f"SELECT {cols} FROM alerts a JOIN endpoints e ON e.id=a.endpoint_id WHERE {' AND '.join(where)} "
                   "ORDER BY a.endpoint_id, a.window_start_ns, a.id LIMIT 200000", tuple(params))


def group(rows: list[dict]) -> list[list[dict]]:
    out, cur = [], []
    for r in rows:
        if cur and (r["endpoint_id"] != cur[-1]["endpoint_id"] or r["window_start_ns"] - cur[-1]["window_start_ns"] > GAP_NS):
            out.append(cur); cur = []
        cur.append(r)
    if cur:
        out.append(cur)
    return out


def incident_status(alerts: list[dict]) -> str:
    st = {a["status"] for a in alerts}
    if st == {"false_positive"}:
        return "false_positive"
    if st == {"true_positive"}:
        return "true_positive"
    if st <= {"closed", "true_positive", "false_positive"}:
        return "resolved"
    if "ack" in st or "true_positive" in st:
        return "investigating"
    return "open"


def _actor_in(reason: str | None) -> str | None:
    """Rule reasons start with the acting program: "/opt/venv/bin/python, which read sensitive data, ..." """
    m = re.match(r"^\s*([^,]+?), which", reason or "")
    return os.path.basename(m.group(1)) if m and m.group(1) not in UNKNOWN else None


def _ip_in(reason: str | None) -> str | None:
    m = re.search(r"untrusted ([0-9a-fA-F.:]+)", reason or "")
    return m.group(1) if m else None


def summarise(alerts: list[dict]) -> dict:
    top = min(alerts, key=_det_key)
    rules = {a["rule"] for a in alerts if a["layer"] == "rules"}
    layers = {a["layer"] for a in alerts}
    if rules & {"exfiltration", "untrusted_code_network"}:
        severity = "critical"
    elif "untrusted_exec" in rules or ("novelty" in layers and rules):
        severity = "high"
    elif layers & {"novelty", "rules", "corroborated"}:
        severity = "medium"
    else:
        severity = "low"
    who = parse_label(top["ntype"], top["label"], top["node_uuid"], top.get("display"))
    name = _actor_in(top["reason"]) or who["label"]
    if top["layer"] == "rules" and top["rule"] == "exfiltration":
        title = f"Sensitive data sent to untrusted {_ip_in(top['reason']) or 'address'} by {name}"
    elif top["layer"] == "rules" and top["rule"] == "untrusted_code_network":
        title = f"Downloaded program {name} contacted {_ip_in(top['reason']) or 'an untrusted address'}"
    elif top["layer"] == "rules" and top["rule"] == "untrusted_exec":
        title = f"A dropped file was executed ({name})"
    elif top["layer"] == "rules":
        title = f"Suspicious data flow involving {name}"
    elif top["layer"] == "novelty":
        progs = sorted({parse_label(a["ntype"], a["label"], a["node_uuid"], a.get("display"))["label"] for a in alerts if a["layer"] == "novelty"})
        title = f"New program {progs[0]} ran" + (f" (and {len(progs) - 1} more)" if len(progs) > 1 else "")
    else:
        title = f"Unusual activity of {name}"
    tactics = {TACTIC.get(a["rule"] or "", "Unusual behaviour" if a["layer"] == "learned" else None) for a in alerts}
    tactics.discard(None)
    procs = {a["node_uuid"] for a in alerts if a["ntype"] == "subject"}
    return {"id": alerts[0]["id"], "endpoint_id": str(alerts[0]["endpoint_id"]), "endpoint_name": alerts[0]["endpoint_name"],
            "first_ns": int(alerts[0]["window_start_ns"]), "last_ns": int(alerts[-1]["window_start_ns"]) + WINDOW_NS,
            "severity": severity, "title": title, "tactics": [t for t in TACTIC_ORDER if t in tactics],
            "alerts": len(alerts), "processes": len(procs), "status": incident_status(alerts)}


def list_incidents(c, scope, endpoint_id=None) -> list[dict]:
    return [summarise(g) for g in group(load_alerts(c, scope, endpoint_id))]


def find(c, scope, incident_id: int, with_context: bool = False) -> list[dict] | None:
    a = db.q(c, "SELECT endpoint_id FROM alerts WHERE id=%s", (incident_id,), one=True)
    if not a or (scope is not None and str(a["endpoint_id"]) not in scope):
        return None
    for g in group(load_alerts(c, None, str(a["endpoint_id"]), with_context=with_context)):
        if g[0]["id"] == incident_id:
            return g
    return None


# ---------------------------------------------------------------------------------------------- attack graph
def build_graph(alerts: list[dict]) -> tuple[dict, list[dict]]:
    raw_nodes: dict[str, dict] = {}
    raw_edges: dict[tuple, dict] = {}
    for a in alerts:
        ctx = a.get("context") or {}
        for n in ctx.get("nodes", []):
            raw_nodes.setdefault(n["uuid"], n)
        for e in ctx.get("edges", []):
            k = (e["src"], e["dst"], e["op"])
            t = int(e.get("ts_ns") or 0)
            cur = raw_edges.get(k)
            if cur is None:
                raw_edges[k] = {"src": e["src"], "dst": e["dst"], "op": e["op"], "first_ns": t, "count": 1}
            else:
                cur["count"] += 1
                cur["first_ns"] = min(cur["first_ns"], t) if cur["first_ns"] else t
        raw_nodes.setdefault(a["node_uuid"], {"uuid": a["node_uuid"], "ntype": a["ntype"], "label": a["label"]})
    # the strongest detection per node
    flagged: dict[str, dict] = {}
    display: dict[str, dict] = {}
    for a in sorted(alerts, key=_det_key):
        flagged.setdefault(a["node_uuid"], a)
        if a.get("display"):
            display.setdefault(a["node_uuid"], a["display"])
    # OPEN adds nothing next to READ/WRITE of the same pair
    pairs = {(k[0], k[1]) for k in raw_edges if k[2] in ("READ", "WRITE")} | {(k[1], k[0]) for k in raw_edges if k[2] in ("READ", "WRITE")}
    edges = [e for k, e in raw_edges.items() if not (k[2] == "OPEN" and ((k[0], k[1]) in pairs))]
    for e in edges:
        for u in (e["src"], e["dst"]):
            raw_nodes.setdefault(u, {"uuid": u, "ntype": "file" if u.startswith("file:") else "subject" if u.startswith("proc:") else "netflow", "label": u})

    def ntype(u):
        return raw_nodes[u].get("ntype")

    def path_of(u):
        lab = raw_nodes[u].get("label") or ""
        return lab.split(" ", 1)[1] if " " in lab else lab

    # ---- fold system files a process only reads
    touch: dict[str, set] = {}
    for e in edges:
        touch.setdefault(e["src"], set()).add(e["op"]); touch.setdefault(e["dst"], set()).add(e["op"])

    def foldable(u, aggressive=False):
        if u in flagged or ntype(u) != "file":
            return False
        if touch.get(u, set()) - {"READ", "OPEN"}:
            return False
        p = path_of(u)
        if SENSITIVE_RE.search(p):
            return False
        return aggressive or bool(SYSTEM_RE.search(p))

    def fold(pred, label_fmt):
        nonlocal edges
        groups: dict[str, dict] = {}
        keep = []
        for e in edges:
            f = e["src"] if pred(e["src"]) and ntype(e["dst"]) == "subject" else None
            if f is None:
                keep.append(e); continue
            g = groups.setdefault(e["dst"], {"files": {}, "first_ns": e["first_ns"]})
            g["files"][f] = path_of(f)
            g["first_ns"] = min(g["first_ns"], e["first_ns"]) if g["first_ns"] else e["first_ns"]
        for proc, g in groups.items():
            gid = f"group:{label_fmt[0]}:{proc}"
            sample = sorted(g["files"].values())
            raw_nodes[gid] = {"uuid": gid, "ntype": "group", "label": label_fmt[1].format(n=len(sample)),
                              "sample": sample[:25], "count": len(sample)}
            keep.append({"src": gid, "dst": proc, "op": "READ", "first_ns": g["first_ns"], "count": len(sample)})
        edges = keep

    fold(lambda u: foldable(u), ("sys", "{n} system files"))
    live = {e["src"] for e in edges} | {e["dst"] for e in edges} | set(flagged)
    if len(live) > MAX_NODES:
        fold(lambda u: foldable(u, aggressive=True), ("read", "{n} other files read"))
    live = {e["src"] for e in edges} | {e["dst"] for e in edges} | set(flagged)
    truncated = False
    if len(live) > MAX_NODES:
        # keep alerted nodes and their direct neighbours that matter most (network, executed/written files, processes)
        prio = {}
        for e in edges:
            for u, v in ((e["src"], e["dst"]), (e["dst"], e["src"])):
                if u in flagged:
                    score = 0 if ntype(v) == "netflow" else 1 if e["op"] in ("EXECUTE", "WRITE", "CLONE") else 2
                    prio[v] = min(prio.get(v, 9), score)
        ranked = list(flagged) + sorted((u for u in prio if u not in flagged), key=lambda u: prio[u])
        keepn = set(ranked[:MAX_NODES])
        edges = [e for e in edges if e["src"] in keepn and e["dst"] in keepn]
        live = keepn
        truncated = True
    # ---- output
    order = sorted(range(len(edges)), key=lambda i: (edges[i]["first_ns"] or 0, i))
    rank = {i: r + 1 for r, i in enumerate(order)}
    first_seen: dict[str, int] = {}
    for e in edges:
        for u in (e["src"], e["dst"]):
            if e["first_ns"]:
                first_seen[u] = min(first_seen.get(u, e["first_ns"]), e["first_ns"])
    nodes_out = []
    for u in live:
        n = raw_nodes.get(u) or {"uuid": u, "ntype": "file", "label": u}
        if n.get("ntype") == "group":
            nodes_out.append({"id": u, "type": "group", "label": n["label"], "title": n["label"],
                              "details": {"Files": n["count"], "Examples": ", ".join(n["sample"][:8])}, "sample": n["sample"],
                              "alerted": False, "detection": None, "first_ns": first_seen.get(u), "count": n["count"]})
            continue
        d = parse_label(n.get("ntype") or "file", n.get("label"), u, display.get(u))
        f = flagged.get(u)
        nodes_out.append({"id": u, **d, "alerted": f is not None,
                          "detection": {"type": f["layer"], "rule": f["rule"], "reason": _reason(f),
                                        "alert_id": f["id"]} if f else None,
                          "first_ns": first_seen.get(u), "count": 1})
    edges_out = [{"id": f"e{i}", "source": e["src"], "target": e["dst"], "op": e["op"], "label": OP_LABEL.get(e["op"], e["op"].lower()),
                  "first_ns": e["first_ns"], "count": e["count"], "order": rank[i]} for i, e in enumerate(edges)]
    return {"nodes": nodes_out, "edges": edges_out, "truncated": truncated}, edges


def clean_reason(layer: str | None, reason: str | None) -> str:
    """The analyst-facing reason: no detector scores, no internal layer names."""
    layer = layer or "learned"
    if not reason or layer in ("corroborated", "learned") or "score" in reason or "percentile" in reason:
        return _default_reason({"layer": layer})
    return reason.replace("runs None,", "runs a program the collector could not name,").replace("runs null,", "runs a program the collector could not name,")


def _reason(a: dict) -> str:
    return clean_reason(a.get("layer"), a.get("reason"))


def _default_reason(a: dict) -> str:
    return {"learned": "Behaviour unlike anything this endpoint did while its baseline was recorded",
            "corroborated": "Closely connected to another detection and unusual for this endpoint",
            "evidence": "received untrusted data and acted on it"}.get(a["layer"], a["layer"])


def story(graph: dict, alerts: list[dict]) -> list[dict]:
    """Time-ordered plain-language steps around the alerted nodes."""
    nodes = {n["id"]: n for n in graph["nodes"]}
    alerted = {n["id"] for n in graph["nodes"] if n["alerted"]}
    steps, seen = [], set()
    for e in sorted(graph["edges"], key=lambda e: e["order"]):
        s, d, op = e["source"], e["target"], e["op"]
        if not (s in alerted or d in alerted):
            continue
        sn, dn = nodes.get(s), nodes.get(d)
        if not sn or not dn:
            continue
        if op == "CLONE":
            kind, actor, verb, obj, node = "process", sn["label"], "started", dn["title"], d
        elif op == "EXECUTE":
            kind, actor, verb, obj, node = "exec", dn["label"], "executed", sn["title"], d
        elif op == "WRITE":
            kind, actor, verb, obj, node = "write", sn["label"], "wrote", dn["title"], s
        elif op in NET_OPS:
            proc, net = (s, d) if nodes[s]["type"] == "process" else (d, s)
            verb = {"CONNECT": "connected to", "SENDTO": "sent data to", "SENDMSG": "sent data to"}.get(op, "received data from")
            kind, actor, obj, node = "network", nodes[proc]["label"], nodes[net]["label"], proc
        elif op in ("READ", "OPEN"):
            if sn["type"] == "group" or not (s in alerted or SENSITIVE_RE.search(sn.get("title") or "")):
                continue
            kind, actor, verb, obj, node = "read", dn["label"], "read", sn["title"], d
        else:
            continue
        text = f"{actor} {verb} {obj}"
        if (kind, text) in seen:
            continue
        seen.add((kind, text))
        steps.append({"ts_ns": e["first_ns"], "kind": kind, "text": text, "node": node, "detection": None,
                      "_actor": actor, "_verb": verb, "_obj": obj})
    # detections, placed at the node's first activity
    first = {}
    for st in steps:
        first.setdefault(st["node"], st["ts_ns"])
    for n in graph["nodes"]:
        if n["alerted"]:
            steps.append({"ts_ns": first.get(n["id"]) or n.get("first_ns") or 0, "kind": "detection",
                          "text": n["detection"]["reason"], "node": n["id"],
                          "detection": {"type": n["detection"]["type"], "rule": n["detection"]["rule"], "reason": n["detection"]["reason"]}})
    steps.sort(key=lambda x: (x["ts_ns"] or 0, x["kind"] == "detection"))
    steps = _collapse(steps)
    if len(steps) > MAX_STORY:   # keep every detection, then the earliest other steps
        det = [x for x in steps if x["kind"] == "detection"]
        rest = [x for x in steps if x["kind"] != "detection"][: max(0, MAX_STORY - len(det))]
        steps = sorted(det + rest, key=lambda x: (x["ts_ns"] or 0, x["kind"] == "detection"))
    return steps


def _collapse(steps: list[dict]) -> list[dict]:
    """Runs of the same actor doing the same thing ("cp wrote a.c", "cp wrote b.c", ...) become one step; repeated
    detection reasons likewise."""
    out: list[dict] = []
    for st in steps:
        prev = out[-1] if out else None
        same = prev is not None and prev["kind"] == st["kind"] and (
            (st["kind"] == "detection" and prev["text"] == st["text"]) or
            (st["kind"] != "detection" and prev.get("_actor") == st.get("_actor") and prev.get("_verb") == st.get("_verb")))
        if same:
            prev.setdefault("_objs", [prev.get("_obj")]).append(st.get("_obj"))
            prev.setdefault("_n", 1)
            prev["_n"] += 1
            continue
        out.append(dict(st))
    for st in out:
        n = st.pop("_n", 1)
        objs = st.pop("_objs", None)
        actor, verb = st.pop("_actor", None), st.pop("_verb", None)
        st.pop("_obj", None)
        if n > 1:
            if st["kind"] == "detection":
                st["text"] = f"{st['text']} ({n} processes)"
            else:
                noun = {"write": "files", "read": "files", "exec": "files", "process": "processes", "network": "addresses"}[st["kind"]]
                ex = ", ".join(os.path.basename(o.rstrip("/")) if st["kind"] in ("write", "read", "exec") else o.split(" ", 1)[0] for o in objs[:3] if o)
                st["text"] = f"{actor} {verb} {n} {noun} ({ex}{', ...' if n > 3 else ''})"
            st["count"] = n
    return out


def detail(alerts: list[dict]) -> dict:
    graph, _ = build_graph(alerts)
    nodes = {n["id"]: n for n in graph["nodes"]}
    alist = []
    for a in alerts:
        d = nodes.get(a["node_uuid"]) or {**parse_label(a["ntype"], a["label"], a["node_uuid"], a.get("display"))}
        alist.append({"id": a["id"], "ts_ns": int(a["window_start_ns"]), "node": a["node_uuid"], "label": d["label"], "title": d["title"],
                      "type": a["layer"], "rule": a["rule"], "reason": _reason(a), "status": a["status"]})
    inc = summarise(alerts)
    ts = [e["first_ns"] for e in graph["edges"] if e.get("first_ns")]
    if ts:
        inc["first_ns"], inc["last_ns"] = min(ts), max(ts)
    return {"incident": inc, "story": story(graph, alerts), "graph": graph, "alerts": alist}
