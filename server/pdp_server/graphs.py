"""Graph and timeline queries for the console (built from alert context and per-window summaries)."""
from __future__ import annotations

from . import db

WINDOW_NS = 15 * 60 * 1_000_000_000


def _short(label: str) -> str:
    return label.split(" ", 1)[1] if " " in label else label


def incident_graph(endpoint_id: str, focus_ns: int | None = None, span_windows: int = 3) -> dict:
    """Stitch the alerts around a focus window into one attack graph with an analyst summary.

    An 'incident' is the alerts within +/- span_windows of a focus window (default: the window with the highest
    fused score on the endpoint, i.e. the strongest detection). The per-alert context subgraphs are merged into one
    provenance graph; the summary pulls out the kill-chain pieces: flagged processes, executed/written files and the
    external endpoints the flagged processes talked to, ordered in time."""
    with db.conn() as c:
        if focus_ns is None:
            # strongest detection: deterministic layers (rules, novelty) before learned scores
            top = db.q(c, "SELECT window_start_ns FROM alerts WHERE endpoint_id=%s ORDER BY (layer = 'rules') DESC NULLS LAST, "
                          "(layer = 'novelty') DESC NULLS LAST, fused DESC LIMIT 1", (endpoint_id,), one=True)
            if not top:
                return {"nodes": [], "edges": [], "summary": None, "focus_ns": None, "windows": []}
            focus_ns = int(top["window_start_ns"])
        lo, hi = focus_ns - span_windows * WINDOW_NS, focus_ns + (span_windows + 1) * WINDOW_NS
        alerts = db.q(c, "SELECT node_uuid, label, ntype, fused, r1, r2, window_start_ns, context, coalesce(layer, 'learned') AS layer, rule, reason FROM alerts "
                        "WHERE endpoint_id=%s AND window_start_ns >= %s AND window_start_ns < %s ORDER BY fused DESC", (endpoint_id, lo, hi))
        wins = db.q(c, "SELECT DISTINCT window_start_ns FROM alerts WHERE endpoint_id=%s AND window_start_ns >= %s AND window_start_ns < %s ORDER BY window_start_ns", (endpoint_id, lo, hi))
    flagged = {}
    for a in alerts:
        f = flagged.get(a["node_uuid"])
        if not f or a["fused"] > f["fused"]:
            flagged[a["node_uuid"]] = {"fused": a["fused"], "r1": a["r1"], "r2": a["r2"], "ts": int(a["window_start_ns"]),
                                       "layer": a["layer"], "rule": a["rule"], "reason": a["reason"]}
    nodes, edges = {}, {}
    for a in alerts:
        ctx = a["context"] or {}
        for n in ctx.get("nodes", []):
            nodes.setdefault(n["uuid"], n)
        for e in ctx.get("edges", []):
            edges.setdefault((e["src"], e["dst"], e["op"], e["ts_ns"]), e)
    for u, n in nodes.items():
        n["flagged"] = flagged.get(u)
    edge_list = list(edges.values())
    # ---- analyst summary (kill-chain pieces touched by flagged nodes) ----
    nmap = nodes
    def nt(u):
        return nmap.get(u, {}).get("ntype")
    def lbl(u):
        return _short(nmap.get(u, {}).get("label", u))
    procs = sorted(({"uuid": u, "label": lbl(u), **flagged[u]} for u in flagged if nt(u) == "subject"), key=lambda x: (x["ts"], -x["fused"]))
    externals, executed, written = {}, {}, {}
    for e in edge_list:
        s, d, op = e["src"], e["dst"], e["op"]
        fs, fd = s in flagged, d in flagged
        if op in ("CONNECT", "SENDTO", "SENDMSG", "RECVFROM", "RECVMSG") and (nt(d) == "netflow" or nt(s) == "netflow"):
            nf = d if nt(d) == "netflow" else s
            if fs or fd or nf in flagged:
                externals[nf] = {"uuid": nf, "label": lbl(nf), "op": op, "ts": e["ts_ns"], "flagged": nf in flagged}
        if op == "EXECUTE" and nt(s) == "file" and (fd or s in flagged):
            executed[s] = {"uuid": s, "label": lbl(s), "ts": e["ts_ns"], "flagged": s in flagged}
        if op == "WRITE" and nt(d) == "file" and (fs or d in flagged):
            written[d] = {"uuid": d, "label": lbl(d), "ts": e["ts_ns"], "flagged": d in flagged}
    ts_all = [f["ts"] for f in flagged.values()]
    summary = {
        "flagged_nodes": len(flagged),
        "flagged_processes": procs[:50],
        "executed_files": sorted(executed.values(), key=lambda x: x["ts"])[:50],
        "written_files": sorted(written.values(), key=lambda x: x["ts"])[:50],
        "external_connections": sorted(externals.values(), key=lambda x: x["ts"])[:50],
        "first_ns": min(ts_all) if ts_all else None,
        "last_ns": max(ts_all) if ts_all else None,
        "max_fused": max((f["fused"] for f in flagged.values()), default=0.0),
        "by_layer": {k: sum(1 for f in flagged.values() if f["layer"] == k) for k in ("novelty", "rules", "corroborated", "learned")},
        "detections": sorted(({"uuid": u, "label": lbl(u), "layer": f["layer"], "rule": f["rule"], "reason": f["reason"], "ts": f["ts"]}
                              for u, f in flagged.items() if f["layer"] in ("novelty", "rules")), key=lambda x: x["ts"])[:50],
        "windows": len(wins),
    }
    return {"nodes": list(nodes.values()), "edges": edge_list, "summary": summary, "focus_ns": focus_ns,
            "windows": [int(w["window_start_ns"]) for w in wins]}


def endpoint_timeline(endpoint_id: str, limit: int = 2000) -> list[dict]:
    with db.conn() as c:
        rows = db.q(c, "SELECT start_ns, end_ns, edges, nodes, alerts, max_fused, max_r1, max_r2 FROM windows WHERE endpoint_id=%s ORDER BY start_ns DESC LIMIT %s", (endpoint_id, limit))
    return [dict(r) for r in reversed(rows)]


def alert_graph(alert_id: int, expand: str | None = None, hops: int = 1) -> dict:
    """The alert's stored context subgraph (window-local k-hop neighbourhood) plus, when `expand` names a node,
    the neighbourhood of that node taken from other alerts of the same endpoint and window."""
    with db.conn() as c:
        a = db.q(c, "SELECT * FROM alerts WHERE id=%s", (alert_id,), one=True)
        if not a:
            return {"nodes": [], "edges": [], "alert": None}
        ctx = a["context"] or {"nodes": [], "edges": []}
        nodes = {n["uuid"]: n for n in ctx.get("nodes", [])}
        edges = {(e["src"], e["dst"], e["op"], e["ts_ns"]): e for e in ctx.get("edges", [])}
        if expand:
            others = db.q(c, "SELECT context FROM alerts WHERE endpoint_id=%s AND window_start_ns=%s AND id<>%s", (a["endpoint_id"], a["window_start_ns"], alert_id))
            for o in others:
                oc = o["context"] or {}
                touch = {e["src"] for e in oc.get("edges", []) if e["dst"] == expand} | {e["dst"] for e in oc.get("edges", []) if e["src"] == expand}
                if not touch:
                    continue
                for n in oc.get("nodes", []):
                    if n["uuid"] in touch or n["uuid"] == expand:
                        nodes.setdefault(n["uuid"], n)
                for e in oc.get("edges", []):
                    if expand in (e["src"], e["dst"]):
                        edges.setdefault((e["src"], e["dst"], e["op"], e["ts_ns"]), e)
        flagged = {r["node_uuid"]: {"fused": r["fused"], "r1": r["r1"], "r2": r["r2"], "layer": r["layer"], "reason": r["reason"]} for r in
                   db.q(c, "SELECT node_uuid, fused, r1, r2, coalesce(layer, 'learned') AS layer, reason FROM alerts WHERE endpoint_id=%s AND window_start_ns=%s",
                        (a["endpoint_id"], a["window_start_ns"]))}
    for u, n in nodes.items():
        n["flagged"] = flagged.get(u)
    return {"alert": dict(a, id=a["id"], endpoint_id=str(a["endpoint_id"])), "nodes": list(nodes.values()), "edges": list(edges.values())}
