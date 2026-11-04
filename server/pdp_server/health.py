"""Agent health as the console and the notifier see it: one list of problems per endpoint, from its heartbeat."""
from __future__ import annotations

import time

BEHIND_S = 45 * 60          # a protected agent whose last scored window ended this long ago is falling behind


def problems(row: dict, target_version: str | None = None) -> list[dict]:
    """[{key, level: warning|error, text}] for an endpoint row (health, phase, kind, current_bundle, agent_version)."""
    h = row.get("health") or {}
    out = []
    if h.get("collector_error"):
        out.append({"key": "collector_error", "level": "error",
                    "text": f"The collector is not running, so nothing is recorded or detected: {str(h['collector_error'])[:300]}"})
    if (h.get("collector_lost") or 0) > 0:
        out.append({"key": "collector_lost", "level": "warning", "text": f"The collector dropped {h['collector_lost']} events since the agent started (ring buffer full)"})
    dropped = int(h.get("spool_dropped_unuploaded") or 0) + int(h.get("spool_dropped_unscored") or 0)
    if dropped:
        out.append({"key": "spool_dropped", "level": "warning", "text": f"The agent's local queue reached its size limit and dropped {dropped} events"})
    pct = h.get("disk_free_pct")
    if pct is not None and pct < 10:
        out.append({"key": "disk", "level": "error" if pct < 3 else "warning",
                    "text": f"Only {pct:.0f}% ({(h.get('disk_free_mb') or 0) / 1024:.1f} GB) free on the disk holding the agent's data"})
    if (h.get("queue_depth") or 0) > 500_000:
        out.append({"key": "queue", "level": "warning", "text": f"{h['queue_depth']} events are waiting to be processed"})
    lw = h.get("last_window_end_ns") or 0
    if row.get("current_bundle") and lw and h.get("at") and time.time() - float(h["at"]) < 300 and time.time() - lw / 1e9 > BEHIND_S:
        out.append({"key": "behind", "level": "warning", "text": f"Detection is {int((time.time() - lw / 1e9) // 60)} minutes behind the endpoint's activity"})
    u = h.get("update") or {}
    for v in u.get("failed") or []:
        if v == target_version:
            out.append({"key": f"update_failed:{v}", "level": "warning", "text": f"Agent {v} did not start on this endpoint and was rolled back; it stays on {row.get('agent_version')}"})
    if target_version and row.get("agent_version") and row.get("agent_version") != target_version and u and not u.get("updater"):
        cfg = row.get("config") or {}
        how = ("apply the cluster's manifest again: Endpoints > Kubernetes clusters > Manifest" if isinstance(cfg, dict) and cfg.get("cluster")
               else "this host's service predates automatic updates (run the installer with --upgrade once)")
        out.append({"key": "no_updater", "level": "warning", "text": f"Agent {target_version} is available; {how}"})
    return out
