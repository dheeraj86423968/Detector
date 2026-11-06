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
    # agents >= 0.3.19 report the last hour and the agent-fell-behind drops separately; older ones only a running total
    lost = h.get("collector_lost_1h", h.get("collector_lost")) or 0
    behind = h.get("collector_behind_1h") or 0
    if lost > 0:
        out.append({"key": "collector_lost", "level": "warning",
                    "text": f"The collector missed {lost:,} events{' in the last hour' if 'collector_lost_1h' in h else ' since the agent started'}: "
                            "the host was too busy for it to keep up with a burst of activity (the kernel's event buffer filled up)"
                            + ("" if "collector_behind" in h else ". Agent 0.3.19 makes this much rarer")})
    if behind > 0:
        out.append({"key": "collector_behind", "level": "warning",
                    "text": f"The agent fell behind reading events and dropped {behind:,} in the last hour (sustained heavy activity)"})
    if "spool_dropped_unuploaded_1h" in h:          # agents >= 0.3.22: the last hour; older ones only running totals
        dropped = int(h.get("spool_dropped_unuploaded_1h") or 0) + int(h.get("spool_dropped_unscored_1h") or 0)
        when = " in the last hour"
    else:
        dropped = int(h.get("spool_dropped_unuploaded") or 0) + int(h.get("spool_dropped_unscored") or 0)
        when = " since it was installed"
    if dropped:
        out.append({"key": "spool_dropped", "level": "warning",
                    "text": f"The agent's local queue reached its size limit and dropped {dropped:,} events{when}"})
    if h.get("disk_full") or h.get("disk_full_dropped"):
        out.append({"key": "disk_full", "level": "error" if h.get("disk_full") else "warning",
                    "text": (f"The disk holding the agent's data is full: activity cannot be stored "
                             f"({int(h.get('disk_full_dropped') or 0):,} events dropped since the agent started). Free space on it; the agent continues by itself"
                             if h.get("disk_full") else f"The disk was full for a while: {int(h['disk_full_dropped']):,} events could not be stored")})
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
    # detection posture (pdp_server.posture.compute, 0.6), when the caller computed it for this row: no or early model,
    # stale model, layers off, risky allow-list entries (its worsening is notified as a security event, not here)
    out += list((row.get("posture") or {}).get("problems") or [])
    return out
