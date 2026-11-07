"""Learning integrity (0.6): what an endpoint's own alerts say about its baseline.

A model is (re)trained on the endpoint's recent days. If an attacker was active on those days - before the first
model, or between two retrainings (the periodic refresh retrains on the two most recent days) - the attack would
become "normal": its program a known program for layer 1, its command-and-control address a trusted address for
layer 2, its rule keys benign-calibrated. Two safeguards, both general:

1. Exclusions. Everything an alert of this endpoint points at stays out of the new model's notion of normal unless
   an administrator resolved that alert as benign (a false-positive or closed verdict by an admin, or an allow-list
   entry, which only admins create): the programs of new-program and untrusted-exec alerts, the remote addresses of
   alerted network endpoints, and the (rule, key) pairs of rule alerts. Open, acknowledged, true-positive alerts and
   verdicts by analysts do not release anything - "nobody looked at it" and "one analyst closed it" are exactly what
   an attacker (or an insider) would arrange. pdp_engine.layers.fit_layers(exclude=...) applies them.

2. Verified feedback. Alerts marked false positive become benign training windows (worker.write_feedback_day) only
   when the verdict is an administrator's or comes from an allow-list entry.

Alerts recorded before 0.6 have no verdict author (status_by NULL) and count as unverified.
"""
from __future__ import annotations

from . import db

# verdicts that release an alert's activity into the baseline when an administrator gave them
RELEASING = ("false_positive", "closed")
MAX_ALERTS = 50_000          # most recent alerts considered per endpoint (bounded work per training)

# COALESCE: a verdict without an author (status_by NULL) is unverified - plain SQL would make the test NULL, and
# NOT (... AND NULL) silently drops the alert from the exclusions
VERIFIED_SQL = ("COALESCE(a.allowed_by IS NOT NULL OR a.status_by IN (SELECT u.id FROM users u WHERE u.role = 'admin'), false)")


def _remote_ip(label: str) -> str:
    parts = (label or "").split(" ")
    return parts[1] if len(parts) > 1 else ""


def day_end_ns(days, tz: str = "UTC") -> int | None:
    """End (exclusive, ns since epoch) of the latest calendar day in `days` ('YYYY-MM-DD' in the endpoint's time
    zone); None if no day parses (early models train on pseudo-days)."""
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    best = None
    for d in days:
        try:
            t = datetime.strptime(str(d), "%Y-%m-%d").replace(tzinfo=ZoneInfo(tz or "UTC")) + timedelta(days=1)
        except (ValueError, KeyError):
            continue
        ns = int(t.timestamp()) * 1_000_000_000
        best = ns if best is None else max(best, ns)
    return best


def exclusions(c, eid: str, until_ns: int | None = None) -> dict:
    """{"programs", "addresses", "rule_keys"} pointed at by this endpoint's unreleased alerts (see module doc).
    until_ns: only alerts about activity before this time (the end of the days being learned) - alerts about later
    activity say nothing about the baseline's content (and on a replayed benchmark they come from the test days)."""
    rows = db.q(c, f"SELECT a.ntype, a.label, a.layer, a.rule, a.reasons FROM alerts a WHERE a.endpoint_id=%s "
                   f"AND NOT (a.status IN %s AND {VERIFIED_SQL}) AND (%s::bigint IS NULL OR a.window_start_ns < %s::bigint) "
                   f"ORDER BY a.id DESC LIMIT %s", (eid, RELEASING, until_ns, until_ns, MAX_ALERTS))
    progs, addrs, keys = set(), set(), set()
    for r in rows:
        if r["ntype"] == "netflow":
            ip = _remote_ip(r["label"])
            if ip:
                addrs.add(ip)
        for x in (r["reasons"] or []) or [{"layer": r["layer"], "rule": r["rule"]}]:
            rule, key = x.get("rule"), x.get("key")
            if not rule or key is None:
                continue
            if rule in ("novel_executable", "novel_executable_repeat", "untrusted_exec"):
                progs.add(str(key))
            if x.get("layer") in ("rules", "corroborated") or rule in ("untrusted_exec", "exfiltration", "untrusted_code_network",
                                                                       "untrusted_persistence", "tainted_spawn", "tainted_modify"):
                keys.add((str(rule), str(key)))
    return {"programs": sorted(progs), "addresses": sorted(addrs), "rule_keys": sorted([list(k) for k in keys])}


def feedback_filter() -> str:
    """SQL condition (alias a) for false-positive verdicts that may become benign training data."""
    return VERIFIED_SQL


def exclude_nodes(reg, ex: dict) -> list[int]:
    """0.7: registry positions detector-3 must not learn from - processes of an excluded program and network
    endpoints at an excluded address (the same unreleased alerts as for layers 1-2). Every event touching them is left
    out of the counts, so an attacker active during the baseline does not become 'what this program normally does'."""
    from pdp_engine.layers import executable, program_key, remote_ip
    progs, addrs = set(ex.get("programs") or ()), set(ex.get("addresses") or ())
    if not progs and not addrs:
        return []
    out = []
    for i, e in enumerate(reg.entities):
        if e.ntype == "subject" and progs:
            exe = executable(e.label)
            if program_key(exe, strict=True) in progs or program_key(exe) in progs:
                out.append(i)
        elif e.ntype == "netflow" and addrs and remote_ip(e.label) in addrs:
            out.append(i)
    return out
