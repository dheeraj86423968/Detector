"""Platform health for the operator: Prometheus metrics (GET /metrics on the API, internal only: the gateway does not
route it) and the problems the notifier sends to the internal organisation's channels (event "platform")."""
from __future__ import annotations

import os
import shutil
import time

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from . import db

router = APIRouter()
DATA_DIR = os.environ.get("PDP_DATA_DIR", "/data")


def snapshot(c) -> dict:
    s = {}
    s["endpoints"] = db.q(c, "SELECT phase, kind, count(*) AS n, count(*) FILTER (WHERE last_seen > now() - interval '5 minutes') AS online "
                             "FROM endpoints GROUP BY 1, 2")
    s["versions"] = db.q(c, "SELECT coalesce(agent_version, 'unknown') AS v, count(*) AS n FROM endpoints WHERE phase <> 'retired' AND kind='live' GROUP BY 1")
    s["jobs"] = db.q(c, "SELECT kind, state, count(*) AS n, extract(epoch from now() - min(created_at)) AS oldest FROM jobs "
                        "WHERE state IN ('queued','running') GROUP BY 1, 2")
    s["alerts_hour"] = db.q(c, "SELECT count(*) AS n FROM alerts WHERE created_at > now() - interval '1 hour'", one=True)["n"]
    s["alerts_total"] = db.q(c, "SELECT count(*) AS n FROM alerts", one=True)["n"]
    s["uploads_hour"] = db.q(c, "SELECT coalesce(sum(rows), 0) AS n FROM upload_batches WHERE kind='events' AND received_at > now() - interval '1 hour'", one=True)["n"]
    s["orgs"] = db.q(c, "SELECT count(*) AS n FROM orgs WHERE NOT disabled", one=True)["n"]
    b = db.q(c, "SELECT v FROM kv WHERE k='backup'", one=True)
    s["backup"] = b["v"] if b else None
    n = db.q(c, "SELECT v FROM kv WHERE k='notifier'", one=True)
    s["notifier"] = n["v"] if n else None
    s["platform_db_bytes"] = db.q(c, "SELECT pg_database_size(current_database()) AS n", one=True)["n"]
    try:
        with db.conn(db.TELEMETRY_DSN) as t:
            s["telemetry_db_bytes"] = db.q(t, "SELECT pg_database_size(current_database()) AS n", one=True)["n"]
    except Exception:  # noqa
        s["telemetry_db_bytes"] = None
    try:
        du = shutil.disk_usage(DATA_DIR)
        s["data_free"], s["data_total"] = du.free, du.total
    except OSError:
        s["data_free"] = s["data_total"] = None
    return s


@router.get("/metrics", include_in_schema=False)
def metrics():
    with db.conn() as c:
        s = snapshot(c)
    out = []

    def m(name, value, help_, labels=None, typ="gauge"):
        if value is None:
            return
        if not any(l.startswith(f"# HELP {name} ") for l in out):
            out.append(f"# HELP {name} {help_}"); out.append(f"# TYPE {name} {typ}")
        lab = "{" + ",".join(f'{k}="{v}"' for k, v in labels.items()) + "}" if labels else ""
        out.append(f"{name}{lab} {float(value):g}")
    for r in s["endpoints"]:
        m("pdp_endpoints", r["n"], "endpoints by phase and kind", {"phase": r["phase"], "kind": r["kind"]})
        m("pdp_endpoints_online", r["online"], "endpoints that reported in the last 5 minutes", {"phase": r["phase"], "kind": r["kind"]})
    for r in s["versions"]:
        m("pdp_agent_version_endpoints", r["n"], "live endpoints by agent version", {"version": r["v"]})
    for r in s["jobs"]:
        m("pdp_jobs", r["n"], "queued / running jobs", {"kind": r["kind"], "state": r["state"]})
        m("pdp_job_oldest_seconds", r["oldest"], "age of the oldest queued / running job", {"kind": r["kind"], "state": r["state"]})
    m("pdp_alerts_last_hour", s["alerts_hour"], "alerts received in the last hour")
    m("pdp_alerts", s["alerts_total"], "alerts stored", typ="gauge")
    m("pdp_baseline_events_last_hour", s["uploads_hour"], "baseline events uploaded in the last hour")
    m("pdp_organisations", s["orgs"], "enabled organisations")
    if s["backup"]:
        m("pdp_backup_age_seconds", time.time() - float(s["backup"].get("at") or 0), "seconds since the last backup attempt")
        m("pdp_backup_ok", 1 if s["backup"].get("ok") else 0, "1 if the last backup succeeded")
        m("pdp_backup_bytes", s["backup"].get("bytes"), "size of the last backup archive")
    if s["notifier"]:
        m("pdp_notifier_age_seconds", time.time() - float(s["notifier"].get("at") or 0), "seconds since the notifier's last round")
    m("pdp_db_bytes", s["platform_db_bytes"], "database size", {"db": "platform"})
    m("pdp_db_bytes", s["telemetry_db_bytes"], "database size", {"db": "telemetry"})
    m("pdp_data_free_bytes", s["data_free"], "free space on the data volume")
    m("pdp_data_total_bytes", s["data_total"], "size of the data volume")
    return PlainTextResponse("\n".join(out) + "\n", media_type="text/plain; version=0.0.4")


def platform_problems(c) -> list[dict]:
    """[{key, level, text}] for the operator (notifier, internal organisation)."""
    out = []
    now = time.time()
    b = db.q(c, "SELECT v FROM kv WHERE k='backup'", one=True)
    if b:
        v = b["v"]
        if not v.get("ok"):
            out.append({"key": "backup_failed", "level": "error", "text": f"The last backup failed: {v.get('error') or 'see docker logs pdp-backup-1'}"})
        elif now - float(v.get("at") or 0) > 36 * 3600:
            out.append({"key": "backup_old", "level": "error", "text": f"No backup for {int((now - float(v['at'])) // 3600)} hours"})
    for r in db.q(c, "SELECT kind, extract(epoch from now() - min(created_at)) AS age FROM jobs WHERE state='queued' GROUP BY 1"):
        if r["kind"] != "command" and r["age"] > 2 * 3600:
            out.append({"key": f"queue_{r['kind']}", "level": "warning", "text": f"{r['kind']} jobs have waited {int(r['age'] // 3600)} hours (worker down or overloaded?)"})
    for r in db.q(c, "SELECT kind, count(*) AS n FROM jobs WHERE state='running' AND heartbeat < now() - interval '10 minutes' GROUP BY 1"):
        out.append({"key": f"stale_{r['kind']}", "level": "warning", "text": f"{r['n']} running {r['kind']} job(s) stopped reporting (worker crashed?)"})
    try:
        du = shutil.disk_usage(DATA_DIR)
        if du.free / du.total < 0.10:
            out.append({"key": "disk", "level": "error", "text": f"Only {du.free / 2**30:.0f} GB ({100 * du.free / du.total:.0f}%) free for server data"})
    except OSError:
        pass
    return out
