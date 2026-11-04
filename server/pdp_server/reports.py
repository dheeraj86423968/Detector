"""Weekly summary per organisation: the console's printable report (GET /api/reports/weekly) and the notifier's
Monday message (event "weekly")."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from . import db, incidents
from .access import session

router = APIRouter()
SEVS = ("critical", "high", "medium", "low")


def weekly(c, org_id, end: datetime | None = None) -> dict:
    end = end or datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    lo, hi = int(start.timestamp() * 1e9), int(end.timestamp() * 1e9)
    eps = db.q(c, "SELECT id, name, phase, last_seen FROM endpoints WHERE org_id=%s AND kind='live' AND phase <> 'retired'", (org_id,))
    ids = sorted(str(e["id"]) for e in eps)
    incs = incidents.list_incidents(c, ids) if ids else []
    new = [i for i in incs if lo <= i["first_ns"] < hi]
    open_now = [i for i in incs if i["status"] in ("open", "investigating")]
    alerts = db.q(c, "SELECT count(*) AS n, count(*) FILTER (WHERE status='false_positive') AS fp, count(*) FILTER (WHERE status='true_positive') AS tp "
                     "FROM alerts WHERE endpoint_id = ANY(%s::uuid[]) AND created_at >= %s AND created_at < %s", (ids, start, end), one=True) if ids else {"n": 0, "fp": 0, "tp": 0}
    now = time.time()
    online = sum(1 for e in eps if e["last_seen"] and now - e["last_seen"].timestamp() < 600)
    by_phase = {}
    for e in eps:
        by_phase[e["phase"]] = by_phase.get(e["phase"], 0) + 1
    top = sorted(new, key=lambda i: (SEVS.index(i["severity"]) if i["severity"] in SEVS else 9, -i["alerts"]))[:5]
    return {"from": start.isoformat(), "to": end.isoformat(),
            "incidents_new": len(new), "incidents_new_by_severity": {s: sum(1 for i in new if i["severity"] == s) for s in SEVS},
            "incidents_open": len(open_now), "alerts": alerts["n"], "false_alarms": alerts["fp"], "confirmed": alerts["tp"],
            "endpoints": len(eps), "endpoints_online": online, "endpoints_by_phase": by_phase,
            "top": [{"id": i["id"], "title": i["title"], "severity": i["severity"], "endpoint": i["endpoint_name"], "status": i["status"]} for i in top]}


def weekly_text(w: dict, org_name: str, console: str) -> str:
    sev = ", ".join(f"{n} {s}" for s, n in w["incidents_new_by_severity"].items() if n) or "none"
    lines = [f"PDP weekly summary for {org_name}, {w['from'][:10]} to {w['to'][:10]}", "",
             f"New incidents: {w['incidents_new']} ({sev}); still open: {w['incidents_open']}",
             f"Alerts: {w['alerts']} ({w['confirmed']} confirmed, {w['false_alarms']} marked false alarms)",
             f"Endpoints: {w['endpoints']} ({w['endpoints_online']} reporting; " + ", ".join(f"{n} {p}" for p, n in sorted(w["endpoints_by_phase"].items())) + ")"]
    if w["top"]:
        lines += ["", "Most important new incidents:"] + [f"- [{t['severity']}] {t['title']} ({t['endpoint']}, {t['status']}): {console}/#/incidents/{t['id']}" for t in w["top"]]
    lines += ["", f"Full report: {console}/#/reports/weekly"]
    return "\n".join(lines)


@router.get("/api/reports/weekly")
def weekly_report(s=Depends(session)):
    with db.conn() as c:
        return {"ok": True, "org": s.get("org_name"), **weekly(c, s["org"])}
