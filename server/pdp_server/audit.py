"""Console audit log: who changed what, when, from where (table audit_log, org-scoped).

A middleware records every mutating console request (POST / PATCH / PUT / DELETE under /api/) after it has been
answered, as "METHOD /route/{template}" with the path's ids as target and the HTTP status (refused attempts are
recorded too). Request bodies are not stored (they may hold passwords or secrets). Sign-in attempts are recorded by
the login routes themselves (no session exists yet). Admins read their organisation's log: GET /api/audit.

0.6 (pdp_server.posture.audit_change): changes to endpoint settings, the allow list, organisation and notification
settings and users add a row of their own, written in the same transaction as the change, whose `detail` holds a
redacted before/after diff (secrets never, URLs reduced to their host), the reason given and, for a change that
weakens detection, what it weakens. Alert exports (with the row count) and hunts (with the query text) are recorded
too. The audit log is kept for at least 365 days, whatever the organisation's data retention (worker.apply_retention)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from . import auth, db
from .access import admin

router = APIRouter()
SKIP = ("/api/registry/auth", "/api/login", "/api/logout", "/api/signup")   # recorded explicitly or not a change


def record(org_id, user_id, username, action, target=None, status=None, ip=None, detail: dict | None = None):
    try:
        import json
        with db.conn() as c:
            db.q(c, "INSERT INTO audit_log (org_id, user_id, username, action, target, status, ip, detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                 (org_id, user_id, username, action[:200], (target or "")[:300] or None, status, (ip or "")[:64] or None,
                  json.dumps(detail, default=str) if detail else None))
    except Exception:  # noqa - the audit log must never break a request
        pass


def _client_ip(request: Request) -> str | None:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


async def middleware(request: Request, call_next):
    resp = await call_next(request)
    path = request.url.path
    if request.method in ("POST", "PATCH", "PUT", "DELETE") and path.startswith("/api/") and not path.startswith(SKIP):
        s = auth.read_session(request.cookies.get("pdp_session"))
        route = request.scope.get("route")
        tmpl = getattr(route, "path", path)
        params = request.scope.get("path_params") or {}
        target = ", ".join(f"{k}={v}" for k, v in params.items()) or None
        uid = s.get("u") if s else None
        await run_in_threadpool(_record_request, uid, f"{request.method} {tmpl}", target, resp.status_code, _client_ip(request))
    return resp


def _record_request(uid, action, target, status, ip):
    org, name = None, None
    if uid is not None:
        try:
            with db.conn() as c:
                u = db.q(c, "SELECT org_id, username FROM users WHERE id=%s", (uid,), one=True)
            if u:
                org, name = u["org_id"], u["username"]
        except Exception:  # noqa
            pass
    if org is None and uid is None:
        return              # anonymous requests (invite acceptance etc.) belong to no organisation's log
    record(org, uid, name, action, target, status, ip)


@router.get("/api/audit")
def audit_list(limit: int = 200, s=Depends(admin)):
    with db.conn() as c:
        rows = db.q(c, "SELECT a.id, a.at, coalesce(u.display_name, a.username) AS who, a.action, a.target, a.status, a.ip, a.detail FROM audit_log a "
                       "LEFT JOIN users u ON u.id=a.user_id WHERE a.org_id=%s ORDER BY a.at DESC, a.id DESC LIMIT %s",
                    (s["org"], max(1, min(int(limit), 2000))))
    return {"ok": True, "entries": rows}
