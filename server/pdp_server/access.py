"""Console access control: who is signed in, what they may do, which endpoints they may see.

Roles:   admin    everything (users and access, endpoints and their settings, triage, detection checks)
         analyst  view everything in scope, triage incidents and alerts, run detection checks
         viewer   view everything in scope, read-only
Scope:   users.endpoints NULL = all endpoints; otherwise a JSON list of endpoint ids the user may see. Admins always
         see every endpoint. Objects outside a user's scope answer 404, so a scoped user cannot probe other endpoints.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from . import auth, db

ROLES = ("admin", "analyst", "viewer")
ROLE_TEXT = {"admin": "Full access, including users, endpoints and settings",
             "analyst": "Investigates and triages incidents, runs detection checks",
             "viewer": "Read-only access to incidents, alerts and endpoint status"}


def session(request: Request) -> dict:
    """Valid session cookie AND the user still exists and is enabled: deleting or disabling a user, or changing
    their role or endpoint access, takes effect on the next request. Role and scope come from the database."""
    s = auth.read_session(request.cookies.get("pdp_session"))
    if not s:
        raise HTTPException(401, "not authenticated")
    with db.conn() as c:
        u = db.q(c, "SELECT role, auth, disabled, endpoints FROM users WHERE id=%s", (s["u"],), one=True)
    if not u or u["disabled"]:
        raise HTTPException(401, "user no longer exists or is disabled")
    scope = None if u["role"] == "admin" or u["endpoints"] is None else {str(x) for x in u["endpoints"]}
    return {**s, "r": u["role"], "a": u["auth"], "scope": scope}


def admin(s=Depends(session)) -> dict:
    if s["r"] != "admin":
        raise HTTPException(403, "admin role required")
    return s


def triager(s=Depends(session)) -> dict:
    if s["r"] not in ("admin", "analyst"):
        raise HTTPException(403, "your role is read-only")
    return s


def can(s: dict) -> dict:
    r = s["r"]
    return {"manage_users": r == "admin", "manage_endpoints": r == "admin",
            "triage": r in ("admin", "analyst"), "run_checks": r in ("admin", "analyst")}


def visible(s: dict, endpoint_id) -> bool:
    return s.get("scope") is None or str(endpoint_id) in s["scope"]


def require_endpoint(s: dict, endpoint_id) -> None:
    if not visible(s, endpoint_id):
        raise HTTPException(404, "not found")


def scope_list(s: dict) -> list[str] | None:
    """None = no restriction; else the visible endpoint ids (possibly empty) for `= ANY(%s::uuid[])`."""
    return None if s.get("scope") is None else sorted(s["scope"])


def scope_sql(s: dict, col: str) -> tuple[str, tuple]:
    """SQL fragment restricting `col` (an endpoint-id column) to the user's scope, with its parameters."""
    ids = scope_list(s)
    if ids is None:
        return "TRUE", ()
    return f"{col} = ANY(%s::uuid[])", (ids,)
