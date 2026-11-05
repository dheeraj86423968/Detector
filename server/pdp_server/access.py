"""Console access control: who is signed in, what they may do, which endpoints they may see.

Roles:   admin    everything (users and access, endpoints and their settings, triage, detection checks)
         analyst  view everything in scope, triage incidents and alerts, run detection checks
         viewer   view everything in scope, read-only
Tenancy: every user belongs to one organisation (orgs) and only ever sees that organisation's endpoints; this holds
         for admins too. The platform operator flag (users.operator) adds the organisation list (usage only), never
         another organisation's data.
Scope:   the organisation's endpoints, narrowed by users.endpoints (NULL = all of them; admins always see all of their
         organisation's). Objects outside a user's scope answer 404, so nobody can probe other endpoints.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request, Response

from . import auth, db

ROLES = ("admin", "analyst", "viewer")
ROLE_TEXT = {"admin": "Full access, including users, endpoints and settings",
             "analyst": "Investigates and triages incidents, runs detection checks",
             "viewer": "Read-only access to incidents, alerts and endpoint status"}


MFA_SETUP_PATHS = {"/api/me", "/api/me/mfa/setup", "/api/me/mfa/enable", "/api/logout", "/api/auth/config"}


def session(request: Request) -> dict:
    """Valid session cookie AND the user still exists and is enabled AND the cookie is of the user's current session
    generation: deleting or disabling a user, changing their role or endpoint access, and changing or resetting their
    password (which ends their other sessions) take effect on the next request. Role and scope come from the database."""
    s = auth.read_session(request.cookies.get("pdp_session"))
    if not s:
        raise HTTPException(401, "not authenticated")
    with db.conn() as c:
        u = db.q(c, "SELECT u.role, u.auth, u.disabled, u.endpoints, u.org_id, u.operator, u.totp_enabled, u.session_gen, o.require_mfa, "
                    "o.disabled AS org_disabled, o.name AS org_name "
                    "FROM users u JOIN orgs o ON o.id = u.org_id WHERE u.id=%s", (s["u"],), one=True)
        if not u or u["disabled"] or u["org_disabled"]:
            raise HTTPException(401, "user no longer exists or is disabled")
        if int(s.get("g", 0)) != u["session_gen"]:
            raise HTTPException(401, "this session was ended (password changed or signed out everywhere); sign in again")
        if u["require_mfa"] and u["auth"] == "local" and not u["totp_enabled"] and request.url.path not in MFA_SETUP_PATHS:
            raise HTTPException(403, "your organisation requires two-factor sign-in: set it up under Account first")
        org_eps = {str(r["id"]) for r in db.q(c, "SELECT id FROM endpoints WHERE org_id=%s", (u["org_id"],))}
    scope = org_eps if u["role"] == "admin" or u["endpoints"] is None else org_eps & {str(x) for x in u["endpoints"]}
    return {**s, "r": u["role"], "a": u["auth"], "scope": scope, "org": str(u["org_id"]), "org_name": u["org_name"],
            "op": bool(u["operator"])}


def set_session(response: Response, user_id: int, role: str) -> None:
    """Sign the user in on this response with a session of their current generation."""
    with db.conn() as c:
        g = db.q(c, "SELECT session_gen FROM users WHERE id=%s", (user_id,), one=True)
    response.set_cookie("pdp_session", auth.make_session(user_id, role, g["session_gen"] if g else 0), httponly=True, secure=True,
                        samesite="strict", max_age=auth.SESSION_TTL, path="/")


def end_sessions(c, user_id: int) -> None:
    """End every session of this user (password change or reset, sign out everywhere). Call inside the transaction
    that makes the change; sign the acting user in again with set_session() afterwards if they keep working."""
    db.q(c, "UPDATE users SET session_gen = session_gen + 1 WHERE id=%s", (user_id,))


def admin(s=Depends(session)) -> dict:
    if s["r"] != "admin":
        raise HTTPException(403, "admin role required")
    return s


def operator(s=Depends(session)) -> dict:
    if not s["op"]:
        raise HTTPException(404, "not found")
    return s


def triager(s=Depends(session)) -> dict:
    if s["r"] not in ("admin", "analyst"):
        raise HTTPException(403, "your role is read-only")
    return s


def can(s: dict) -> dict:
    r = s["r"]
    return {"manage_users": r == "admin", "manage_endpoints": r == "admin",
            "triage": r in ("admin", "analyst"), "run_checks": r in ("admin", "analyst"),
            "manage_org": r == "admin", "operate": bool(s.get("op"))}


def visible(s: dict, endpoint_id) -> bool:
    return s.get("scope") is None or str(endpoint_id) in s["scope"]


def require_endpoint(s: dict, endpoint_id) -> None:
    if not visible(s, endpoint_id):
        raise HTTPException(404, "not found")


def scope_list(s: dict) -> list[str] | None:
    """The visible endpoint ids (possibly empty) for `= ANY(%s::uuid[])`. A console session always has a scope (its
    organisation); None only for internal callers that pass no session."""
    return None if s.get("scope") is None else sorted(s["scope"])


def scope_sql(s: dict, col: str) -> tuple[str, tuple]:
    """SQL fragment restricting `col` (an endpoint-id column) to the user's scope, with its parameters."""
    ids = scope_list(s)
    if ids is None:
        return "TRUE", ()
    return f"{col} = ANY(%s::uuid[])", (ids,)
