"""Organisations (hosted multi-tenant): sign-up, invites, organisation settings, operator overview.

Every user, endpoint, enrolment token and allow-list entry belongs to one organisation; pdp_server.access scopes every
console request to the caller's organisation. A client organisation is created by self sign-up (PDP_SIGNUP=open, or
=code with PDP_SIGNUP_CODE), its admin invites the team with single-use links and enrols agents with the one-line
installer - nobody at the provider has to do anything. The operator (users.operator) sees organisations and their
usage only.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import auth, db
from .access import ROLE_TEXT, admin, operator, session

router = APIRouter()

SIGNUP = os.environ.get("PDP_SIGNUP", "off").strip().lower()            # off | code | open
SIGNUP_CODE = os.environ.get("PDP_SIGNUP_CODE", "").strip()
DEFAULT_MAX_ENDPOINTS = int(os.environ.get("PDP_ORG_MAX_ENDPOINTS", "25"))
INTERNAL_ORG_NAME = os.environ.get("PDP_INTERNAL_ORG_NAME", "Internal")
INVITE_DAYS = 7
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")
SIGNUPS_PER_HOUR = int(os.environ.get("PDP_SIGNUPS_PER_HOUR", "5"))


def signup_mode() -> str:
    if SIGNUP == "code" and not SIGNUP_CODE:
        return "off"          # a code mode without a code would admit nobody; say so instead of pretending
    return SIGNUP if SIGNUP in ("off", "code", "open") else "off"


# ---------------------------------------------------------------------------------------------- migration
def internal_org(c) -> str:
    r = db.q(c, "SELECT id FROM orgs WHERE internal", one=True)
    if r:
        return str(r["id"])
    return str(db.q(c, "INSERT INTO orgs (name, internal, max_endpoints) VALUES (%s, true, 100000) "
                       "ON CONFLICT (internal) WHERE internal DO UPDATE SET internal=true RETURNING id", (INTERNAL_ORG_NAME,), one=True)["id"])


def migrate(c) -> None:
    """Existing single-tenant installations: everything without an organisation joins the internal one, whose
    first admin becomes the operator."""
    org = internal_org(c)
    for t in ("users", "endpoints", "enroll_tokens", "allowlist"):
        db.q(c, f"UPDATE {t} SET org_id=%s WHERE org_id IS NULL", (org,))
    if not db.q(c, "SELECT 1 FROM users WHERE operator", one=True):
        db.q(c, "UPDATE users SET operator=true WHERE id = (SELECT min(id) FROM users WHERE org_id=%s AND role='admin')", (org,))


# ---------------------------------------------------------------------------------------------- helpers
def endpoint_usage(c, org_id: str) -> int:
    """Active endpoints plus unused, unexpired single-endpoint enrolment tokens: what counts against the endpoint limit
    (a Kubernetes fleet token reserves nothing; the limit is checked at each node's enrolment)."""
    return db.q(c, "SELECT (SELECT count(*) FROM endpoints WHERE org_id=%s AND phase<>'retired') + "
                   "(SELECT count(*) FROM enroll_tokens WHERE org_id=%s AND used_by IS NULL AND max_uses IS NULL AND expires_at > now()) AS n",
                (org_id, org_id), one=True)["n"]


def check_endpoint_limit(c, org_id: str) -> None:
    o = db.q(c, "SELECT max_endpoints FROM orgs WHERE id=%s", (org_id,), one=True)
    if o and endpoint_usage(c, org_id) >= o["max_endpoints"]:
        raise HTTPException(403, f"Your organisation has reached its limit of {o['max_endpoints']} endpoints. "
                                 "Retire an endpoint or ask for a higher limit.")


def me_body(c, uid: int) -> dict:
    from .access import can
    u = db.q(c, "SELECT u.*, o.name AS org_name, o.require_mfa FROM users u JOIN orgs o ON o.id=u.org_id WHERE u.id=%s", (uid,), one=True)
    s = {"r": u["role"], "op": bool(u["operator"])}
    return {"ok": True, "role": u["role"], "username": u["username"], "display_name": u["display_name"] or u["username"],
            "user_id": u["id"], "auth": u["auth"], "email": u["email"],
            "endpoints": None if u["role"] == "admin" else u["endpoints"], "can": can(s),
            "org": {"id": str(u["org_id"]), "name": u["org_name"]}, "operator": bool(u["operator"]),
            "mfa_enabled": bool(u.get("totp_enabled")),
            "mfa_setup_required": bool(u.get("require_mfa")) and u["auth"] == "local" and not u.get("totp_enabled")}


def _sign_in(response: Response, uid: int, role: str) -> None:
    response.set_cookie("pdp_session", auth.make_session(uid, role), httponly=True, secure=True, samesite="strict",
                        max_age=auth.SESSION_TTL, path="/")


def _email(v: str | None) -> str:
    e = (v or "").strip().lower()
    if not EMAIL_RE.match(e) or len(e) > 254:
        raise HTTPException(400, "Enter a valid email address")
    return e


def _password(v: str) -> str:
    if len(v or "") < 10:
        raise HTTPException(400, "The password must have at least 10 characters")
    if len(v) > 256:
        raise HTTPException(400, "The password is too long")
    return v


def _name(v: str | None, what: str, lo: int = 1, hi: int = 128) -> str:
    n = " ".join((v or "").split())
    if not lo <= len(n) <= hi:
        raise HTTPException(400, f"{what} must have {lo}-{hi} characters")
    return n


def _taken(c, email: str) -> bool:
    return bool(db.q(c, "SELECT 1 FROM users WHERE lower(username)=%s OR lower(email)=%s", (email, email), one=True))


_rate: dict[str, list[float]] = {}
_rate_lock = threading.Lock()


def _rate_limit(request: Request) -> None:
    ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "?")
    now = time.time()
    with _rate_lock:
        hits = [t for t in _rate.get(ip, []) if now - t < 3600]
        if len(hits) >= SIGNUPS_PER_HOUR:
            raise HTTPException(429, "Too many sign-ups from your network; try again later")
        hits.append(now)
        _rate[ip] = hits


def _base(request: Request) -> str:
    return f"https://{request.headers.get('host', request.url.netloc)}"


# ---------------------------------------------------------------------------------------------- sign-up
class SignUp(BaseModel):
    organisation: str = Field(max_length=200)
    name: str = Field(max_length=200)
    email: str = Field(max_length=300)
    password: str = Field(max_length=1000)
    code: str | None = Field(default=None, max_length=200)


@router.post("/api/signup")
def signup(req: SignUp, request: Request, response: Response):
    mode = signup_mode()
    if mode == "off":
        raise HTTPException(403, "Sign-up is not open on this server")
    if mode == "code" and not hmac.compare_digest((req.code or "").strip().encode(), SIGNUP_CODE.encode()):
        raise HTTPException(403, "The sign-up code is not valid")
    org_name = _name(req.organisation, "Organisation name", 2, 80)
    name = _name(req.name, "Your name")
    email = _email(req.email)
    pw = _password(req.password)
    _rate_limit(request)
    with db.conn() as c:
        if _taken(c, email):
            raise HTTPException(409, "An account with this email already exists; sign in instead")
        org = db.q(c, "INSERT INTO orgs (name, max_endpoints) VALUES (%s, %s) RETURNING id", (org_name, DEFAULT_MAX_ENDPOINTS), one=True)["id"]
        uid = db.q(c, "INSERT INTO users (username, password_hash, role, display_name, email, org_id, last_login) "
                      "VALUES (%s,%s,'admin',%s,%s,%s,now()) RETURNING id", (email, auth.hash_password(pw), name, email, org), one=True)["id"]
        body = me_body(c, uid)
    _sign_in(response, uid, "admin")
    return body


# ---------------------------------------------------------------------------------------------- invites
class NewInvite(BaseModel):
    email: str | None = Field(default=None, max_length=300)
    role: str = "viewer"
    endpoints: list[str] | None = None


def _invite_out(r: dict, names: dict, base: str) -> dict:
    eps = None if r["role"] == "admin" or r["endpoints"] is None else [{"id": e, "name": names.get(e, "(removed endpoint)")} for e in r["endpoints"]]
    return {"id": r["id"], "email": r["email"], "role": r["role"], "endpoints": eps, "created_at": r["created_at"],
            "expires_at": r["expires_at"], "created_by": r.get("created_by_name"), "link": f"{base}/#/join/{r['token']}"}


@router.get("/api/invites")
def list_invites(request: Request, s=Depends(admin)):
    with db.conn() as c:
        rows = db.q(c, "SELECT i.*, coalesce(u.display_name, u.username) AS created_by_name FROM invites i LEFT JOIN users u ON u.id=i.created_by "
                       "WHERE i.org_id=%s AND i.used_at IS NULL AND NOT i.revoked AND i.expires_at > now() ORDER BY i.created_at DESC", (s["org"],))
        names = {str(r["id"]): r["name"] for r in db.q(c, "SELECT id, name FROM endpoints WHERE org_id=%s", (s["org"],))}
    return {"ok": True, "invites": [_invite_out(r, names, _base(request)) for r in rows]}


@router.post("/api/invites")
def create_invite(req: NewInvite, request: Request, s=Depends(admin)):
    from .api import _check_endpoint_ids
    if req.role not in ROLE_TEXT:
        raise HTTPException(400, "role must be admin, analyst or viewer")
    email = _email(req.email) if (req.email or "").strip() else None
    with db.conn() as c:
        if email and _taken(c, email):
            raise HTTPException(409, "An account with this email already exists")
        eps = None if req.role == "admin" else _check_endpoint_ids(c, req.endpoints, s)
        if db.q(c, "SELECT count(*) AS n FROM invites WHERE org_id=%s AND used_at IS NULL AND NOT revoked AND expires_at > now()", (s["org"],), one=True)["n"] >= 200:
            raise HTTPException(400, "Too many pending invites; revoke some first")
        r = db.q(c, "INSERT INTO invites (token, org_id, email, role, endpoints, created_by, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *",
                 (secrets.token_urlsafe(24), s["org"], email, req.role, json.dumps(eps) if eps is not None else None, s["u"],
                  datetime.now(timezone.utc) + timedelta(days=INVITE_DAYS)), one=True)
        r["created_by_name"] = db.q(c, "SELECT coalesce(display_name, username) AS n FROM users WHERE id=%s", (s["u"],), one=True)["n"]
        names = {str(x["id"]): x["name"] for x in db.q(c, "SELECT id, name FROM endpoints WHERE org_id=%s", (s["org"],))}
    return {"ok": True, "invite": _invite_out(r, names, _base(request))}


@router.delete("/api/invites/{invite_id}")
def revoke_invite(invite_id: int, s=Depends(admin)):
    with db.conn() as c:
        if not db.q(c, "UPDATE invites SET revoked=true WHERE id=%s AND org_id=%s AND used_at IS NULL RETURNING id", (invite_id, s["org"]), one=True):
            raise HTTPException(404, "not found")
    return {"ok": True}


def _open_invite(c, token: str) -> dict:
    if not token or len(token) > 100:
        raise HTTPException(404, "This invitation is not valid")
    r = db.q(c, "SELECT i.*, o.name AS org_name, o.disabled AS org_disabled, coalesce(u.display_name, u.username) AS by FROM invites i "
                "JOIN orgs o ON o.id=i.org_id LEFT JOIN users u ON u.id=i.created_by "
                "WHERE i.token=%s AND i.used_at IS NULL AND NOT i.revoked AND i.expires_at > now()", (token,), one=True)
    if not r or r["org_disabled"]:
        raise HTTPException(404, "This invitation is not valid. It may have expired, been used or been revoked.")
    return r


@router.get("/api/invites/{token}")
def invite_info(token: str):
    with db.conn() as c:
        r = _open_invite(c, token)
    return {"ok": True, "organisation": r["org_name"], "role": r["role"], "role_text": ROLE_TEXT[r["role"]], "email": r["email"],
            "expires_at": r["expires_at"], "invited_by": r["by"]}


class Accept(BaseModel):
    name: str = Field(max_length=200)
    email: str | None = Field(default=None, max_length=300)
    password: str = Field(max_length=1000)


@router.post("/api/invites/{token}/accept")
def accept_invite(token: str, req: Accept, response: Response):
    name, pw = _name(req.name, "Your name"), _password(req.password)
    conflict = None
    with db.conn() as c:
        inv = _open_invite(c, token)
        email = inv["email"] or _email(req.email)
        if inv["email"] and (req.email or "").strip() and _email(req.email) != inv["email"]:
            raise HTTPException(400, f"This invitation is for {inv['email']}")
        if _taken(c, email):
            conflict = "An account with this email already exists; sign in instead"
        else:
            # claim the invite first: two simultaneous accepts cannot both succeed
            if not db.q(c, "UPDATE invites SET used_at=now() WHERE id=%s AND used_at IS NULL RETURNING id", (inv["id"],), one=True):
                raise HTTPException(404, "This invitation is not valid")
            uid = db.q(c, "INSERT INTO users (username, password_hash, role, display_name, email, endpoints, org_id, last_login) "
                          "VALUES (%s,%s,%s,%s,%s,%s,%s,now()) RETURNING id",
                       (email, auth.hash_password(pw), inv["role"], name, email,
                        json.dumps(inv["endpoints"]) if inv["endpoints"] is not None else None, inv["org_id"]), one=True)["id"]
            db.q(c, "UPDATE invites SET used_by=%s WHERE id=%s", (uid, inv["id"]))
            body = me_body(c, uid)
    if conflict:
        raise HTTPException(409, conflict)
    _sign_in(response, uid, inv["role"])
    return body


# ---------------------------------------------------------------------------------------------- organisation
def _org_out(c, org_id: str) -> dict:
    o = db.q(c, "SELECT * FROM orgs WHERE id=%s", (org_id,), one=True)
    return {"id": str(o["id"]), "name": o["name"], "created_at": o["created_at"], "max_endpoints": o["max_endpoints"],
            "retention_days": o.get("retention_days"), "require_mfa": bool(o.get("require_mfa")),
            "response_actions": bool(o.get("response_actions")),
            "sso": _sso_out(o.get("sso")),
            "endpoints": db.q(c, "SELECT count(*) AS n FROM endpoints WHERE org_id=%s AND phase<>'retired'", (org_id,), one=True)["n"],
            "endpoint_usage": endpoint_usage(c, org_id),
            "users": db.q(c, "SELECT count(*) AS n FROM users WHERE org_id=%s AND NOT disabled", (org_id,), one=True)["n"],
            "pending_invites": db.q(c, "SELECT count(*) AS n FROM invites WHERE org_id=%s AND used_at IS NULL AND NOT revoked AND expires_at > now()",
                                    (org_id,), one=True)["n"]}


@router.get("/api/org")
def get_org(s=Depends(session)):
    with db.conn() as c:
        return {"ok": True, "org": _org_out(c, s["org"])}


class OrgPatch(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    retention_days: int | None = None
    require_mfa: bool | None = None
    response_actions: bool | None = None


def _sso_out(sso: dict | None) -> dict | None:
    if not sso:
        return None
    return {k: v for k, v in sso.items() if k != "client_secret"} | {"has_secret": bool(sso.get("client_secret"))}


@router.patch("/api/org")
def patch_org(req: OrgPatch, s=Depends(admin)):
    sets, vals = [], []
    if req.name is not None:
        sets.append("name=%s"); vals.append(_name(req.name, "Organisation name", 2, 80))
    if req.retention_days is not None:
        if not 30 <= req.retention_days <= 3650:
            raise HTTPException(400, "keep data between 30 and 3650 days")
        sets.append("retention_days=%s"); vals.append(req.retention_days)
    if req.require_mfa is not None:
        sets.append("require_mfa=%s"); vals.append(req.require_mfa)
    if req.response_actions is not None:
        sets.append("response_actions=%s"); vals.append(req.response_actions)
    with db.conn() as c:
        if sets:
            db.q(c, f"UPDATE orgs SET {', '.join(sets)} WHERE id=%s", (*vals, s["org"]))
        return {"ok": True, "org": _org_out(c, s["org"])}


# ---------------------------------------------------------------------------------------------- operator
@router.get("/api/operator/orgs")
def operator_orgs(s=Depends(operator)):
    with db.conn() as c:
        rows = db.q(c, """
            SELECT o.id, o.name, o.created_at, o.disabled, o.max_endpoints, o.internal,
                   (SELECT count(*) FROM users u WHERE u.org_id=o.id AND NOT u.disabled) AS users,
                   (SELECT count(*) FROM endpoints e WHERE e.org_id=o.id AND e.phase<>'retired') AS endpoints,
                   (SELECT count(*) FROM endpoints e WHERE e.org_id=o.id AND e.phase<>'retired' AND e.kind='live'
                      AND e.last_seen > now() - interval '5 minutes') AS endpoints_online,
                   (SELECT count(*) FROM alerts a JOIN endpoints e ON e.id=a.endpoint_id WHERE e.org_id=o.id
                      AND a.created_at > now() - interval '7 days') AS alerts_7d,
                   GREATEST((SELECT max(last_seen) FROM endpoints e WHERE e.org_id=o.id),
                            (SELECT max(last_login) FROM users u WHERE u.org_id=o.id)) AS last_activity
            FROM orgs o ORDER BY o.internal DESC, o.created_at""")
    return {"ok": True, "signup": {"mode": signup_mode(), "code": SIGNUP_CODE if signup_mode() == "code" else None},
            "orgs": [{**r, "id": str(r["id"])} for r in rows]}


class OrgAdmin(BaseModel):
    disabled: bool | None = None
    max_endpoints: int | None = Field(default=None, ge=0, le=100000)


@router.patch("/api/operator/orgs/{org_id}")
def operator_patch(org_id: str, req: OrgAdmin, s=Depends(operator)):
    with db.conn() as c:
        o = db.q(c, "SELECT id, internal FROM orgs WHERE id::text=%s", (org_id,), one=True)
        if not o:
            raise HTTPException(404, "not found")
        if req.disabled and o["internal"]:
            raise HTTPException(400, "The operator's own organisation cannot be disabled")
        if req.disabled is not None:
            db.q(c, "UPDATE orgs SET disabled=%s WHERE id=%s", (req.disabled, o["id"]))
        if req.max_endpoints is not None:
            db.q(c, "UPDATE orgs SET max_endpoints=%s WHERE id=%s", (req.max_endpoints, o["id"]))
        r = db.q(c, "SELECT id, name, created_at, disabled, max_endpoints FROM orgs WHERE id=%s", (o["id"],), one=True)
    return {"ok": True, "org": {**r, "id": str(r["id"])}}


@router.delete("/api/operator/orgs/{org_id}")
def operator_delete(org_id: str, s=Depends(operator)):
    """Offboard a client: delete the organisation and everything it owns (users, endpoints and their telemetry,
    alerts, models, checks, allow list, invites). Only a disabled, non-internal organisation can be deleted."""
    import shutil
    with db.conn() as c:
        o = db.q(c, "SELECT id, internal, disabled FROM orgs WHERE id::text=%s", (org_id,), one=True)
        if not o:
            raise HTTPException(404, "not found")
        if o["internal"]:
            raise HTTPException(400, "The operator's own organisation cannot be deleted")
        if not o["disabled"]:
            raise HTTPException(400, "Disable the organisation first")
        eps = [str(r["id"]) for r in db.q(c, "SELECT id FROM endpoints WHERE org_id=%s", (o["id"],))]
        if eps:
            db.q(c, "DELETE FROM sim_campaigns WHERE endpoint_id = ANY(%s::uuid[])", (eps,))
            db.q(c, "DELETE FROM endpoints WHERE id = ANY(%s::uuid[])", (eps,))     # cascades: jobs, bundles, windows, alerts, days
        db.q(c, "DELETE FROM enroll_tokens WHERE org_id=%s", (o["id"],))
        db.q(c, "DELETE FROM allowlist WHERE org_id=%s", (o["id"],))
        db.q(c, "DELETE FROM invites WHERE org_id=%s", (o["id"],))
        db.q(c, "DELETE FROM users WHERE org_id=%s", (o["id"],))
        db.q(c, "DELETE FROM orgs WHERE id=%s", (o["id"],))
    data = os.environ.get("PDP_DATA_DIR", "/data")
    for e in eps:
        db.drop_telemetry(e)
        shutil.rmtree(os.path.join(data, "bundles", e), ignore_errors=True)
    return {"ok": True, "endpoints_deleted": len(eps)}
