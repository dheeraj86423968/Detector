"""Single sign-on per organisation: each organisation's admins connect their own identity provider (Google
Workspace, Microsoft Entra ID or any OpenID Connect provider) for the email domains they own.

Sign-in: the login page asks for the email address; GET /api/sso/start?email= finds the organisation whose SSO
domains contain the address's domain and sends the browser to that organisation's provider (authorization code
flow with PKCE, state + nonce in a signed 10-minute cookie); GET /api/sso/callback exchanges the code, verifies the
ID token (signature against the provider's JWKS, issuer, audience, expiry, nonce), requires a verified email in one
of the organisation's domains, and signs the user in to that organisation only: an existing account with that email,
else a new one with the organisation's default role (admin for the listed admin emails).

Domains are unique across organisations and public mail providers cannot be claimed. Proof of domain ownership
(DNS TXT) is not implemented yet - the operator should check new SSO domains (Operator page lists them).

The API reaches the providers through the egress proxy (compose profile "sso"); its allow list must contain the
providers' hosts: Google accounts.google.com, oauth2.googleapis.com, www.googleapis.com, openidconnect.googleapis.com;
Microsoft login.microsoftonline.com; other providers their issuer host.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import urllib.parse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from . import db
from .access import admin
from .oidc import CLOCK_SKEW, OIDCError, _b64e, _http, _sign, _unsign, verify_jwt

router = APIRouter()
PUBLIC_DOMAINS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "me.com",
                  "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com", "zoho.com"}
DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
_lock = threading.Lock()
_cache: dict[str, tuple[float, dict]] = {}


def issuer_of(cfg: dict) -> str:
    p = cfg.get("provider")
    if p == "google":
        return "https://accounts.google.com"
    if p == "microsoft":
        return f"https://login.microsoftonline.com/{cfg['tenant']}/v2.0"
    return str(cfg.get("issuer") or "").rstrip("/")


def _cached(key: str, fn):
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < 3600:
            return hit[1]
    v = fn()
    with _lock:
        _cache[key] = (time.time(), v)
    return v


def discovery(iss: str) -> dict:
    def get():
        d = _http(f"{iss}/.well-known/openid-configuration")
        if d.get("issuer", "").rstrip("/") != iss:
            raise OIDCError(f"discovery issuer {d.get('issuer')!r} does not match {iss!r}")
        return d
    return _cached("d:" + iss, get)


def jwk_lookup(iss: str):
    def lookup(kid):
        for attempt in (0, 1):
            if attempt:
                with _lock:
                    _cache.pop("k:" + iss, None)
            keys = _cached("k:" + iss, lambda: _http(discovery(iss)["jwks_uri"]))
            for k in keys.get("keys", []):
                if kid is None or k.get("kid") == kid:
                    return k
        raise OIDCError(f"no signing key {kid!r} at the identity provider")
    return lookup


def validate(claims: dict, iss: str, client_id: str, nonce: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    if claims.get("iss", "").rstrip("/") != iss:
        raise OIDCError("ID token issuer mismatch")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if client_id not in auds or (len(auds) > 1 and claims.get("azp") not in (None, client_id)):
        raise OIDCError("ID token audience mismatch")
    if float(claims.get("exp", 0)) < now - CLOCK_SKEW or float(claims.get("iat", now)) > now + CLOCK_SKEW:
        raise OIDCError("ID token expired or not yet valid")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OIDCError("ID token nonce mismatch (replayed or foreign sign-in)")


def email_of(claims: dict, provider: str) -> str | None:
    e = claims.get("email")
    if provider == "microsoft" and not e:
        e = claims.get("preferred_username")            # Entra ID: the UPN (tenant-controlled)
    if not e or "@" not in str(e):
        return None
    if provider != "microsoft" and claims.get("email_verified") is False:
        return None
    return str(e).strip().lower()


def org_for_domain(c, domain: str) -> dict | None:
    return db.q(c, "SELECT id, name, sso FROM orgs WHERE NOT disabled AND sso IS NOT NULL AND (sso->>'enabled')::boolean "
                   "AND sso->'domains' ? %s", (domain.lower(),), one=True)


def _base(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{proto}://{request.headers.get('host', request.url.netloc)}"


# ------------------------------------------------------------------------------------------------ sign-in
@router.get("/api/sso/start")
def sso_start(email: str, request: Request):
    email = (email or "").strip().lower()
    if "@" not in email:
        raise HTTPException(400, "enter your work email address")
    with db.conn() as c:
        org = org_for_domain(c, email.rsplit("@", 1)[1])
    if not org:
        raise HTTPException(404, "no single sign-on is set up for this email domain; sign in with your password")
    cfg = org["sso"]
    iss = issuer_of(cfg)
    redirect = _base(request) + "/api/sso/callback"
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    q = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": redirect, "scope": "openid profile email",
         "state": state, "nonce": nonce, "code_challenge": _b64e(hashlib.sha256(verifier.encode()).digest()),
         "code_challenge_method": "S256", "login_hint": email}
    if cfg.get("provider") == "google" and len(cfg.get("domains") or []) == 1:
        q["hd"] = cfg["domains"][0]
    try:
        url = discovery(iss)["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)
    except OIDCError as e:
        raise HTTPException(502, f"identity provider unreachable: {e}")
    r = RedirectResponse(url, status_code=302)
    r.set_cookie("pdp_sso", _sign({"s": state, "n": nonce, "v": verifier, "r": redirect, "o": str(org["id"]), "exp": int(time.time()) + 600}),
                 httponly=True, secure=True, samesite="lax", max_age=600, path="/api/sso")
    return r


def finish(cfg: dict, org_id: str, code: str, st: dict) -> dict:
    iss = issuer_of(cfg)
    d = discovery(iss)
    basic = base64.b64encode(f"{urllib.parse.quote(cfg['client_id'], safe='')}:{urllib.parse.quote(cfg.get('client_secret') or '', safe='')}".encode()).decode()
    tok = _http(d["token_endpoint"], {"grant_type": "authorization_code", "code": code, "redirect_uri": st["r"], "code_verifier": st["v"]},
                {"Authorization": f"Basic {basic}"})
    if "id_token" not in tok:
        raise OIDCError("the identity provider returned no ID token")
    claims = verify_jwt(tok["id_token"], jwk_lookup(iss))
    validate(claims, iss, cfg["client_id"], st["n"])
    email = email_of(claims, cfg.get("provider", "oidc"))
    if not email or email.rsplit("@", 1)[1] not in set(cfg.get("domains") or []):
        raise OIDCError("your account's email is not in a domain this organisation signs in with")
    return {"iss": iss, "sub": str(claims["sub"]), "email": email, "name": claims.get("name") or email}


@router.get("/api/sso/callback")
def sso_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    from .api import _set_session
    from .audit import _client_ip, record
    try:
        if error:
            raise OIDCError(f"the identity provider refused the sign-in ({error})")
        st = _unsign(request.cookies.get("pdp_sso"))
        if not hmac.compare_digest(st["s"], state or ""):
            raise OIDCError("sign-in state mismatch")
        with db.conn() as c:
            org = db.q(c, "SELECT id, sso, disabled FROM orgs WHERE id=%s", (st["o"],), one=True)
        if not org or org["disabled"] or not (org["sso"] or {}).get("enabled"):
            raise OIDCError("single sign-on is not available for this organisation")
        ident = finish(org["sso"], st["o"], code or "", st)
    except OIDCError as e:
        return RedirectResponse("/#/login?error=" + urllib.parse.quote(str(e)[:300]), status_code=302)
    cfg = org["sso"]
    with db.conn() as c:
        u = db.q(c, "SELECT * FROM users WHERE org_id=%s AND ((oidc_issuer=%s AND oidc_sub=%s) OR lower(email)=%s) ORDER BY (oidc_sub IS NOT NULL) DESC LIMIT 1",
                 (st["o"], ident["iss"], ident["sub"], ident["email"]), one=True)
        if u and u["disabled"]:
            record(st["o"], u["id"], u["username"], "sign-in refused: account disabled (single sign-on)", None, 403, _client_ip(request))
            return RedirectResponse("/#/login?error=" + urllib.parse.quote("your account is disabled"), status_code=302)
        if not u:
            role = "admin" if ident["email"] in set(cfg.get("admin_emails") or []) else cfg.get("default_role", "viewer")
            if role not in ("admin", "analyst", "viewer"):
                role = "viewer"
            uname = ident["email"]
            if db.q(c, "SELECT 1 FROM users WHERE username=%s", (uname,), one=True):    # usernames are global: one per org
                uname = f"{ident['email']}#{str(st['o'])[:6]}"
            u = db.q(c, "INSERT INTO users (username, display_name, password_hash, role, auth, oidc_issuer, oidc_sub, email, org_id, last_login) "
                        "VALUES (%s,%s,'!',%s,'oidc',%s,%s,%s,%s,now()) RETURNING *",
                     (uname, ident["name"], role, ident["iss"], ident["sub"], ident["email"], st["o"]), one=True)
        else:
            db.q(c, "UPDATE users SET last_login=now(), oidc_issuer=coalesce(oidc_issuer, %s), oidc_sub=coalesce(oidc_sub, %s) WHERE id=%s",
                 (ident["iss"], ident["sub"], u["id"]))
    record(st["o"], u["id"], u["username"], "sign-in (single sign-on)", None, 200, _client_ip(request))
    r = RedirectResponse("/#/overview", status_code=302)
    r.delete_cookie("pdp_sso", path="/api/sso")
    _set_session(r, u["id"], u["role"])
    return r


# ------------------------------------------------------------------------------------------------ admin settings
class SSOConfig(BaseModel):
    provider: str = Field(pattern="^(google|microsoft|oidc)$")
    tenant: str | None = Field(default=None, max_length=100)
    issuer: str | None = Field(default=None, max_length=300)
    client_id: str = Field(min_length=3, max_length=300)
    client_secret: str | None = Field(default=None, max_length=500)
    domains: list[str]
    default_role: str = "viewer"
    admin_emails: list[str] = Field(default_factory=list)
    enabled: bool = True


@router.put("/api/org/sso")
def set_sso(req: SSOConfig, s=Depends(admin)):
    doms = sorted({d.strip().lower() for d in req.domains if d.strip()})
    if not doms or len(doms) > 20 or not all(DOMAIN_RE.match(d) for d in doms):
        raise HTTPException(400, "enter one to twenty email domains, such as example.com")
    if PUBLIC_DOMAINS & set(doms):
        raise HTTPException(400, f"public mail domains cannot be used for single sign-on: {', '.join(sorted(PUBLIC_DOMAINS & set(doms)))}")
    if req.default_role not in ("viewer", "analyst"):
        raise HTTPException(400, "new single sign-on users get the viewer or analyst role (list admins by email)")
    if req.provider == "microsoft" and not re.match(r"^[A-Za-z0-9.-]{3,100}$", req.tenant or ""):
        raise HTTPException(400, "enter the Microsoft Entra tenant id (or its primary domain)")
    if req.provider == "oidc" and not (req.issuer or "").startswith("https://"):
        raise HTTPException(400, "enter the provider's issuer URL (https://...)")
    with db.conn() as c:
        taken = db.q(c, "SELECT name FROM orgs WHERE id<>%s AND sso IS NOT NULL AND sso->'domains' ?| %s", (s["org"], doms), one=True)
        if taken:
            raise HTTPException(409, "one of these domains is already used by another organisation")
        old = db.q(c, "SELECT sso FROM orgs WHERE id=%s", (s["org"],), one=True)["sso"] or {}
        cfg = {"provider": req.provider, "tenant": req.tenant, "issuer": req.issuer if req.provider == "oidc" else None, "client_id": req.client_id,
               "client_secret": req.client_secret or old.get("client_secret"), "domains": doms, "default_role": req.default_role,
               "admin_emails": sorted({e.strip().lower() for e in req.admin_emails if "@" in e}), "enabled": req.enabled}
        if not cfg["client_secret"]:
            raise HTTPException(400, "enter the client secret")
        db.q(c, "UPDATE orgs SET sso=%s WHERE id=%s", (json.dumps(cfg), s["org"]))
    from .orgs import _sso_out
    return {"ok": True, "sso": _sso_out(cfg)}


@router.delete("/api/org/sso")
def delete_sso(s=Depends(admin)):
    with db.conn() as c:
        db.q(c, "UPDATE orgs SET sso=NULL WHERE id=%s", (s["org"],))
    return {"ok": True}
