"""Single sign-on for the console: OpenID Connect authorization-code flow with PKCE (Okta, Entra ID, Google
Workspace, Keycloak, Auth0, ADFS, Dex, ...).

Flow: the console links to /api/oidc/login -> the IdP -> /api/oidc/callback. The callback exchanges the code
(client secret + PKCE verifier), validates the ID token (signature against the IdP's JWKS, issuer, audience,
expiry, nonce), maps the IdP groups to a PDP role and sets the same session cookie as a password login. The IdP is
the source of truth for the role: it is re-evaluated at every sign-in, and a user in none of the mapped groups is
refused.

Configuration (environment of the api service):
  PDP_OIDC_ISSUER            issuer URL (discovery at <issuer>/.well-known/openid-configuration); unset = SSO off
  PDP_OIDC_CLIENT_ID         client id registered at the IdP
  PDP_OIDC_CLIENT_SECRET     client secret (or PDP_OIDC_CLIENT_SECRET_FILE)
  PDP_OIDC_REDIRECT_URL      https://<console host>/api/oidc/callback (register it at the IdP)
  PDP_OIDC_SCOPES            default "openid profile email"; add "groups" if the IdP needs a scope for groups
  PDP_OIDC_GROUPS_CLAIM      default "groups" (Entra ID: "groups" or "roles"; Keycloak: a groups mapper)
  PDP_OIDC_ADMIN_GROUPS      comma-separated IdP groups that get the admin role
  PDP_OIDC_ANALYST_GROUPS    comma-separated IdP groups that get the analyst role
  PDP_OIDC_VIEWER_GROUPS     comma-separated IdP groups that get the read-only viewer role
  PDP_OIDC_DEFAULT_ROLE      role for an authenticated user in no mapped group: "none" (refuse, default), "viewer" or "analyst"
  PDP_OIDC_USERNAME_CLAIM    default "preferred_username" (falls back to email, then sub)
  PDP_OIDC_LABEL             button text, default "Sign in with SSO"
  PDP_PASSWORD_LOGIN         "enabled" (default), "admin-only" (break-glass local admins only) or "disabled"
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import auth

ISSUER = os.environ.get("PDP_OIDC_ISSUER", "").rstrip("/")
CLIENT_ID = os.environ.get("PDP_OIDC_CLIENT_ID", "")
REDIRECT_URL = os.environ.get("PDP_OIDC_REDIRECT_URL", "")
SCOPES = os.environ.get("PDP_OIDC_SCOPES", "openid profile email")
GROUPS_CLAIM = os.environ.get("PDP_OIDC_GROUPS_CLAIM", "groups")
USERNAME_CLAIM = os.environ.get("PDP_OIDC_USERNAME_CLAIM", "preferred_username")
LABEL = os.environ.get("PDP_OIDC_LABEL", "Sign in with SSO")
DEFAULT_ROLE = os.environ.get("PDP_OIDC_DEFAULT_ROLE", "none")
PASSWORD_LOGIN = os.environ.get("PDP_PASSWORD_LOGIN", "enabled")
STATE_TTL = 600
CLOCK_SKEW = 120


def _groups(var: str) -> set[str]:
    return {g.strip() for g in os.environ.get(var, "").split(",") if g.strip()}


ADMIN_GROUPS, ANALYST_GROUPS = _groups("PDP_OIDC_ADMIN_GROUPS"), _groups("PDP_OIDC_ANALYST_GROUPS")
VIEWER_GROUPS = _groups("PDP_OIDC_VIEWER_GROUPS")


class OIDCError(Exception):
    pass


def enabled() -> bool:
    return bool(ISSUER and CLIENT_ID)


def client_secret() -> str:
    f = os.environ.get("PDP_OIDC_CLIENT_SECRET_FILE")
    if f:
        return open(f).read().strip()
    return os.environ.get("PDP_OIDC_CLIENT_SECRET", "")


def password_login_allowed(role: str | None, local: bool = True) -> bool:
    if PASSWORD_LOGIN == "disabled":
        return False
    if PASSWORD_LOGIN == "admin-only":
        return role == "admin" and local
    return True


# ---------------------------------------------------------------------------------------------- HTTP + caches
def _http(url: str, data: dict | None = None, headers: dict | None = None) -> dict:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Accept": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read()[:300].decode(errors="replace")
        raise OIDCError(f"{url}: HTTP {e.code} {detail}") from None
    except urllib.error.URLError as e:
        raise OIDCError(f"identity provider unreachable ({url}): {e.reason}") from None


_lock = threading.Lock()
_disc: tuple[float, dict] | None = None
_jwks: tuple[float, dict] | None = None


def discovery() -> dict:
    global _disc
    with _lock:
        if _disc and time.time() - _disc[0] < 3600:
            return _disc[1]
    d = _http(f"{ISSUER}/.well-known/openid-configuration")
    if d.get("issuer", "").rstrip("/") != ISSUER:
        raise OIDCError(f"discovery issuer {d.get('issuer')!r} does not match PDP_OIDC_ISSUER {ISSUER!r}")
    with _lock:
        _disc = (time.time(), d)
    return d


def _jwk(kid: str | None) -> dict:
    global _jwks
    for attempt in (0, 1):
        with _lock:
            cached = _jwks if _jwks and time.time() - _jwks[0] < 3600 and attempt == 0 else None
        if cached is None:
            keys = _http(discovery()["jwks_uri"])
            with _lock:
                _jwks = (time.time(), keys)
            cached = _jwks
        for k in cached[1].get("keys", []):
            if kid is None or k.get("kid") == kid:
                return k
    raise OIDCError(f"no signing key {kid!r} in the identity provider's JWKS")


# ---------------------------------------------------------------------------------------------- JWT
def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _int(s: str) -> int:
    return int.from_bytes(_b64d(s), "big")


_HASH = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
_CURVE = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}


def verify_jwt(token: str, jwk_lookup=None) -> dict:
    """Verify a compact JWS (RS*, PS*, ES*) and return its claims. Claims are NOT validated here."""
    try:
        h64, p64, s64 = token.split(".")
        header, claims, sig = json.loads(_b64d(h64)), json.loads(_b64d(p64)), _b64d(s64)
    except Exception:  # noqa
        raise OIDCError("malformed ID token") from None
    alg = header.get("alg", "")
    if alg[:2] not in ("RS", "PS", "ES") or alg[2:] not in _HASH:
        raise OIDCError(f"unsupported ID token algorithm {alg!r}")      # never "none" or HS* (client-secret MACs)
    k = (jwk_lookup or _jwk)(header.get("kid"))
    data, h = f"{h64}.{p64}".encode(), _HASH[alg[2:]]()
    try:
        if alg[:2] in ("RS", "PS"):
            if k.get("kty") != "RSA":
                raise OIDCError("JWKS key type does not match the token algorithm")
            pub = rsa.RSAPublicNumbers(_int(k["e"]), _int(k["n"])).public_key()
            pad = padding.PKCS1v15() if alg[:2] == "RS" else padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size)
            pub.verify(sig, data, pad, h)
        else:
            if k.get("kty") != "EC":
                raise OIDCError("JWKS key type does not match the token algorithm")
            pub = ec.EllipticCurvePublicNumbers(_int(k["x"]), _int(k["y"]), _CURVE[k["crv"]]()).public_key()
            n = len(sig) // 2
            pub.verify(encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big")), data, ec.ECDSA(h))
    except InvalidSignature:
        raise OIDCError("ID token signature is invalid") from None
    return claims


def validate_claims(claims: dict, nonce: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    if claims.get("iss", "").rstrip("/") != ISSUER:
        raise OIDCError("ID token issuer mismatch")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if CLIENT_ID not in auds:
        raise OIDCError("ID token audience mismatch")
    if len(auds) > 1 and claims.get("azp") not in (None, CLIENT_ID):
        raise OIDCError("ID token authorized party mismatch")
    if float(claims.get("exp", 0)) < now - CLOCK_SKEW:
        raise OIDCError("ID token expired")
    if float(claims.get("iat", now)) > now + CLOCK_SKEW:
        raise OIDCError("ID token issued in the future")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise OIDCError("ID token nonce mismatch (replayed or foreign login)")


# ---------------------------------------------------------------------------------------------- login state
def _sign(payload: dict) -> str:
    raw = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    return raw + "." + hmac.new(auth._secret(), b"oidc:" + raw.encode(), hashlib.sha256).hexdigest()


def _unsign(value: str | None) -> dict:
    if not value or "." not in value:
        raise OIDCError("sign-in state missing - start the sign-in again")
    raw, sig = value.rsplit(".", 1)
    if not hmac.compare_digest(hmac.new(auth._secret(), b"oidc:" + raw.encode(), hashlib.sha256).hexdigest(), sig):
        raise OIDCError("sign-in state tampered")
    d = json.loads(_b64d(raw))
    if d.get("exp", 0) < time.time():
        raise OIDCError("sign-in took too long - start it again")
    return d


def start(redirect_url: str) -> tuple[str, str]:
    """-> (IdP authorization URL, signed state cookie value)."""
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
    q = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": redirect_url, "scope": SCOPES,
         "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    url = discovery()["authorization_endpoint"] + "?" + urllib.parse.urlencode(q)
    return url, _sign({"s": state, "n": nonce, "v": verifier, "r": redirect_url, "exp": int(time.time()) + STATE_TTL})


def finish(code: str, state: str, cookie: str | None) -> dict:
    """Exchange the code and validate the ID token -> identity {sub, iss, username, email, groups, role}."""
    st = _unsign(cookie)
    if not hmac.compare_digest(st["s"], state or ""):
        raise OIDCError("sign-in state mismatch")
    d = discovery()
    basic = base64.b64encode(f"{urllib.parse.quote(CLIENT_ID, safe='')}:{urllib.parse.quote(client_secret(), safe='')}".encode()).decode()
    tok = _http(d["token_endpoint"], {"grant_type": "authorization_code", "code": code, "redirect_uri": st["r"],
                                      "code_verifier": st["v"]}, {"Authorization": f"Basic {basic}"})
    if "id_token" not in tok:
        raise OIDCError("the identity provider returned no ID token (is the 'openid' scope allowed?)")
    claims = verify_jwt(tok["id_token"])
    validate_claims(claims, st["n"])
    groups = claims.get(GROUPS_CLAIM)
    if groups is None and tok.get("access_token") and d.get("userinfo_endpoint"):
        info = _http(d["userinfo_endpoint"], headers={"Authorization": f"Bearer {tok['access_token']}"})
        if info.get("sub") != claims.get("sub"):
            raise OIDCError("userinfo subject does not match the ID token")
        groups = info.get(GROUPS_CLAIM)
        claims = {**info, **claims}
    groups = [groups] if isinstance(groups, str) else list(groups or [])
    groups = {str(g).rsplit("/", 1)[-1] if str(g).startswith("/") else str(g) for g in groups}   # Keycloak "/group"
    role = role_for(groups)
    username = str(claims.get(USERNAME_CLAIM) or claims.get("email") or claims["sub"])
    return {"sub": str(claims["sub"]), "iss": ISSUER, "username": username, "email": claims.get("email"),
            "groups": sorted(groups), "role": role}


def role_for(groups: set[str]) -> str | None:
    if groups & ADMIN_GROUPS:
        return "admin"
    if groups & ANALYST_GROUPS:
        return "analyst"
    if groups & VIEWER_GROUPS:
        return "viewer"
    return DEFAULT_ROLE if DEFAULT_ROLE in ("analyst", "viewer") else None


def end_session_url(post_logout: str) -> str | None:
    try:
        ep = discovery().get("end_session_endpoint")
    except OIDCError:
        return None
    if not ep:
        return None
    return ep + "?" + urllib.parse.urlencode({"client_id": CLIENT_ID, "post_logout_redirect_uri": post_logout})
