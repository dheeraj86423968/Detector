"""Two-factor sign-in for password accounts: TOTP (RFC 6238: SHA-1, 30 s, 6 digits - any authenticator app) and
ten single-use recovery codes. Single sign-on accounts get their second factor from the identity provider.

Sign-in: a correct password for an account with TOTP returns {mfa_required: true} and a 5-minute signed cookie
(pdp_mfa) instead of a session; POST /api/login/mfa with a code (or a recovery code) completes it. A code is accepted
once (users.totp_last). An organisation can require two-factor sign-in (orgs.require_mfa): its users without it get a
session that only allows setting it up (access.session refuses everything else)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from . import auth, db
from .access import session

router = APIRouter()
STEP = 30


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def code_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def verify(secret: str, code: str, last: int | None, now: float | None = None) -> int | None:
    """The time step the code belongs to (one step of clock skew either way), or None. Steps <= last are refused."""
    code = (code or "").strip().replace(" ", "")
    if not (len(code) == 6 and code.isdigit()):
        return None
    t = int((now if now is not None else time.time()) // STEP)
    for c in (t - 1, t, t + 1):
        if (last is None or c > last) and hmac.compare_digest(code_at(secret, c), code):
            return c
    return None


def _hash_code(c: str) -> str:
    return hashlib.sha256(c.strip().lower().replace("-", "").encode()).hexdigest()


def use_recovery(c, user: dict, code: str) -> bool:
    codes = list(user.get("recovery_codes") or [])
    h = _hash_code(code)
    if h in codes:
        codes.remove(h)
        db.q(c, "UPDATE users SET recovery_codes=%s WHERE id=%s", (json.dumps(codes), user["id"]))
        return True
    return False


def pending_cookie(user_id: int) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"u": user_id, "exp": int(time.time()) + 300, "mfa": 1}).encode()).decode()
    return payload + "." + hmac.new(auth._secret(), payload.encode(), hashlib.sha256).hexdigest()


def read_pending(cookie: str | None) -> int | None:
    d = auth.read_session(cookie)
    return int(d["u"]) if d and d.get("mfa") == 1 else None


class Code(BaseModel):
    code: str


class Disable(BaseModel):
    password: str
    code: str


@router.post("/api/login/mfa")
def login_mfa(req: Code, request: Request, response: Response):
    from .api import _set_session
    from .audit import _client_ip, record
    uid = read_pending(request.cookies.get("pdp_mfa"))
    if uid is None:
        raise HTTPException(401, "sign in with your password first (the code step expired after 5 minutes)")
    with db.conn() as c:
        u = db.q(c, "SELECT * FROM users WHERE id=%s AND NOT disabled", (uid,), one=True)
        ok = False
        if u and u["totp_enabled"]:
            step = verify(u["totp_secret"], req.code, u.get("totp_last"))
            if step is not None:
                db.q(c, "UPDATE users SET totp_last=%s, last_login=now() WHERE id=%s", (step, uid)); ok = True
            elif use_recovery(c, u, req.code):
                db.q(c, "UPDATE users SET last_login=now() WHERE id=%s", (uid,)); ok = True
    record(u["org_id"] if u else None, uid, u["username"] if u else None, "sign-in (second factor)" if ok else "sign-in refused: wrong code",
           None, 200 if ok else 401, _client_ip(request))
    if not ok:
        time.sleep(0.5)
        raise HTTPException(401, "wrong or already used code")
    response.delete_cookie("pdp_mfa", path="/api/login")
    _set_session(response, u["id"], u["role"])
    return {"ok": True, "role": u["role"], "username": u["username"]}


@router.post("/api/me/mfa/setup")
def mfa_setup(s=Depends(session)):
    if s.get("a") != "local":
        raise HTTPException(400, "single sign-on accounts use the identity provider's second factor")
    sec = new_secret()
    with db.conn() as c:
        u = db.q(c, "SELECT username, totp_enabled FROM users WHERE id=%s", (s["u"],), one=True)
        if u["totp_enabled"]:
            raise HTTPException(409, "two-factor sign-in is already on; turn it off first to change the authenticator")
        db.q(c, "UPDATE users SET totp_secret=%s WHERE id=%s", (sec, s["u"]))
    uri = f"otpauth://totp/{quote('PDP:' + u['username'])}?secret={sec}&issuer=PDP&algorithm=SHA1&digits=6&period=30"
    return {"ok": True, "secret": sec, "otpauth_uri": uri}


@router.post("/api/me/mfa/enable")
def mfa_enable(req: Code, s=Depends(session)):
    with db.conn() as c:
        u = db.q(c, "SELECT * FROM users WHERE id=%s", (s["u"],), one=True)
        if not u.get("totp_secret"):
            raise HTTPException(400, "start the setup first")
        step = verify(u["totp_secret"], req.code, None)
        if step is None:
            raise HTTPException(400, "that code does not match; check the time on your phone and try the next code")
        codes = ["-".join([secrets.token_hex(2), secrets.token_hex(2)]) for _ in range(10)]
        db.q(c, "UPDATE users SET totp_enabled=true, totp_last=%s, recovery_codes=%s WHERE id=%s",
             (step, json.dumps([_hash_code(x) for x in codes]), s["u"]))
    return {"ok": True, "recovery_codes": codes}


@router.post("/api/me/mfa/disable")
def mfa_disable(req: Disable, s=Depends(session)):
    with db.conn() as c:
        u = db.q(c, "SELECT u.*, o.require_mfa FROM users u JOIN orgs o ON o.id=u.org_id WHERE u.id=%s", (s["u"],), one=True)
        if u["require_mfa"]:
            raise HTTPException(400, "your organisation requires two-factor sign-in")
        if not auth.verify_password(req.password, u["password_hash"]) or verify(u["totp_secret"] or "", req.code, None) is None:
            raise HTTPException(400, "password or code is wrong")
        db.q(c, "UPDATE users SET totp_enabled=false, totp_secret=NULL, recovery_codes=NULL, totp_last=NULL WHERE id=%s", (s["u"],))
    return {"ok": True}
