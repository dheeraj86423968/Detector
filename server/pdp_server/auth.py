"""Console authentication: scrypt password hashes, HMAC-signed session cookies, roles."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

# the session secret lives with the other private material (pki.PRIVATE_DIR: not mounted into the gateway); an
# installation that still has it at the pre-review path /pki/session.secret is migrated by pki.migrate_private()
SESSION_SECRET_PATH = os.environ.get("PDP_SESSION_SECRET") or os.path.join(
    (os.environ.get("PDP_PKI_PRIVATE_DIR") or os.path.join(os.environ.get("PDP_PKI_DIR") or "/pki", "private")), "session.secret")
LEGACY_SESSION_SECRET_PATH = os.path.join(os.environ.get("PDP_PKI_DIR", "/pki"), "session.secret")
SESSION_TTL = 12 * 3600


def _secret() -> bytes:
    if not os.path.exists(SESSION_SECRET_PATH):
        os.makedirs(os.path.dirname(SESSION_SECRET_PATH), mode=0o700, exist_ok=True)
        if os.path.exists(LEGACY_SESSION_SECRET_PATH) and LEGACY_SESSION_SECRET_PATH != SESSION_SECRET_PATH:
            data = open(LEGACY_SESSION_SECRET_PATH, "rb").read()      # keep existing sessions valid across the move
        else:
            data = secrets.token_bytes(32)
        with open(SESSION_SECRET_PATH, "wb") as f:
            f.write(data)
        os.chmod(SESSION_SECRET_PATH, 0o600)
    return open(SESSION_SECRET_PATH, "rb").read()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=2 ** 15, r=8, p=1, dklen=32, maxmem=128 * 1024 * 1024)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


_DUMMY: list[str] = []


def dummy_hash() -> str:
    """A hash of a random password, verified when a sign-in names an unknown user so that the request costs the same
    scrypt work as a wrong password for an existing one (no user enumeration by response time)."""
    if not _DUMMY:
        _DUMMY.append(hash_password(secrets.token_hex(16)))
    return _DUMMY[0]


def make_session(user_id: int, role: str, gen: int = 0) -> str:
    """`gen` is the user's session generation (users.session_gen): bumping it (password change or reset, "sign out
    everywhere") ends every session issued before - access.session() compares it on each request."""
    payload = base64.urlsafe_b64encode(json.dumps({"u": user_id, "r": role, "g": gen, "exp": int(time.time()) + SESSION_TTL,
                                                   "sid": secrets.token_urlsafe(16)}).encode()).decode()   # sid: revocable at logout
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def read_session(cookie: str | None) -> dict | None:
    if not cookie or "." not in cookie:
        return None
    payload, sig = cookie.rsplit(".", 1)
    if not hmac.compare_digest(hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest(), sig):
        return None
    data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    if data.get("exp", 0) < time.time():
        return None
    return data
