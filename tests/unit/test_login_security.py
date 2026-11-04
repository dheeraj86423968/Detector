"""Login security: TOTP (RFC 6238 test vector, clock skew, replay) and per-organisation single sign-on (issuer per
provider, ID-token validation, email/domain rules, the code exchange against a mock provider)."""
import base64
import json
import os
import sys
import tempfile
import time

os.environ["PDP_SESSION_SECRET"] = os.path.join(tempfile.mkdtemp(), "session.secret")
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

from pdp_server import mfa, sso  # noqa: E402
from pdp_server.oidc import OIDCError  # noqa: E402

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


# ---- TOTP
sec = base64.b32encode(b"12345678901234567890").decode()          # RFC 6238 appendix B, SHA-1
check(mfa.code_at(sec, 59 // 30) == "287082" and mfa.code_at(sec, 1111111109 // 30) == "081804", "RFC 6238 test vectors (6 digits)")
now = 1_800_000_000
c = mfa.code_at(sec, now // 30)
check(mfa.verify(sec, c, None, now) == now // 30, "current code accepted")
check(mfa.verify(sec, mfa.code_at(sec, now // 30 - 1), None, now) is not None, "previous step accepted (clock skew)")
check(mfa.verify(sec, mfa.code_at(sec, now // 30 - 3), None, now) is None, "an old code is refused")
check(mfa.verify(sec, c, now // 30, now) is None, "a used code is refused (replay)")
check(mfa.verify(sec, "12a456", None, now) is None and mfa.verify(sec, "", None, now) is None, "malformed codes refused")
s2 = mfa.new_secret()
check(len(s2) == 32 and mfa.verify(s2, mfa.code_at(s2, now // 30), None, now) is not None, "new secrets work")
p = mfa.pending_cookie(42)
check(mfa.read_pending(p) == 42 and mfa.read_pending(p[:-2] + "00") is None, "second-step cookie signed")

# ---- per-organisation SSO
check(sso.issuer_of({"provider": "google"}) == "https://accounts.google.com", "Google issuer")
check(sso.issuer_of({"provider": "microsoft", "tenant": "contoso.onmicrosoft.com"}) == "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0", "Microsoft issuer per tenant")
check(sso.email_of({"email": "A@Corp.com", "email_verified": True}, "google") == "a@corp.com", "verified email")
check(sso.email_of({"email": "a@corp.com", "email_verified": False}, "google") is None, "unverified email refused")
check(sso.email_of({"preferred_username": "b@corp.com"}, "microsoft") == "b@corp.com", "Entra: UPN as email")

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = key.public_key().public_numbers()
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
n2b = lambda n: n.to_bytes((n.bit_length() + 7) // 8, "big")
JWK = {"kty": "RSA", "kid": "k1", "n": b64(n2b(pub.n)), "e": b64(n2b(pub.e))}
ISS = "https://idp.corp.example"


def jwt(claims):
    h = b64(json.dumps({"alg": "RS256", "kid": "k1"}).encode()); p_ = b64(json.dumps(claims).encode())
    sig = key.sign(f"{h}.{p_}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p_}.{b64(sig)}"


cfg = {"provider": "oidc", "issuer": ISS, "client_id": "pdp", "client_secret": "s", "domains": ["corp.example"], "default_role": "viewer"}
calls = []


def fake_http(url, data=None, headers=None):
    calls.append((url, data, headers))
    if url.endswith("/.well-known/openid-configuration"):
        return {"issuer": ISS, "authorization_endpoint": ISS + "/auth", "token_endpoint": ISS + "/token", "jwks_uri": ISS + "/jwks"}
    if url.endswith("/jwks"):
        return {"keys": [JWK]}
    if url.endswith("/token"):
        return {"id_token": TOKEN[0]}
    raise AssertionError(url)


sso._http = fake_http
t = time.time()
base = {"iss": ISS, "aud": "pdp", "sub": "u1", "email": "alice@corp.example", "email_verified": True, "exp": t + 300, "iat": t, "nonce": "N"}
st = {"r": "https://pdp/api/sso/callback", "v": "verifier", "n": "N"}
TOKEN = [jwt(base)]
ident = sso.finish(cfg, "org", "code", st)
tok_call = [c for c in calls if c[0].endswith("/token")][0]
check(ident["email"] == "alice@corp.example" and ident["iss"] == ISS and ident["sub"] == "u1", "code exchange + verified ID token -> identity")
check(tok_call[1]["code_verifier"] == "verifier" and tok_call[2]["Authorization"].startswith("Basic "), "PKCE verifier and client credentials sent")


def refused(claims, needle):
    TOKEN[0] = jwt({**base, **claims})
    try:
        sso.finish(cfg, "org", "code", st)
    except OIDCError as e:
        return needle in str(e)
    return False


check(refused({"email": "mallory@other.example"}, "domain"), "email outside the organisation's domains refused")
check(refused({"nonce": "X"}, "nonce"), "wrong nonce refused")
check(refused({"aud": "someone-else"}, "audience"), "wrong audience refused")
check(refused({"iss": "https://evil.example"}, "issuer"), "wrong issuer refused")
check(refused({"exp": t - 3600}, "expired"), "expired token refused")
TOKEN[0] = jwt(base)[:-6] + "AAAAAA"
try:
    sso.finish(cfg, "org", "code", st); forged = False
except OIDCError:
    forged = True
check(forged, "forged signature refused")
check(bool(sso.DOMAIN_RE.match("corp.example")) and not sso.DOMAIN_RE.match("corp") and "gmail.com" in sso.PUBLIC_DOMAINS, "domain rules")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
