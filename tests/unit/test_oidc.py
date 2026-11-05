"""Single sign-on (pdp_server.oidc), the egress proxy allow-list and the KMS-mode bundle signing guard.
Run in the server image: PYTHONPATH=server:engine python tests/unit/test_oidc.py"""
import asyncio
import base64
import json
import os
import sys
import tempfile
import time

os.environ.update({"PDP_OIDC_ISSUER": "https://idp.example.com/realms/pdp", "PDP_OIDC_CLIENT_ID": "pdp-console",
                   "PDP_OIDC_ADMIN_GROUPS": "pdp-admins", "PDP_OIDC_ANALYST_GROUPS": "pdp-analysts,soc",
                   "PDP_SESSION_SECRET": os.path.join(tempfile.mkdtemp(), "session.secret")})

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

from pdp_server import egress, oidc  # noqa: E402

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


def raises(fn, needle=""):
    try:
        fn()
    except oidc.OIDCError as e:
        return needle in str(e)
    return False


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def n2b(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
rn = rsa_key.public_key().public_numbers()
en = ec_key.public_key().public_numbers()
JWKS = {"r1": {"kty": "RSA", "kid": "r1", "n": b64(n2b(rn.n)), "e": b64(n2b(rn.e))},
        "e1": {"kty": "EC", "kid": "e1", "crv": "P-256", "x": b64(en.x.to_bytes(32, "big")), "y": b64(en.y.to_bytes(32, "big"))}}
lookup = lambda kid: JWKS[kid]  # noqa: E731


def jwt(claims, alg="RS256", kid="r1", key=None):
    h = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    p = b64(json.dumps(claims).encode())
    data = f"{h}.{p}".encode()
    if alg == "RS256":
        sig = (key or rsa_key).sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "PS256":
        sig = (key or rsa_key).sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif alg == "ES256":
        r, s = decode_dss_signature((key or ec_key).sign(data, ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = b""
    return f"{h}.{p}.{b64(sig)}"


now = time.time()
good = {"iss": oidc.ISSUER, "aud": "pdp-console", "sub": "u-1", "exp": now + 300, "iat": now, "nonce": "N1"}

# ---------------------------------------------------------------- signatures
for alg, kid in (("RS256", "r1"), ("PS256", "r1"), ("ES256", "e1")):
    check(oidc.verify_jwt(jwt(good, alg, kid), lookup)["sub"] == "u-1", f"{alg} ID token verifies against the JWKS")
other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
check(raises(lambda: oidc.verify_jwt(jwt(good, key=other), lookup), "signature"), "token signed by a foreign key is refused")
t = jwt(good).split(".")
tampered = ".".join([t[0], b64(json.dumps({**good, "sub": "admin"}).encode()), t[2]])
check(raises(lambda: oidc.verify_jwt(tampered, lookup), "signature"), "tampered claims are refused")
check(raises(lambda: oidc.verify_jwt(jwt(good, "none"), lookup), "unsupported"), "alg=none is refused")
check(raises(lambda: oidc.verify_jwt(jwt(good, "HS256"), lookup), "unsupported"), "HS256 (client-secret MAC) is refused")
check(raises(lambda: oidc.verify_jwt(jwt(good, "RS256", "e1"), lookup), "key type"), "RSA token against an EC key is refused")
check(raises(lambda: oidc.verify_jwt("abc.def", lookup), "malformed"), "malformed token is refused")

# ---------------------------------------------------------------- claims
oidc.validate_claims(good, "N1")
check(True, "valid claims accepted")
check(raises(lambda: oidc.validate_claims({**good, "iss": "https://evil"}, "N1"), "issuer"), "issuer mismatch refused")
check(raises(lambda: oidc.validate_claims({**good, "aud": "other-app"}, "N1"), "audience"), "audience mismatch refused")
check(raises(lambda: oidc.validate_claims({**good, "aud": ["other", "pdp-console"], "azp": "other"}, "N1"), "authorized party"),
      "multi-audience token for another client refused")
oidc.validate_claims({**good, "aud": ["other", "pdp-console"], "azp": "pdp-console"}, "N1")
check(True, "multi-audience token with azp = client accepted")
check(raises(lambda: oidc.validate_claims({**good, "exp": now - 600}, "N1"), "expired"), "expired token refused")
check(raises(lambda: oidc.validate_claims({**good, "iat": now + 600}, "N1"), "future"), "token from the future refused")
check(raises(lambda: oidc.validate_claims(good, "N2"), "nonce"), "nonce mismatch (replay) refused")
check(raises(lambda: oidc.validate_claims({k: v for k, v in good.items() if k != "nonce"}, "N1"), "nonce"), "missing nonce refused")

# ---------------------------------------------------------------- login state cookie
st = oidc._sign({"s": "S", "n": "N", "v": "V", "r": "https://x/cb", "exp": int(now) + 60})
check(oidc._unsign(st)["v"] == "V", "state cookie round-trips")
raw, sig = st.rsplit(".", 1)
forged = b64(json.dumps({"s": "S", "n": "N", "v": "attacker", "r": "https://x/cb", "exp": int(now) + 60}).encode()) + "." + sig
check(raises(lambda: oidc._unsign(forged), "tampered"), "forged state cookie refused")
check(raises(lambda: oidc._unsign(oidc._sign({"s": "S", "exp": int(now) - 1})), "too long"), "expired state cookie refused")
check(raises(lambda: oidc._unsign(None), "missing"), "missing state cookie refused")
check(raises(lambda: oidc.finish("code", "other-state", st), "mismatch"), "state parameter must match the cookie (login CSRF)")

# ---------------------------------------------------------------- roles and password policy
check(oidc.role_for({"pdp-admins", "soc"}) == "admin", "admin group wins")
check(oidc.role_for({"soc"}) == "analyst", "analyst group")
check(oidc.role_for({"marketing"}) is None, "no mapped group -> refused (default role none)")
oidc.DEFAULT_ROLE = "analyst"
check(oidc.role_for(set()) == "analyst", "PDP_OIDC_DEFAULT_ROLE=analyst admits any authenticated user as analyst")
oidc.DEFAULT_ROLE = "none"
oidc.PASSWORD_LOGIN = "admin-only"
check(oidc.password_login_allowed("admin") and not oidc.password_login_allowed("analyst"), "admin-only: break-glass admins only")
oidc.PASSWORD_LOGIN = "disabled"
check(not oidc.password_login_allowed("admin"), "disabled: no password sign-in")
oidc.PASSWORD_LOGIN = "enabled"

# ---------------------------------------------------------------- egress allow-list and proxy
os.environ["PDP_EGRESS_ALLOW"] = "login.microsoftonline.com, idp.corp:8443"
check(egress.allow_list() == {("login.microsoftonline.com", 443), ("idp.corp", 8443)}, "egress allow-list parsing")
del os.environ["PDP_EGRESS_ALLOW"]
check(egress.allow_list() == {("idp.example.com", 443)}, "egress allow-list defaults to the issuer host")


async def proxy_roundtrip():
    async def upstream(r, w):
        w.write(b"hello " + await r.read(5))
        await w.drain()
        w.close()
    up = await asyncio.start_server(upstream, "127.0.0.1", 0)
    up_port = up.sockets[0].getsockname()[1]
    allowed = {("127.0.0.1", up_port)}
    px = await asyncio.start_server(lambda r, w: egress.handle(r, w, allowed), "127.0.0.1", 0)
    px_port = px.sockets[0].getsockname()[1]
    out = {}
    for name, target in (("allowed", f"127.0.0.1:{up_port}"), ("refused", "127.0.0.1:1")):
        r, w = await asyncio.open_connection("127.0.0.1", px_port)
        w.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        await w.drain()
        status = (await r.readline()).decode()
        if "200" in status:
            await r.readline()          # blank line ending the proxy response
            w.write(b"world")
            await w.drain()
            status += (await r.read(100)).decode()
        out[name] = status
        w.close()
    r, w = await asyncio.open_connection("127.0.0.1", px_port)
    w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
    await w.drain()
    out["get"] = (await r.readline()).decode()
    w.close()
    px.close(); up.close()
    return out


res = asyncio.run(proxy_roundtrip())
check("200" in res["allowed"] and "hello world" in res["allowed"], "egress relays CONNECT to an allowed host")
check("403" in res["refused"], "egress refuses CONNECT to other hosts")
check("405" in res["get"], "egress refuses plain HTTP proxying")

# per-organisation providers: built-ins and the resolver are static; org issuers only on public addresses
st_allow = egress.static_allow()
check({("accounts.google.com", 443), ("login.microsoftonline.com", 443), ("cloudflare-dns.com", 443)} <= st_allow,
      "Google, Microsoft and the DNS-over-HTTPS resolver are always allowed")
real_pa, real_dh = egress.public_addrs, egress._discovery_hosts
egress.public_addrs = lambda h, p: {"idp.okta.example": ["93.184.215.14"], "jwks.okta.example": ["93.184.215.15"]}.get(h, [])
egress._discovery_hosts = lambda iss: {("idp.okta.example", 443), ("jwks.okta.example", 443)} if "okta" in iss else set()
pol = egress.Policy(set(st_allow), issuers=lambda: ["https://idp.okta.example/oauth2/default", "https://evil.internal/realm"])
check(pol.decide("accounts.google.com", 443) == [], "static host: connect by name")
check(pol.decide("idp.okta.example", 443) == ["93.184.215.14"] and pol.decide("jwks.okta.example", 443) == ["93.184.215.15"],
      "an organisation's own provider (issuer and key hosts) is allowed, pinned to the checked address")
check(pol.decide("evil.internal", 443) is None and pol.decide("example.org", 443) is None, "internal or unlisted hosts refused")
egress.public_addrs = lambda h, p: []           # the org's issuer now resolves to an internal address (DNS rebinding)
check(pol.decide("idp.okta.example", 443) is None, "a listed org provider resolving to an internal address is refused")
egress.public_addrs, egress._discovery_hosts = real_pa, real_dh
check(egress.public_addrs("127.0.0.1", 443) == [] and egress.public_addrs("10.1.2.3", 443) == [], "loopback and private addresses are not public")
check(egress._discovery_hosts("https://127.0.0.1/realm") == set() and egress._discovery_hosts("http://idp.example.com") == set(),
      "issuers on internal addresses or without https are never allowed")
pol2 = egress.Policy(set(), issuers=lambda: (_ for _ in ()).throw(RuntimeError("db down")))
pol2.dynamic = {("kept.example", 443)}
pol2.refresh()
check(pol2.dynamic == {("kept.example", 443)}, "database unavailable: the last list is kept")

# ---------------------------------------------------------------- KMS mode: private key never readable
os.environ["PDP_KMS"] = "transit"
import importlib  # noqa: E402
from pdp_server import kms, pki  # noqa: E402
importlib.reload(kms); importlib.reload(pki)
try:
    pki.signing_private_pem()
    check(False, "KMS mode hides the bundle-signing private key")
except RuntimeError:
    check(True, "KMS mode hides the bundle-signing private key")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
