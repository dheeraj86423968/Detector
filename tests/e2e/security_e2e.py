"""Login security on a stack (staging): two-factor sign-in (setup, second step, replay, recovery code, required by the
organisation), the audit log, retention and per-organisation SSO settings (no real identity provider is reached).
Run in a server container of the stack (imports pdp_server.mfa to compute codes)."""
import http.client
import json
import os
import secrets
import ssl
import sys
import time

from pdp_server import mfa

HOST = os.environ.get("PDP_GATEWAY", "gateway")
fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg, flush=True)
    fails += 0 if ok else 1


raw = ssl.create_default_context(); raw.check_hostname = False; raw.verify_mode = ssl.CERT_NONE


class Console:
    def __init__(self):
        self.cookies = {}

    def call(self, method, path, body=None):
        con = http.client.HTTPSConnection(HOST, 443, context=raw, timeout=60)
        h = {"Content-Type": "application/json"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        con.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = con.getresponse(); data = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, val = v.split(";", 1)[0].split("=", 1)
                if val in ("", '""') or "Max-Age=0" in v:
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = val
        try:
            return r.status, json.loads(data or b"{}")
        except json.JSONDecodeError:
            return r.status, {"raw": data[:200]}


run = secrets.token_hex(3)
email, pw = f"sec-{run}@sec-{run}.example", "security-password-1"
A = Console()
check(A.call("POST", "/api/signup", {"organisation": f"Sec {run}", "name": "Sam", "email": email, "password": pw, "code": "x"})[0] == 200, "organisation signs up")
st, s = A.call("POST", "/api/me/mfa/setup")
check(st == 200 and len(s["secret"]) == 32 and s["otpauth_uri"].startswith("otpauth://totp/"), "two-factor setup: secret and otpauth link")
check(A.call("POST", "/api/me/mfa/enable", {"code": "000000"})[0] == 400, "a wrong code does not enable it")
st, en = A.call("POST", "/api/me/mfa/enable", {"code": mfa.code_at(s["secret"], int(time.time() // 30))})
check(st == 200 and len(en["recovery_codes"]) == 10, "enabled with a current code; 10 recovery codes")
B = Console()
st, r = B.call("POST", "/api/login", {"username": email, "password": pw})
check(st == 200 and r.get("mfa_required") and "pdp_session" not in B.cookies and "pdp_mfa" in B.cookies, "password alone gives no session, only the code step")
check(B.call("GET", "/api/me")[0] == 401, "no access before the code")
check(B.call("POST", "/api/login/mfa", {"code": "123456"})[0] == 401, "a wrong code is refused")
# a code not used yet: the next time step (accepted with one step of clock skew)
code = mfa.code_at(s["secret"], int(time.time() // 30) + 1)
st, _ = B.call("POST", "/api/login/mfa", {"code": code})
check(st == 200 and B.call("GET", "/api/me")[1].get("mfa_enabled"), "the code completes the sign-in")
C = Console()
C.call("POST", "/api/login", {"username": email, "password": pw})
check(C.call("POST", "/api/login/mfa", {"code": code})[0] == 401, "the same code cannot be used twice")
st, _ = C.call("POST", "/api/login/mfa", {"code": en["recovery_codes"][0]})
check(st == 200, "a recovery code signs in")
D = Console(); D.call("POST", "/api/login", {"username": email, "password": pw})
check(D.call("POST", "/api/login/mfa", {"code": en["recovery_codes"][0]})[0] == 401, "a recovery code works once")

# organisation requires two-factor: a new analyst without it can only set it up
check(A.call("PATCH", "/api/org", {"require_mfa": True})[0] == 200, "admin requires two-factor sign-in")
st, inv = A.call("POST", "/api/invites", {"role": "analyst", "email": f"ana-{run}@sec-{run}.example"})
E = Console()
st, _ = E.call("POST", f"/api/invites/{inv['invite']['link'].rsplit('/', 1)[1]}/accept", {"name": "Ana", "password": "analyst-password-1"})
check(st == 200, "an analyst joins by invite")
st, me = E.call("GET", "/api/me")
check(st == 200 and me.get("mfa_setup_required") and E.call("GET", "/api/endpoints")[0] == 403, "without two-factor the analyst can only reach the setup")
st, s2 = E.call("POST", "/api/me/mfa/setup")
E.call("POST", "/api/me/mfa/enable", {"code": mfa.code_at(s2["secret"], int(time.time() // 30))})
check(E.call("GET", "/api/endpoints")[0] == 200, "after setting it up the console opens")
check(E.call("POST", "/api/me/mfa/disable", {"password": "analyst-password-1", "code": mfa.code_at(s2["secret"], int(time.time() // 30))})[0] == 400,
      "it cannot be turned off while the organisation requires it")

# retention
check(A.call("PATCH", "/api/org", {"retention_days": 90})[0] == 400, "0.6: lowering retention needs a reason")
check(A.call("PATCH", "/api/org", {"retention_days": 10, "reason": "e2e"})[0] == 400 and A.call("PATCH", "/api/org", {"retention_days": 90, "reason": "e2e"})[0] == 200
      and A.call("GET", "/api/org")[1]["org"]["retention_days"] == 90, "retention: 30-3650 days, saved")

# per-organisation single sign-on settings
dom = f"sso-{run}.example"
body = {"provider": "microsoft", "tenant": "contoso.onmicrosoft.com", "client_id": "app-123", "client_secret": "s3cret", "domains": [dom],
        "default_role": "viewer", "admin_emails": [f"boss@{dom}"]}
check(A.call("PUT", "/api/org/sso", {**body, "domains": ["gmail.com"]})[0] == 400, "public mail domains cannot be claimed")
st, so = A.call("PUT", "/api/org/sso", body)
check(st == 200 and so["sso"]["has_secret"] and "client_secret" not in so["sso"] and "token" not in so["sso"], "Microsoft SSO saved; the secret is never returned")
proof = so["sso"]["proof"][0]
check(proof["domain"] == dom and proof["verified_at"] is None and proof["record_name"] == f"_pdp-verification.{dom}"
      and proof["record_value"].startswith("pdp-verification=") and len(proof["record_value"]) > 30, "the domain awaits proof: TXT record name and value shown")
st, r = Console().call("GET", f"/api/sso/start?email=boss@{dom}")
check(st == 404 and "proof of domain ownership" in r.get("detail", ""), "an unproven domain does not sign in with SSO yet")
st, v = A.call("POST", "/api/org/sso/verify")
check(st == 200 and dom in v["errors"] and v["sso"]["proof"][0]["verified_at"] is None, f"verify without the TXT record: not proven ({v.get('errors', {}).get(dom, '')[:60]})")
F = Console()
F.call("POST", "/api/signup", {"organisation": f"Other {run}", "name": "O", "email": f"o-{run}@other-{run}.example", "password": "other-password-12", "code": "x"})
check(F.call("PUT", "/api/org/sso", {**body, "client_secret": "x"})[0] == 200, "while unproven, another organisation can list the domain too (no squatting)")
check(A.call("POST", f"/api/operator/orgs/{A.call('GET', '/api/org')[1]['org']['id']}/sso/confirm", {"domain": dom})[0] == 404,
      "client admins cannot use the operator's confirmation")
O = Console()
check(O.call("POST", "/api/login", {"username": "admin", "password": os.environ["PDP_ADMIN_PASSWORD"]})[0] == 200, "operator signs in")
orgs = {o["name"]: o for o in O.call("GET", "/api/operator/orgs")[1]["orgs"]}
check(dom in (orgs[f"Sec {run}"]["sso_domains"] or []) and orgs[f"Sec {run}"]["sso_verified"] == {}, "the operator page lists unproven SSO domains")
check(O.call("POST", f"/api/operator/orgs/{orgs[f'Sec {run}']['id']}/sso/confirm", {"domain": dom})[0] == 200, "the operator confirms the domain")
check(O.call("POST", f"/api/operator/orgs/{orgs[f'Other {run}']['id']}/sso/confirm", {"domain": dom})[0] == 409, "a proven domain cannot be confirmed for a second organisation")
check(F.call("PUT", "/api/org/sso", {**body, "client_secret": "x"})[0] == 409, "another organisation cannot claim a proven domain")
check(A.call("GET", "/api/org")[1]["org"]["sso"]["proof"][0]["verified_at"], "the organisation sees its domain as proven")
check(Console().call("GET", "/api/auth/config")[1].get("org_sso") is True, "the login page offers company sign-in")
st, _ = Console().call("GET", f"/api/sso/start?email=x@unknown-{run}.example")
check(st == 404, "an email domain without SSO is told to use the password")
st, _ = Console().call("GET", f"/api/sso/start?email=boss@{dom}")
check(st in (302, 502), f"a proven domain is sent to its provider ({st}; 502 = no internet access from this stack)")
F.call("DELETE", "/api/org/sso")

# sessions end when the password changes
P1, P2 = Console(), Console()
pemail, ppw = f"pw-{run}@pw-{run}.example", "first-password-123"
check(P1.call("POST", "/api/signup", {"organisation": f"Pw {run}", "name": "P", "email": pemail, "password": ppw, "code": "x"})[0] == 200, "second account signs up")
check(P2.call("POST", "/api/login", {"username": pemail, "password": ppw})[0] == 200 and P2.call("GET", "/api/me")[0] == 200, "signed in on a second browser")
check(P1.call("POST", "/api/me/password", {"old_password": ppw, "new_password": "second-password-123"})[0] == 200, "password changed in the first browser")
check(P1.call("GET", "/api/me")[0] == 200, "the browser that changed it stays signed in")
st, r = P2.call("GET", "/api/me")
check(st == 401 and "session was ended" in r.get("detail", ""), "the other browser is signed out")
check(P2.call("POST", "/api/login", {"username": pemail, "password": "second-password-123"})[0] == 200 and P2.call("GET", "/api/me")[0] == 200,
      "signing in again with the new password works")
P3 = Console(); P3.cookies = dict(P2.cookies)              # a copied cookie (stolen, or a second tab)
check(P1.call("POST", "/api/me/sessions/end")[0] == 200 and P1.call("GET", "/api/me")[0] == 200, "sign out everywhere else: this browser continues")
check(P2.call("GET", "/api/me")[0] == 401 and P3.call("GET", "/api/me")[0] == 401, "every other session, copies of its cookie too, is ended")

# audit log
st, al = A.call("GET", "/api/audit")
acts = [e["action"] for e in al["entries"]]
check(st == 200 and "PUT /api/org/sso" in acts and "PATCH /api/org" in acts and "POST /api/me/mfa/enable" in acts and any(a.startswith("sign-in") for a in acts),
      f"the audit log records the changes and sign-ins ({len(acts)} entries)")
check(any(e["status"] == 400 for e in al["entries"]), "refused attempts are recorded with their status")
check(all(f"o-{run}" not in (e["who"] or "") for e in al["entries"]) and F.call("GET", "/api/audit")[0] == 200
      and all(f"sec-{run}" not in (e["who"] or "") for e in F.call("GET", "/api/audit")[1]["entries"]), "each organisation sees only its own log")
check(E.call("GET", "/api/audit")[0] == 403, "analysts cannot read the audit log")
A.call("DELETE", "/api/org/sso")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
