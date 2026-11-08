"""Security review of 2026-11-08 (SECURITY_REVIEW_2026-11-08.md): the fixes, each against the code path it changed.
No database: pdp_server.db is replaced by a small fake that answers the statements these routes run.
Run: PYTHONPATH=server:engine:agent python tests/unit/test_security_hardening.py
"""
import contextlib
import os
import socket
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["PDP_SESSION_SECRET"] = os.path.join(tempfile.mkdtemp(), "session.secret")
from fastapi import HTTPException, Response        # noqa: E402
from pydantic import ValidationError               # noqa: E402

from pdp_server import access, api, auth, db, distrib, hunt, mfa     # noqa: E402
from pdp_server import exporter as X               # noqa: E402

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


def raises(fn, *a, status=None, **kw):
    try:
        fn(*a, **kw)
    except HTTPException as e:
        return e.status_code if status is None else e.status_code == status
    except ValidationError:
        return "validation"
    return None


class FakeDB:
    """The statements the routes under test run, against dicts; every statement is kept for assertions."""
    def __init__(self, users=None, endpoints=None):
        self.users, self.endpoints, self.log = users or {}, endpoints or {}, []

    def q(self, c, sql, args=(), one=False):
        self.log.append((sql, args))
        r = None
        if sql.startswith("SELECT * FROM users WHERE id=%s AND NOT disabled"):
            u = self.users.get(args[0]); r = [u] if u and not u["disabled"] else []
        elif sql.startswith("SELECT u.*, o.disabled AS org_disabled FROM users"):
            r = [u for u in self.users.values() if u["username"] == args[0]]
        elif sql.startswith("SELECT session_gen"):
            r = [{"session_gen": 0}]
        elif sql.startswith("SELECT e.*, o.disabled AS org_disabled FROM endpoints"):
            e = self.endpoints.get(args[0]); r = [dict(e)] if e else []
        elif sql.startswith("UPDATE users SET failed_logins = failed_logins + 1"):
            u = self.users[args[0]]; u["failed_logins"] += 1
            if u["failed_logins"] >= 5:
                u["locked_until"] = datetime.now(timezone.utc) + timedelta(seconds=30)
        elif sql.startswith("UPDATE users SET totp_last") or sql.startswith("UPDATE users SET last_login=now(), failed_logins=0"):
            u = self.users[args[-1]]; u["failed_logins"] = 0; u["locked_until"] = None
        if r is None:
            return None
        return (r[0] if r else None) if one else r


@contextlib.contextmanager
def fake_conn(dsn=None):
    yield None


class Req:
    def __init__(self, cookies=None):
        self.cookies, self.headers, self.client = cookies or {}, {"x-real-ip": "203.0.113.9"}, None


db.conn = fake_conn      # every module does `from . import db` and calls db.conn() / db.q(): patching the module is enough

# ---- 1. second factor: a wrong code counts towards the account lock-out like a wrong password (was: unlimited guesses)
sec = mfa.new_secret()
USER = {"id": 7, "username": "ann", "org_id": "o1", "role": "admin", "disabled": False, "totp_enabled": True, "totp_secret": sec,
        "totp_last": None, "recovery_codes": [], "failed_logins": 0, "locked_until": None, "auth": "local"}
fake = FakeDB(users={7: USER}); db.q = fake.q
cookie = {"pdp_mfa": mfa.pending_cookie(7)}
st = raises(mfa.login_mfa, mfa.Code(code="000000"), Req(cookie), Response())
check(st == 401 and USER["failed_logins"] == 1, "wrong code: 401 and one failed sign-in recorded on the account")
for _ in range(4):
    raises(mfa.login_mfa, mfa.Code(code="000000"), Req(cookie), Response())
check(USER["failed_logins"] == 5 and USER["locked_until"] is not None, "five wrong codes lock the account")
n = len(fake.log)
good = mfa.code_at(sec, int(datetime.now(timezone.utc).timestamp()) // 30)
st = raises(mfa.login_mfa, mfa.Code(code=good), Req(cookie), Response())
check(st == 429 and not any(s.startswith("UPDATE users SET totp_last") for s, _ in fake.log[n:]) and USER["failed_logins"] == 5,
      "while locked even the right code is refused (429), nothing is counted or signed in")
USER["locked_until"] = None
resp = Response()
out = mfa.login_mfa(mfa.Code(code=good), Req(cookie), resp)
check(out["ok"] and USER["failed_logins"] == 0 and any(h.startswith("pdp_session=") for h in resp.headers.getlist("set-cookie")),
      "the right code signs in and resets the counter")
check(access.sign_in_locked({"locked_until": datetime.now(timezone.utc) + timedelta(seconds=5)}) and not access.sign_in_locked({"locked_until": None})
      and not access.sign_in_locked(None), "sign_in_locked")
check("^/api/login(/mfa)?$" in open(os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "nginx", "console.conf")).read(),
      "the gateway's sign-in rate limit covers the second-factor step too")

# ---- 2. password step: an unknown user costs a password verification too (no enumeration by timing); bounded input
calls = []
real_verify = auth.verify_password
auth.verify_password = lambda pw, h: calls.append(h) or real_verify(pw, h)
import time as _t
_sleep, _t.sleep = _t.sleep, lambda s: None      # the 0.5 s penalty is not what is under test
st = raises(api.login, api.Login(username="nobody", password="x" * 12), Response(), Req())
auth.verify_password, _t.sleep = real_verify, _sleep
check(st == 401 and calls == [auth.dummy_hash()] and not real_verify("x" * 12, auth.dummy_hash()), "unknown user: the dummy hash is verified, 401")
check(raises(api.Login, username="a", password="p" * 1025) == "validation" and api.Login(username="a", password="p" * 1024), "password length bounded")

# ---- 3. enrolment request bounded (the one unauthenticated agent route)
ok_req = dict(token="t" * 32, hostname="h", csr_pem="-----BEGIN CERTIFICATE REQUEST-----\nx\n-----END CERTIFICATE REQUEST-----")
check(api.EnrollReq(**ok_req) and raises(api.EnrollReq, **dict(ok_req, csr_pem="x" * 20000)) == "validation"
      and raises(api.EnrollReq, **dict(ok_req, hostname="h" * 300)) == "validation" and raises(api.EnrollReq, **dict(ok_req, token="short")) == "validation",
      "enrol: csr, hostname and token lengths bounded")

# ---- 4. agents of a suspended organisation are refused (was: only the console was locked out)
fake = FakeDB(endpoints={"e1": {"id": "e1", "phase": "protected", "org_id": "o1", "org_disabled": True, "config": {}},
                         "e2": {"id": "e2", "phase": "protected", "org_id": "o2", "org_disabled": False, "config": {}}})
db.q = fake.q
dn = lambda cn: f"O=PDP endpoints,CN={cn}"
check(raises(api.agent_endpoint, "e1", dn("e1"), "SUCCESS") == 403, "suspended organisation: its agent gets 403")
ep = api.agent_endpoint("e2", dn("e2"), "SUCCESS")
check(ep["id"] == "e2" and "org_disabled" not in ep and any(s.startswith("UPDATE endpoints SET last_seen") for s, _ in fake.log), "live organisation: served as before")
check(raises(api.agent_endpoint, "e2", dn("e1"), "SUCCESS") == 403 and raises(api.agent_endpoint, "e2", dn("e2"), "NONE") == 403, "certificate CN / verify still enforced")

# ---- 5. campaign specification: families name files on the worker, days name directories
check(api.validate_campaign_spec({"families": ["ransomware"], "evasion_levels": ["none", "high"], "days": ["validation", "2026-11-01"],
                                  "runs": "40", "horizon_windows": 8})["runs"] == 40, "a valid spec passes (ints coerced)")
check(raises(api.validate_campaign_spec, {"families": ["transplant:../../../etc/passwd"]}) == 400, "a family that is a path is refused")
check(raises(api.validate_campaign_spec, {"families": ["transplant:not-on-this-server"]}) == 400, "an unknown transplant is refused")
check(raises(api.validate_campaign_spec, {"evasion_levels": ["../x"]}) == 400 and raises(api.validate_campaign_spec, {"days": ["../other"]}) == 400,
      "evasion levels and days are checked")
check(raises(api.validate_campaign_spec, {"runs": 0}) == 400 and raises(api.validate_campaign_spec, {"runs": True}) == 400
      and raises(api.validate_campaign_spec, {"horizon_windows": 10**6}) == 400 and raises(api.validate_campaign_spec, {"bogus": 1}) == 400, "numbers bounded, unknown keys refused")

# ---- 6. hunt answers from agents: objects only, bounded
rows = hunt.clean_rows([{"kind": "exec", "program": "x" * 5000, "n": 3, "flag": True, "none": None}, "junk", 42, [1], {"a": {"nested": 1}}] + [{"i": i} for i in range(1000)])
check(len(rows) == hunt.MAX_ANSWER_ROWS and rows[0]["kind"] == "exec" and len(rows[0]["program"]) == hunt.MAX_ANSWER_TEXT and rows[0]["n"] == 3
      and rows[0]["flag"] is True and rows[0]["none"] is None and rows[1] == {"a": "{'nested': 1}"}, "hunt rows: non-objects dropped, text and count bounded")
check(all(isinstance(r, dict) for r in rows) and hunt.clean_rows(["junk", 1]) == [], "every stored row is an object (the console calls x.get on it)")

# ---- 7. syslog: the connection goes to the address that was checked, not to a second DNS answer
seen = []
_cc = socket.create_connection
socket.create_connection = lambda addr, timeout=None: seen.append(addr) or (_ for _ in ()).throw(OSError("no network in tests"))
s = X.SyslogSink("tcp://siem.example.com:6514"); s.addr = "198.51.100.7"
try:
    s._connect()
except OSError:
    pass
socket.create_connection = _cc
check(seen == [("198.51.100.7", 6514)] and s.dest() == ("198.51.100.7", 6514), "tcp syslog connects to the pre-resolved address")
u = X.SyslogSink("udp://siem.example.com"); u.addr = "2001:db8::7"; u._connect()
check(u.sock.family == socket.AF_INET6 and u.dest() == ("2001:db8::7", 514), "udp syslog sends to the pre-resolved address (IPv6 aware)")
u.sock.close()
check(X.SyslogSink("tls://siem.example.com").dest() == ("siem.example.com", 6514), "without a pre-resolved address the host name is used (exporter as before)")

# ---- 8. the request host rendered into the installer script is a host name
os.environ.pop("PDP_PUBLIC_HOSTNAME", None)
class H:
    def __init__(self, host): self.headers = {"host": host}
check(distrib.public_host(H("pdp.example.com:8443")) == "pdp.example.com" and distrib.public_host(H("10.0.0.5")) == "10.0.0.5", "host names and addresses accepted")
check(distrib.public_host(H('x";id;"')) == "localhost" and distrib.public_host(H("a b")) == "localhost", "a host header with shell characters is not rendered")

# ---- 9. the enrolment token is not passed on the command line
from pdp_agent.__main__ import enroll_token
os.environ["PDP_ENROLL_TOKEN"] = "tok-from-env"
check(enroll_token("env") == "tok-from-env" and enroll_token("literal") == "literal", "enroll env reads PDP_ENROLL_TOKEN")
check("enroll env" in open(os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "docker", "agent-entrypoint.sh")).read()
      and 'enroll "$PDP_ENROLL_TOKEN"' not in open(os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "docker", "agent-entrypoint.sh")).read(),
      "the agent entrypoint passes the token through the environment")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
