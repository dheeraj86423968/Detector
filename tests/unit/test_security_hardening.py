"""Security review of 2026-11-08 (SECURITY_REVIEW_2026-11-08.md): the fixes, each against the code path it changed.
No database: pdp_server.db is replaced by a small fake that answers the statements these routes run.
Run: PYTHONPATH=server:engine:agent python tests/unit/test_security_hardening.py
"""
import contextlib
import os
import re
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


# =============================================================================================== round 2
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
from pdp_server import updates, integrity as I, pki   # noqa: E402

# ---- 10. agent updates: digests (F2), downgrades (F4), hold threshold (F5)
D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64
os.environ["PDP_AGENT_VERSION"], os.environ["PDP_AGENT_DIGEST"] = "0.7.0", D1
os.environ["PDP_AGENT_DIGESTS"] = f"0.6.0={D2},0.7.0={D1}"
os.environ["PDP_PUBLIC_HOSTNAME"] = "pdp.example.com"
check(updates.digest_for("0.7.0") == D1 and updates.digest_for("0.6.0") == D2 and updates.digest_for("0.5.0") is None, "recorded digests per version")
check(updates.image_ref("pdp.example.com", "0.7.0") == f"pdp.example.com/pdp/agent:0.7.0@{D1}" and updates.image_ref("h", "0.5.0") is None
      and distrib.agent_image("pdp.example.com") == f"pdp.example.com/pdp/agent:0.7.0@{D1}", "installer and updater references are digest-pinned")
os.environ["PDP_AGENT_DIGESTS"] = "0.6.0=" + D2
os.environ.pop("PDP_AGENT_DIGEST")
check(updates.digest_for("0.7.0") is None and distrib.agent_image("h") is None, "a version published without a digest yields no image reference")
os.environ["PDP_AGENT_DIGEST"], os.environ["PDP_AGENT_DIGESTS"] = D1, f"0.6.0={D2},0.7.0={D1}"

def ep(i, ver, failed=(), seen=0, name=None):
    return {"id": f"e{i}", "name": name or f"host{i}", "agent_version": ver, "agent_version_since": datetime.now(timezone.utc) - timedelta(hours=2),
            "last_seen": datetime.now(timezone.utc) - timedelta(seconds=seen), "enrolled_at": datetime.now(timezone.utc) - timedelta(days=i),
            "health": {"update": {"failed": list(failed)}}}
fleet = [ep(1, "0.6.0", failed=["0.7.0"])] + [ep(i, "0.7.0") for i in range(2, 12)]
h = updates.hold(fleet, "0.7.0")
check(h["held"] is None and h["failed_on"] == [{"id": "e1", "name": "host1"}] and h["tried"] == 11, "one endpoint reporting a failure does not hold the version (recorded)")
h = updates.hold([ep(1, "0.6.0", failed=["0.7.0"]), ep(2, "0.6.0", failed=["0.7.0"])] + [ep(i, "0.7.0") for i in range(3, 12)], "0.7.0")
check(h["held"] and "2 of the 11" in h["held"] and len(h["failed_on"]) == 2, "two failures out of eleven (>= 2 and >= 10 %) hold it")
h = updates.hold([ep(1, "0.6.0", failed=["0.7.0"]), ep(2, "0.6.0", failed=["0.7.0"])] + [ep(i, "0.7.0") for i in range(3, 40)], "0.7.0")
check(h["held"] is None and len(h["failed_on"]) == 2, "two failures out of thirty-nine (< 10 %) do not hold it")
check(updates.hold([ep(1, "0.7.0")], "0.7.0") is None, "no failures: nothing to hold")

class UpdDB(FakeDB):
    def __init__(self, eps, policy="auto", versions=("0.6.0", "0.7.0")):
        super().__init__(users={1: {"username": "op", "org_id": "o1"}}); self.eps, self.policy, self.versions = eps, policy, versions
        self.events, self.audit = [], []
    def q(self, c, sql, args=(), one=False):
        self.log.append((sql, args))
        if sql.startswith("SELECT agent_update FROM orgs"): r = [{"agent_update": self.policy}]
        elif sql.startswith("SELECT id, name, agent_version"): r = [dict(e) for e in self.eps]
        elif sql.startswith("SELECT DISTINCT agent_version"): r = [{"agent_version": v} for v in self.versions]
        elif sql.startswith("SELECT agent_version, count"): r = [{"agent_version": v, "n": 1} for v in self.versions]
        elif sql.startswith("UPDATE orgs SET agent_update"): self.policy = args[0]; r = None
        elif sql.startswith("SELECT username FROM users"): r = [{"username": "op"}]
        elif sql.startswith("INSERT INTO audit_log"): self.audit.append(args); r = None
        elif sql.startswith("INSERT INTO security_events"): self.events.append(args); r = None
        else: raise AssertionError(sql)
        if r is None: return None
        return (r[0] if r else None) if one else r
udb = UpdDB(fleet); db.q = udb.q
r = updates.rollout(None, "o1", "0.7.0")
check(r["ready"] and r["failed_on"] == [{"id": "e1", "name": "host1"}], "rollout: proven, the single failure is reported but does not hold")
upd = updates.update_for(None, {"id": "e2", "org_id": "o1", "agent_version": "0.6.0", "health": {}})
check(upd and upd["image"] == f"pdp.example.com/pdp/agent:0.7.0@{D1}", "an endpoint is offered the digest-pinned image")
os.environ["PDP_AGENT_DIGESTS"] = "0.6.0=" + D2; os.environ.pop("PDP_AGENT_DIGEST")
check(updates.update_for(None, {"id": "e2", "org_id": "o1", "agent_version": "0.6.0", "health": {}}) is None, "no digest for the target: no update is offered")
os.environ["PDP_AGENT_DIGEST"], os.environ["PDP_AGENT_DIGESTS"] = D1, f"0.6.0={D2},0.7.0={D1}"
admin_s = {"u": 1, "org": "o1", "r": "admin", "op": False}
op_s = {"u": 1, "org": "o1", "r": "admin", "op": True}
st = raises(updates.set_policy, updates.UpdatePolicy(agent_update="0.6.0"), admin_s)
check(st == 403 and udb.policy == "auto", "an organisation admin cannot pin below the fleet's running versions")
out = updates.set_policy(updates.UpdatePolicy(agent_update="0.7.0"), admin_s)
check(out["policy"] == "0.7.0" and udb.audit and not udb.events, "pinning at the current version: allowed, audited, no security event")
st = raises(updates.set_policy, updates.UpdatePolicy(agent_update="0.6.0"), op_s)
check(st == 400 and udb.policy == "0.7.0", "the operator rolling back without a reason is refused (reason required)")
out = updates.set_policy(updates.UpdatePolicy(agent_update="0.6.0", reason="CVE in 0.7.0 collector"), op_s)
check(out["policy"] == "0.6.0" and udb.events and udb.events[-1][1] == "detection_weakened" and "0.6.0" in udb.events[-1][6]
      and "CVE in 0.7.0" in udb.audit[-1][6], "the operator's rollback is audited with the reason and raised as a detection_weakened event")
check(raises(updates.set_policy, updates.UpdatePolicy(agent_update="0.5.0"), op_s) == 400, "a version without a recorded digest cannot be pinned")

# ---- 11. per-endpoint ingest budget (F11)
class QuotaDB(FakeDB):
    def __init__(self, used_b, used_n):
        super().__init__(); self.used, self.state, self.events = (used_b, used_n), None, []
    def q(self, c, sql, args=(), one=False):
        self.log.append((sql, args))
        if sql.startswith("SELECT coalesce(sum(bytes), 0) AS b"): r = [{"b": self.used[0], "n": self.used[1]}]
        elif sql.startswith("SELECT state FROM endpoint_integrity"): r = [{"state": self.state}] if self.state else []
        elif sql.startswith("INSERT INTO endpoint_integrity"):
            import json as _j; self.state = {"findings": _j.loads(args[1])}; r = None
        elif sql.startswith("INSERT INTO security_events"): self.events.append(args); r = None
        else: raise AssertionError(sql)
        if r is None: return None
        return (r[0] if r else None) if one else r
EP = {"id": "e1", "org_id": "o1", "name": "web-1", "config": {}}
qdb = QuotaDB(1 << 30, 1_000_000); db.q = qdb.q; I._q = qdb.q
I.check_quota(None, EP, 5000, 1 << 20)
check(not qdb.events, "within the daily budget: accepted")
qdb = QuotaDB(I.DAILY_BYTES - 10, 1_000_000); db.q = qdb.q; I._q = qdb.q
try:
    I.check_quota(None, EP, 5000, 1 << 20); st = None
except I.IngestError as e:
    st = e.status
check(st == 429 and len(qdb.events) == 1 and qdb.events[0][1] == "ingest_quota" and qdb.events[0][3] == "e1"
      and qdb.state["findings"][0]["key"].startswith("ingest_quota:"), "over the byte budget: 429, one integrity finding, one security event")
try:
    I.check_quota(None, EP, 5000, 1 << 20)
except I.IngestError:
    pass
check(len(qdb.events) == 1 and len(qdb.state["findings"]) == 1, "the next refusal the same day adds no second event or finding")
qdb = QuotaDB(0, I.DAILY_ROWS - 1); db.q = qdb.q; I._q = qdb.q
try:
    I.check_quota(None, EP, 5000, 10); st = None
except I.IngestError as e:
    st = e.status
check(st == 429 and "rows" in qdb.events[0][6], "over the row budget: 429")
qdb = QuotaDB(I.DAILY_BYTES + 5, 0); db.q = qdb.q; I._q = qdb.q
I.check_quota(None, dict(EP, config={"ingest_daily_bytes": I.DAILY_BYTES * 4}), 1, 1)
check(not qdb.events and I.quota_for({"config": {"ingest_daily_bytes": True}}) == (I.DAILY_BYTES, I.DAILY_ROWS), "a per-endpoint override raises the budget; a bogus one is ignored")
gw = open(os.path.join(ROOT, "deploy", "nginx", "gateway.conf")).read()
check("limit_req_zone $ssl_client_s_dn zone=pdp_agent" in gw and re.search(r"location /v1/ \{.*?limit_req zone=pdp_agent", gw, re.S), "the agent port is rate-limited per client certificate")

# ---- 12. logout revokes the session server-side (F19)
class SessDB(FakeDB):
    def __init__(self):
        super().__init__(); self.revoked = set()
    def q(self, c, sql, args=(), one=False):
        self.log.append((sql, args))
        if sql.startswith("SELECT u.role, u.auth"):
            r = [{"role": "admin", "auth": "local", "disabled": False, "endpoints": None, "org_id": "o1", "operator": False, "totp_enabled": False,
                  "session_gen": 0, "require_mfa": False, "org_disabled": False, "org_name": "Org"}]
        elif sql.startswith("SELECT 1 FROM revoked_sessions"): r = [{"?": 1}] if args[0] in self.revoked else []
        elif sql.startswith("DELETE FROM revoked_sessions"): r = None
        elif sql.startswith("INSERT INTO revoked_sessions"): self.revoked.add(args[0]); r = None
        elif sql.startswith("SELECT id FROM endpoints WHERE org_id"): r = []
        elif sql.startswith("SELECT session_gen"): r = [{"session_gen": 0}]
        else: raise AssertionError(sql)
        if r is None: return None
        return (r[0] if r else None) if one else r
sdb = SessDB(); db.q = sdb.q
cookie = auth.make_session(7, "admin", 0)
sd = auth.read_session(cookie)
check(sd and len(sd.get("sid") or "") >= 16 and auth.read_session(auth.make_session(7, "admin", 0))["sid"] != sd["sid"], "every session cookie carries its own id")
class SReq:
    def __init__(self, cookie): self.cookies, self.headers, self.client = {"pdp_session": cookie}, {}, None; self.url = type("U", (), {"path": "/api/me"})()
check(access.session(SReq(cookie))["u"] == 7, "a live session is accepted")
access.revoke_session(None, sd)
check(sd["sid"] in sdb.revoked and raises(access.session, SReq(cookie)) == 401, "after logout the same cookie is refused")
check(access.session(SReq(auth.make_session(7, "admin", 0)))["u"] == 7, "the user's other sessions continue")

# ---- 13. private keys out of the gateway's volume (F9)
tmp = tempfile.mkdtemp()
pki.PKI_DIR, pki.PRIVATE_DIR = tmp, os.path.join(tmp, "private")
pki.ensure_pki(["localhost"])
check(os.path.exists(os.path.join(tmp, "private", "ca.key")) and os.path.exists(os.path.join(tmp, "private", "bundle_signing.key"))
      and not os.path.exists(os.path.join(tmp, "ca.key")) and os.path.exists(os.path.join(tmp, "ca.pem")) and os.path.exists(os.path.join(tmp, "server.key")),
      "file mode: CA and signing keys are created under private/, certificates and the TLS key stay in the gateway's directory")
check(oct(os.stat(os.path.join(tmp, "private")).st_mode)[-3:] == "700" and oct(os.stat(os.path.join(tmp, "private", "ca.key")).st_mode)[-3:] == "600", "private/ is 0700, keys 0600")
pem, serial = pki.sign_csr(__import__("cryptography.x509", fromlist=["x"]).CertificateSigningRequestBuilder().subject_name(pki._name("x")).sign(
    __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["x"]).generate_private_key(__import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["x"]).SECP256R1()),
    __import__("cryptography.hazmat.primitives.hashes", fromlist=["x"]).SHA256()).public_bytes(__import__("cryptography.hazmat.primitives.serialization", fromlist=["x"]).Encoding.PEM).decode(), "e1")
check("BEGIN CERTIFICATE" in pem and serial, "the CA signs from its new location")
# an installation from before the review: keys directly in PKI_DIR are moved once
import shutil as _sh
for name in ("ca.key", "bundle_signing.key"):
    _sh.move(os.path.join(tmp, "private", name), os.path.join(tmp, name))
open(os.path.join(tmp, "session.secret"), "wb").write(b"s" * 32)
moved = pki.migrate_private()
check(sorted(moved) == ["bundle_signing.key", "ca.key", "session.secret"] and not os.path.exists(os.path.join(tmp, "ca.key"))
      and open(os.path.join(tmp, "private", "session.secret"), "rb").read() == b"s" * 32 and pki.migrate_private() == [],
      "legacy key files are moved into private/ (once); the session secret keeps its value")
compose = open(os.path.join(ROOT, "deploy", "docker-compose.yml")).read()
import yaml  # noqa: E402
dc = yaml.safe_load(compose)
gw_vols = " ".join(map(str, dc["services"]["gateway"]["volumes"]))
check("pdp_pki_private" not in gw_vols and "pdp_pki:/pki:ro" in gw_vols and all("pdp_pki_private:/pki/private" in " ".join(map(str, dc["services"][n]["volumes"]))
      for n in ("api", "worker-ingest", "worker-train")), "compose: the private volume is mounted into api and workers, never the gateway")
check("ports" not in dc["services"]["registry"] and dc["services"]["registry"]["networks"] == ["backend"]
      and any(":5000" in str(p) for p in dc["services"]["gateway"]["ports"]) and "auth_basic_user_file /etc/nginx/registry-push.htpasswd" in gw
      and dc["services"]["registry"]["environment"]["REGISTRY_STORAGE_MAINTENANCE"] == "readonly: {enabled: ${PDP_REGISTRY_READONLY:-true}}",
      "compose/gateway: registry has no published port, is read-only by default; pushes go through the gateway's authenticated loopback listener")

# ---- 14. backups: encrypt-then-MAC, verified before extraction, unsafe members refused (F22)
import subprocess, tarfile  # noqa: E402
bk = tempfile.mkdtemp()
open(os.path.join(bk, "key"), "w").write("k" * 48)
os.makedirs(os.path.join(bk, "src")); open(os.path.join(bk, "src", "a.txt"), "w").write("hello")
seal = os.path.join(ROOT, "deploy", "backup", "seal.sh")
sh = lambda cmd: subprocess.run(["bash", "-c", f". '{seal}'; {cmd}"], cwd=bk, capture_output=True, text=True)
r = sh("tar -C src -cf - . | gzip -1 | seal key out.enc && verify key out.enc && echo VERIFIED")
check(r.returncode == 0 and "VERIFIED" in r.stdout and os.path.exists(os.path.join(bk, "out.enc.hmac")), f"seal + verify round trip ({r.stderr.strip()[:80]})")
r = sh("unseal key out.enc | gunzip | tar -tf - | grep -q a.txt && echo PLAIN")
check("PLAIN" in r.stdout, "unseal gives the archive back")
data = bytearray(open(os.path.join(bk, "out.enc"), "rb").read()); data[-5] ^= 0x01; open(os.path.join(bk, "out.enc"), "wb").write(data)
check(sh("verify key out.enc").returncode != 0, "a flipped ciphertext byte fails verification")
data[-5] ^= 0x01; open(os.path.join(bk, "out.enc"), "wb").write(data)
open(os.path.join(bk, "key2"), "w").write("x" * 48)
check(sh("verify key2 out.enc").returncode != 0 and sh("rm out.enc.hmac; verify key out.enc").returncode != 0, "a wrong key or a missing MAC fails verification")
with tarfile.open(os.path.join(bk, "evil.tar"), "w") as t:
    ti = tarfile.TarInfo("../../etc/evil"); ti.size = 0; t.addfile(ti)
with tarfile.open(os.path.join(bk, "abs.tar"), "w") as t:
    ti = tarfile.TarInfo("/etc/evil"); ti.size = 0; t.addfile(ti)
with tarfile.open(os.path.join(bk, "link.tar"), "w") as t:
    ti = tarfile.TarInfo("pki/ca.key"); ti.type = tarfile.SYMTYPE; ti.linkname = "/etc/shadow"; t.addfile(ti)
with tarfile.open(os.path.join(bk, "good.tar"), "w") as t:
    t.add(os.path.join(bk, "src", "a.txt"), arcname="./a.txt")
check(all(sh(f"safe_members {n}.tar").returncode != 0 for n in ("evil", "abs", "link")) and sh("safe_members good.tar").returncode == 0,
      "member checks: '..', absolute paths and symlinks are refused, a plain archive passes")
rs = open(os.path.join(ROOT, "deploy", "restore.sh")).read()
check(rs.index("verify \"$KEY\" \"$ARCH\"") < rs.index("unseal \"$KEY\" \"$ARCH\"") < rs.index("safe_members \"$W/archive.tar\"") < rs.index("--no-same-owner -xf \"$W/archive.tar\""),
      "restore.sh: verify, then decrypt to a file, then check members, then extract without ownership")

# ---- 15. installers: the token never has to be on the command line (F10)
def arg_loop(path):
    t = open(path).read()
    return re.search(r"\nwhile \[ \$# -gt 0 \]; do\n.*?\ndone\n", t, re.S).group(0)
for name, path in (("install.sh", os.path.join(ROOT, "server", "pdp_server", "install.sh.tmpl")), ("pdp-agent-install", os.path.join(ROOT, "deploy", "packaging", "agent", "pdp-agent-install"))):
    loop = arg_loop(path)
    head = 'token=""; die() { echo "die: $*" >&2; exit 9; }; usage() { :; }; DATA=/nonexistent\n'
    run = lambda args, env=None, stdin="": subprocess.run(["bash", "-c", head + loop + '\nprintf "%s" "$token"', "x", *args], env={**os.environ, **(env or {})}, input=stdin, capture_output=True, text=True)
    tf = os.path.join(bk, "tok"); open(tf, "w").write("tok-from-file\n")
    check(run(["--token-env"], {"PDP_ENROLL_TOKEN": "tok-from-env"}).stdout == "tok-from-env" and run(["--token-file", tf]).stdout == "tok-from-file"
          and run(["--token-stdin"], stdin="tok-from-stdin\n").stdout == "tok-from-stdin" and run(["--token", "literal"]).stdout == "literal",
          f"{name}: --token-env / --token-file / --token-stdin / --token")
    check(run(["--token-env"], {"PDP_ENROLL_TOKEN": ""}).returncode == 9 and run(["--token-stdin"], stdin="").returncode == 9, f"{name}: an empty token is an error")
check("--token-env" in api.create_endpoint.__code__.co_consts.__repr__() or "install_command_env" in open(os.path.join(ROOT, "server", "pdp_server", "api.py")).read(),
      "the console gets an install command that keeps the token in the environment")
ep_sh = open(os.path.join(ROOT, "deploy", "docker", "agent-entrypoint.sh")).read()
check("enroll env" in ep_sh, "the container entrypoint passes the token through the environment")

# ---- 16. desktop wrapper (F12): no bridge in the console window, guarded IPC, confined navigation
mj = open(os.path.join(ROOT, "desktop", "main.js")).read()
console_prefs = re.search(r"win = new BrowserWindow\(\{.*?webPreferences: \{(.*?)\}", mj, re.S).group(1)
settings_prefs = re.search(r"settingsWin = new BrowserWindow\(\{.*?webPreferences: \{(.*?)\}", mj, re.S).group(1)
check("preload" not in console_prefs and "sandbox: true" in console_prefs and "preload" in settings_prefs, "console window has no preload; the settings window has it")
check(mj.count("if (!fromSettingsPage(e)) throw") == 2 and 'url.startsWith("file://")' in mj, "both IPC handlers check the calling frame is the local settings page")
check('u.protocol !== "https:"' in mj and "validateConfig(c)" in mj, "saveConfig validates the gateway URL scheme and the fingerprint format")
check(re.search(r'if \(u\.protocol === "https:" \|\| u\.protocol === "http:"\) shell\.openExternal', mj) and mj.count("shell.openExternal(") == 1,
      "only http(s) links open outside the app")
check('contents.on("will-navigate"' in mj and "setWindowOpenHandler" in mj and "u.origin === serverOrigin()" in mj, "navigation is confined to the configured server's origin")
check("toggleDevTools" not in mj, "DevTools are not in the production menu")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
