"""Auditor role (0.13): a read-only administrator. Sees every admin read, changes nothing, gets no secrets, is never the
platform operator. Requests go through the real FastAPI app (routing, dependencies, middleware) with a minimal ASGI
client; pdp_server.db is replaced by a fake that answers the statements the routes under test run.
Run: PYTHONPATH=server:engine:agent python tests/unit/test_auditor.py
"""
import asyncio
import contextlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["PDP_SESSION_SECRET"] = os.path.join(tempfile.mkdtemp(), "session.secret")
from fastapi import HTTPException                  # noqa: E402
from fastapi.routing import APIRoute               # noqa: E402

from pdp_server import access, api, audit, auth, db, notify, oidc, orgs, posture, sso   # noqa: E402
from pdp_server.k8s import key_of                  # noqa: E402

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


def raises(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except HTTPException as e:
        return e.status_code
    return None


# ------------------------------------------------------------------------------------------------ fixtures
NOW = datetime.now(timezone.utc)
EP1, EP2 = "00000000-0000-0000-0000-0000000000e1", "00000000-0000-0000-0000-0000000000e2"
INVITE_TOKEN = "invTOKENsecret0123456789abcdef"
ENROLL_TOKEN = "enrolTOKENsecret0123456789abc"
CLUSTER_TOKEN = "clusterTOKENsecret0123456789"
HOOK_SECRET_PATH = "T0SECRET/B0SECRET/xyzSECRETxyz"
SLACK = f"https://hooks.slack.com/services/{HOOK_SECRET_PATH}"
WEBHOOK = "https://soar.example.com/pdp?apikey=QUERYSECRET"
SECRETS = (INVITE_TOKEN, ENROLL_TOKEN, CLUSTER_TOKEN, "SECRET", "QUERYSECRET", "chansecret")


class FakeDB:
    def __init__(self):
        self.log = []
        self.users = {}

    def q(self, c, sql, args=(), one=False):
        self.log.append((sql, args))
        r = None
        if sql.startswith("SELECT u.role, u.auth, u.disabled, u.endpoints, u.org_id, u.operator"):
            u = self.users.get(args[0]); r = [dict(u, org_disabled=False, org_name="Org", require_mfa=False)] if u else []
        elif sql.startswith("SELECT id FROM endpoints WHERE org_id"):
            r = [{"id": EP1}, {"id": EP2}]
        elif sql.startswith("SELECT u.*, o.name AS org_name"):
            u = self.users.get(args[0]); r = [dict(u, org_name="Org", require_mfa=False)] if u else []
        elif sql.startswith("SELECT id, username, display_name, role, auth, email, endpoints, disabled"):
            r = [dict(u, created_at=NOW, last_login=None) for u in self.users.values()]
        elif sql.startswith("SELECT id, name FROM endpoints WHERE org_id"):
            r = [{"id": EP1, "name": "web-01"}, {"id": EP2, "name": "db-01"}]
        elif "FROM jobs j JOIN endpoints e" in sql:
            r = [{"id": "j1", "endpoint_id": EP1, "endpoint": "web-01", "kind": "train", "state": "done", "params": {}, "progress": {},
                  "error": None, "result": None, "created_at": NOW, "started_at": NOW, "finished_at": NOW, "heartbeat": None}]
        elif sql.startswith("SELECT token, name, progress, used_by, expires_at FROM enroll_tokens"):
            r = [{"token": ENROLL_TOKEN, "name": "web-03", "progress": [{"stage": "started"}], "used_by": None, "expires_at": NOW + timedelta(hours=3)}]
        elif "FROM audit_log a" in sql:
            r = [{"id": 1, "at": NOW, "who": "ann", "action": "POST /api/invites/{token}/accept", "target": f"token={INVITE_TOKEN}", "status": 200,
                  "ip": "203.0.113.9", "detail": None},
                 {"id": 2, "at": NOW, "who": "ann", "action": "notification channel added", "target": "channel_id=1", "status": 200, "ip": None,
                  "detail": {"changes": posture.diff(None, {"target": SLACK, "secret": "chansecret"})}}]
        elif "FROM security_events se" in sql:
            r = [{"id": 1, "kind": "detection_weakened", "severity": "high", "endpoint_id": EP1, "endpoint": "web-01", "who": "ann",
                  "title": "Notifications reduced", "detail": {"diff": posture.diff({"target": SLACK}, {"target": WEBHOOK})}, "at": NOW}]
        elif sql.startswith("SELECT * FROM notify_channels WHERE org_id"):
            base = {"min_severity": "high", "events": ["incident"], "every_alert": False, "enabled": True, "created_by": "ann", "created_at": NOW,
                    "last_ok_at": None, "last_error_at": NOW, "secret": "chansecret"}
            r = [dict(base, id=1, name="soc", kind="slack", target=SLACK, last_error=f"HTTP 404 posting to {SLACK}"),
                 dict(base, id=2, name="soar", kind="webhook", target=WEBHOOK, last_error=None),
                 dict(base, id=3, name="mail", kind="email", target="soc@example.com", last_error=None, secret=None)]
        elif sql.startswith("SELECT v FROM kv WHERE k='notifier'"):
            r = [{"v": {"email": True, "at": NOW.timestamp()}}]
        elif sql.startswith("SELECT 1 FROM notify_channels WHERE id"):
            r = [{"?column?": 1}]
        elif "FROM notify_log WHERE channel_id" in sql:
            r = [{"key": "incident:1:high", "subject": "[M.D Lab] incident", "state": "failed", "detail": f"<urlopen error {WEBHOOK}>", "at": NOW}]
        elif sql.startswith("SELECT token, name, uses, max_uses, expires_at FROM enroll_tokens"):
            r = [{"token": CLUSTER_TOKEN, "name": "prod-eu-1", "uses": 2, "max_uses": 20, "expires_at": NOW + timedelta(days=3)}]
        elif sql.startswith("SELECT config->>'cluster'"):
            r = [{"cluster": "prod-eu-1", "n": 2}]
        elif "FROM invites i LEFT JOIN users u" in sql:
            r = [{"id": 5, "token": INVITE_TOKEN, "email": "new@example.com", "role": "analyst", "endpoints": None, "created_at": NOW,
                  "expires_at": NOW + timedelta(days=7), "created_by_name": "ann"},
                 {"id": 6, "token": INVITE_TOKEN + "2", "email": None, "role": "auditor", "endpoints": [EP1], "created_at": NOW,
                  "expires_at": NOW + timedelta(days=7), "created_by_name": "ann"}]
        elif sql.startswith("SELECT state, result, params, created_at, finished_at FROM jobs"):
            r = [{"state": "done", "result": "ok", "params": {"command": "isolate"}, "created_at": NOW, "finished_at": NOW}]
        elif "FROM alerts a JOIN endpoints e" in sql:
            r = []
        elif sql.startswith("SELECT * FROM users WHERE id=%s AND org_id=%s"):
            u = self.users.get(args[0]); r = [dict(u)] if u else []
        elif sql.startswith("SELECT 1 FROM users WHERE"):
            r = []
        elif sql.startswith("INSERT INTO users"):
            r = [{"id": 99}]
        elif sql.startswith("SELECT count(*) AS n FROM invites"):
            r = [{"n": 0}]
        elif sql.startswith("INSERT INTO invites"):
            r = [{"id": 7, "token": args[0], "org_id": args[1], "email": args[2], "role": args[3], "endpoints": json.loads(args[4]) if args[4] else None,
                  "created_at": NOW, "expires_at": args[6]}]
        elif sql.startswith("SELECT coalesce(display_name, username) AS n FROM users"):
            r = [{"n": "ann"}]
        if r is None:
            return None
        return (r[0] if r else None) if one else r


@contextlib.contextmanager
def fake_conn(dsn=None):
    yield None


fake = FakeDB()
db.conn = fake_conn
db.q = fake.q
fake.users = {
    1: {"id": 1, "username": "ann", "display_name": "Ann", "role": "admin", "auth": "local", "email": "ann@example.com", "endpoints": None,
        "disabled": False, "org_id": "o1", "operator": True, "totp_enabled": False, "session_gen": 0},
    2: {"id": 2, "username": "audrey", "display_name": "Audrey", "role": "auditor", "auth": "local", "email": None, "endpoints": [EP1],
        "disabled": False, "org_id": "o1", "operator": True, "totp_enabled": False, "session_gen": 0},   # operator flag must not count
    3: {"id": 3, "username": "vic", "display_name": "Vic", "role": "viewer", "auth": "local", "email": None, "endpoints": [EP1],
        "disabled": False, "org_id": "o1", "operator": False, "totp_enabled": False, "session_gen": 0},
}


def sess(role, uid):
    return {"u": uid, "r": role, "a": "local", "scope": {EP1, EP2} if role in ("admin", "auditor") else {EP1}, "org": "o1", "org_name": "Org",
            "op": role == "admin", "sid": "x", "g": 0}


CURRENT = {}
api.app.dependency_overrides[access.session] = lambda: CURRENT["s"]


def call(method, path, role="auditor", body=None, query=""):
    """One request through the ASGI app; returns (status, body text)."""
    CURRENT["s"] = sess(role, {"admin": 1, "auditor": 2, "viewer": 3, "analyst": 4}[role])
    raw = json.dumps(body if body is not None else {}).encode()
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "https", "path": path,
             "raw_path": path.encode(), "query_string": query.encode(), "root_path": "",
             "headers": [(b"host", b"console.example.com"), (b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())],
             "client": ("203.0.113.9", 1234), "server": ("console.example.com", 443)}
    out = {"status": None, "body": b""}
    sent = {"done": False}

    async def receive():
        if not sent["done"]:
            sent["done"] = True
            return {"type": "http.request", "body": raw, "more_body": False}
        await asyncio.Event().wait()      # the client stays connected (a disconnect would cut the middleware's response)

    async def send(m):
        if m["type"] == "http.response.start":
            out["status"] = m["status"]
        elif m["type"] == "http.response.body":
            out["body"] += m.get("body", b"")

    asyncio.run(api.app(scope, receive, send))
    return out["status"], out["body"].decode(errors="replace")


# ------------------------------------------------------------------------------------------------ 1. role model
c = access.can({"r": "auditor", "op": True})
check(c["view_admin"] and c["export"] and not any(c[k] for k in ("manage_users", "manage_endpoints", "manage_org", "triage", "run_checks", "operate")),
      "can(auditor): view_admin and export only; every manage_* / triage / run_checks / operate false (even with the operator flag)")
c = access.can({"r": "admin", "op": False})
check(c["view_admin"] and c["manage_users"] and c["manage_org"] and c["export"], "can(admin): view_admin and manage_* as before")
check(not access.can({"r": "viewer", "op": False})["view_admin"] and not access.can({"r": "analyst", "op": False})["view_admin"]
      and not access.can({"r": "viewer", "op": False})["export"] and access.can({"r": "analyst", "op": False})["export"],
      "can(analyst/viewer): no view_admin; viewers cannot export (as before), analysts can")
check("auditor" in access.ROLES and "auditor" in access.ROLE_TEXT and "changes nothing" in access.ROLE_TEXT["auditor"]
      and "sees everything an admin sees" in access.ROLE_TEXT["auditor"], "role listed with its description")
check(not access.is_operator("auditor", True) and access.is_operator("admin", True) and not access.is_operator("admin", False),
      "is_operator: the flag never counts for an auditor")

# session(): scope = all of the organisation's endpoints (users.endpoints ignored), operator flag ignored


class Req:
    def __init__(self, cookie):
        self.cookies, self.headers, self.client = {"pdp_session": cookie}, {}, None
        self.url = type("U", (), {"path": "/api/users"})()


s = access.session(Req(auth.make_session(2, "auditor", 0)))
check(s["r"] == "auditor" and s["scope"] == {EP1, EP2} and s["op"] is False, "session(auditor): every endpoint of the organisation, never the operator")
s = access.session(Req(auth.make_session(3, "viewer", 0)))
check(s["r"] == "viewer" and s["scope"] == {EP1}, "session(viewer): still narrowed by users.endpoints")
me = orgs.me_body(None, 2)
check(me["role"] == "auditor" and me["operator"] is False and me["can"]["view_admin"] and not me["can"]["operate"] and me["endpoints"] is None,
      "/api/me for an auditor: operator false, can.view_admin, endpoints null (all)")

# ------------------------------------------------------------------------------------------------ 2. every change is refused
OWN_OR_PUBLIC = {"/api/signup", "/api/login", "/api/login/mfa", "/api/logout", "/api/me/password", "/api/me/sessions/end", "/api/me/mfa/setup",
                 "/api/me/mfa/enable", "/api/me/mfa/disable", "/api/invites/{token}/accept", "/api/public/install/progress"}
mutating = sorted({(m, r.path) for r in api.app.routes if isinstance(r, APIRoute) and r.path.startswith("/api/")
                   for m in r.methods if m in ("POST", "PUT", "PATCH", "DELETE")})
checked, bad = 0, []
for m, p in mutating:
    if p in OWN_OR_PUBLIC:
        continue
    path = re.sub(r"\{(\w+)\}", lambda x: EP1 if x.group(1) == "endpoint_id" else "1", p)
    want = 404 if p.startswith("/api/operator/") else 403     # operator routes hide themselves from everyone else
    for role in ("auditor", "viewer"):
        st, _ = call(m, path, role, body={"x": 1})
        if st != want:
            bad.append(f"{role} {m} {p}: {st}")
    checked += 1
check(checked >= 30 and not bad, f"auditor and viewer refused on all {checked} mutating console routes (403; operator routes 404)" + (f": {bad}" if bad else ""))
check(not [x for x in fake.log if x[0].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))],
      "no refused change reached the database")
own = sorted(p for _, p in mutating if p in OWN_OR_PUBLIC)
check(own == sorted(OWN_OR_PUBLIC), "the routes left out above are exactly the own-account / public ones")


def guards(route):
    seen, todo = set(), [route.dependant]
    while todo:
        d = todo.pop()
        for sd in d.dependencies:
            seen.add(getattr(sd.call, "__name__", ""))
            todo.append(sd)
    return seen


gets = {r.path: guards(r) for r in api.app.routes if isinstance(r, APIRoute) and "GET" in r.methods and r.path.startswith("/api/")}
admin_gets = sorted(p for p, g in gets.items() if "admin" in g)
check(admin_gets == ["/api/clusters/{key}/manifest"], f"the only admin-only read left is the cluster manifest (it embeds the enrolment token): {admin_gets}")
VIEWS = ["/api/users", "/api/jobs", "/api/install-progress/{key}", "/api/audit", "/api/security-events", "/api/notifications/channels",
         "/api/notifications/log", "/api/clusters", "/api/invites", "/api/endpoints/{endpoint_id}/commands/{command_id}"]
check(all("admin_view" in gets[p] for p in VIEWS), "every other admin read is open to auditors (admin_view)")

# ------------------------------------------------------------------------------------------------ 3. admin reads: allowed, secrets withheld
ADMIN_READS = [("/api/users", ""), ("/api/jobs", ""), (f"/api/install-progress/{key_of(ENROLL_TOKEN)}", ""), ("/api/audit", ""),
               ("/api/security-events", ""), ("/api/notifications/channels", ""), ("/api/notifications/log", "channel_id=1"),
               ("/api/clusters", ""), ("/api/invites", ""), (f"/api/endpoints/{EP1}/commands/c1", "")]
bodies = {}
for p, qs in ADMIN_READS:
    st, b = call("GET", p, "auditor", query=qs)
    bodies[p] = b
    leaked = [x for x in SECRETS if x in b]
    check(st == 200 and not leaked, f"auditor GET {p}: 200, no secrets" + (f" (status {st}, leaked {leaked})" if st != 200 or leaked else ""))
    st_v, _ = call("GET", p, "viewer", query=qs)
    check(st_v == 403, f"viewer GET {p}: still 403")

inv = json.loads(bodies["/api/invites"])["invites"]
check(len(inv) == 2 and all(i["link"] is None for i in inv) and inv[1]["endpoints"] is None,
      "invites: listed without their link; an auditor invite always covers all endpoints")
ch = {c["name"]: c for c in json.loads(bodies["/api/notifications/channels"])["channels"]}
check(ch["soc"]["target"] == "https://hooks.slack.com/..." and ch["soar"]["target"] == "https://soar.example.com/..."
      and ch["mail"]["target"] == "soc@example.com" and "secret" not in ch["soc"] and ch["soc"]["has_secret"] is True
      and ch["soc"]["last_error"] == "HTTP 404 posting to https://hooks.slack.com/...",
      "notification channels: URLs reduced to their host (also in last_error), e-mail recipients kept, the signing secret never")
log = json.loads(bodies["/api/notifications/log"])["log"]
check(log[0]["detail"] == "<urlopen error https://soar.example.com/...>", "notification log: URLs in delivery errors reduced to their host")
aud = json.loads(bodies["/api/audit"])["entries"]
check(aud[0]["target"] == "token=[redacted]" and aud[1]["target"] == "channel_id=1", "audit log: token path parameters redacted, other targets kept")
cl = json.loads(bodies["/api/clusters"])["clusters"]
check(cl and cl[0]["key"] == key_of(CLUSTER_TOKEN) and cl[0]["cluster"] == "prod-eu-1", "clusters: listed (key, name, usage)")
check(len(json.loads(bodies["/api/users"])["users"]) == 3 and any(r["id"] == "auditor" for r in json.loads(bodies["/api/users"])["roles"]),
      "users: listed, the role list includes auditor")
au = [u for u in json.loads(bodies["/api/users"])["users"] if u["role"] == "auditor"][0]
check(au["endpoints"] is None, "users: an auditor's endpoint access shows as all endpoints")

st, b = call("GET", f"/api/clusters/{key_of(CLUSTER_TOKEN)}/manifest", "auditor")
check(st == 403 and CLUSTER_TOKEN not in b, "cluster manifest (embeds the enrolment token): auditor 403")

# export: a read; allowed for auditors (rate limit and audit row as for everyone)
real_take, real_audit = posture.take, posture.audit_change
took = []
posture.take = lambda c, uid, kind: took.append((uid, kind))
posture.audit_change = lambda *a, **k: took.append(("audit", a[2]))
st, _ = call("GET", "/api/alerts/export", "auditor", query="format=csv")
check(st == 200 and (2, "export") in took and ("audit", "alerts exported") in took, "alert export: auditor 200, rate-limited and audited")
st, _ = call("GET", "/api/alerts/export", "viewer", query="format=csv")
check(st == 403, "alert export: viewer still 403")
posture.take, posture.audit_change = real_take, real_audit

# admins still get everything (no regression)
st, b = call("GET", "/api/invites", "admin")
check(st == 200 and INVITE_TOKEN in b and "/#/join/" in b, "admin GET /api/invites: links included")
st, b = call("GET", "/api/notifications/channels", "admin")
check(st == 200 and SLACK in b and WEBHOOK in b and "chansecret" not in b, "admin GET /api/notifications/channels: full URLs (secret never, as before)")
st, b = call("GET", "/api/audit", "admin")
check(st == 200 and f"token={INVITE_TOKEN}" in b, "admin GET /api/audit: targets unchanged")

# ------------------------------------------------------------------------------------------------ 4. role management
A = sess("admin", 1)
fake.log.clear()
out = api.create_user(api.NewUser(username="aud2", password="x" * 12, role="auditor", endpoints=[EP1]), s=A)
ins = [a for q, a in fake.log if q.startswith("INSERT INTO users")]
check(out["ok"] and ins and ins[0][2] == "auditor" and ins[0][5] is None, "admin creates an auditor; endpoint scope dropped (auditors see all)")
check(raises(api.create_user, api.NewUser(username="x2", password="x" * 12, role="superuser"), s=A) == 400, "unknown role still refused")
check(not any("operator" in q for q, _ in fake.log if q.startswith("INSERT INTO users")), "user creation never sets the operator flag")
check(raises(api.update_user, 1, {"operator": True}, s=A) == 400, "PATCH /api/users: operator is not a settable field")
fake.users[5] = dict(fake.users[3], id=5, username="op2", role="analyst", operator=True)
check(raises(api.update_user, 5, {"role": "auditor"}, s=A) == 400, "an operator's role cannot be changed to auditor")
fake.log.clear()
check(api.update_user(3, {"role": "auditor"}, s=A)["ok"] and any(q.startswith("UPDATE users SET role=") and a[0] == "auditor" for q, a in fake.log),
      "admin changes a viewer to auditor")
fake.users[6] = dict(fake.users[1], id=6, username="adm2", operator=False)
check(raises(api.update_user, 6, {"role": "auditor"}, s=sess("admin", 6)) == 400, "an admin cannot demote themselves to auditor")
r = orgs.create_invite(orgs.NewInvite(role="auditor", endpoints=[EP1]), type("R", (), {"headers": {"host": "c.example.com"}, "url": type("U", (), {"netloc": "c.example.com"})()})(), s=A)
check(r["invite"]["role"] == "auditor" and r["invite"]["endpoints"] is None and r["invite"]["link"], "admin invites an auditor (all endpoints, link shown to the admin)")
check(raises(orgs.create_invite, orgs.NewInvite(role="owner"), None, s=A) == 400, "invite with an unknown role refused")

# single sign-on never hands out the role
cfg = dict(provider="google", client_id="abc", client_secret="s" * 8, domains=["example.org"], default_role="auditor")
check(raises(sso.set_sso, sso.SSOConfig(**cfg), s=A) == 400, "organisation SSO: default role auditor refused (viewer or analyst only)")
_dr = oidc.DEFAULT_ROLE
oidc.DEFAULT_ROLE = "auditor"
check(oidc.role_for(set()) is None, "server OIDC: PDP_OIDC_DEFAULT_ROLE=auditor maps to no role")
oidc.DEFAULT_ROLE = _dr

# ------------------------------------------------------------------------------------------------ 5. schema
ddl = open(os.path.join(os.path.dirname(access.__file__), "schema.sql")).read()
adds = re.findall(r"ADD CONSTRAINT (users_role_check|invites_role_check) CHECK \(role IN \(([^)]*)\)\)", ddl)
check({n for n, _ in adds} == {"users_role_check", "invites_role_check"} and all("'auditor'" in v for _, v in adds),
      "schema: every (re-)added role constraint of users and invites allows auditor (re-applying schema.sql stays valid)")
check("DROP CONSTRAINT IF EXISTS invites_role_check" in ddl and "ADD CONSTRAINT users_auditor_not_operator CHECK (NOT (role = 'auditor' AND operator))" in ddl
      and ddl.index("ADD COLUMN IF NOT EXISTS operator") < ddl.index("users_auditor_not_operator"),
      "schema: idempotent migration of the invites constraint; the database refuses an auditor operator")

# ------------------------------------------------------------------------------------------------ 6. redaction helpers
check(notify._host_only("see https://user:pw@hooks.slack.com/services/A/B?x=1 now") == "see https://hooks.slack.com/... now"
      and notify._host_only("tls://siem.example.com:6514") == "tls://siem.example.com:6514" and notify._host_only(None) is None,
      "_host_only: path, query and credentials dropped; a bare host:port kept")
check(audit.redact_target("token=abc, x=1") == "token=[redacted], x=1" and audit.redact_target(None) is None, "redact_target")

print(f"{'all passed' if not fails else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
