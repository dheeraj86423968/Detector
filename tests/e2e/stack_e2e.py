"""End-to-end test of a running stack through the real gateway (console API + agent protocol over mTLS).

Run inside the agent image on the stack's edge network:
  docker run --rm --network pdp_edge -v $PWD:/src:ro -w /src -e PDP_ADMIN_PASSWORD=<pw> \
    -e PYTHONPATH=/src/engine:/src/agent --entrypoint python pdp/agent:dev tests/e2e/stack_e2e.py
"""
import gzip
import hashlib
import http.client
import json
import os
import ssl
import sys
import time
import tempfile
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST = os.environ.get("PDP_GATEWAY", "gateway")
CONSOLE_PORT, AGENT_PORT = 443, 8443
fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg, flush=True)
    fails += 0 if cond else 1


# ---- TLS: fetch the CA once (unverified), then verify everything against it
raw = ssl.create_default_context(); raw.check_hostname = False; raw.verify_mode = ssl.CERT_NONE
c = http.client.HTTPSConnection(HOST, CONSOLE_PORT, context=raw); c.request("GET", "/dl/ca.pem"); CA_PEM = c.getresponse().read()
ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem"); ca_file.write(CA_PEM); ca_file.close()
CA_DER_SHA = hashlib.sha256(x509.load_pem_x509_certificate(CA_PEM).public_bytes(serialization.Encoding.DER)).hexdigest()
ctx = ssl.create_default_context(cafile=ca_file.name)


class Console:
    def __init__(self):
        self.cookie = None

    def call(self, method, path, body=None, raw_body=False):
        con = http.client.HTTPSConnection(HOST, CONSOLE_PORT, context=ctx)
        h = {"Content-Type": "application/json"}
        if self.cookie:
            h["Cookie"] = self.cookie
        con.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = con.getresponse(); data = r.read()
        sc = r.getheader("Set-Cookie")
        if sc and "pdp_session=" in sc:
            self.cookie = sc.split(";", 1)[0]
        if raw_body:
            return r.status, {k.lower(): v for k, v in r.getheaders()}, data
        try:
            return r.status, json.loads(data or b"{}")
        except json.JSONDecodeError:
            return r.status, {"raw": data[:200]}


def agent_call(cert_dir, method, path, body=None, ndjson=None, headers=None):
    actx = ssl.create_default_context(cafile=ca_file.name)
    actx.load_cert_chain(os.path.join(cert_dir, "c.pem"), os.path.join(cert_dir, "k.pem"))
    con = http.client.HTTPSConnection(HOST, AGENT_PORT, context=actx)
    h = dict(headers or {})
    if ndjson is not None:
        data = gzip.compress("\n".join(json.dumps(r) for r in ndjson).encode()); h.update({"Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"})
    else:
        data = json.dumps(body).encode() if body is not None else None; h["Content-Type"] = "application/json"
    con.request(method, path, body=data, headers=h)
    r = con.getresponse(); out = r.read()
    try:
        return r.status, json.loads(out or b"{}")
    except json.JSONDecodeError:
        return r.status, {"raw": out[:200]}


def enroll(token):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil-claims-other-id")])).sign(key, hashes.SHA256())
    con = http.client.HTTPSConnection(HOST, CONSOLE_PORT, context=ctx)
    con.request("POST", "/v1/enroll", body=json.dumps({"token": token, "hostname": "e2e", "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}),
                headers={"Content-Type": "application/json"})
    r = con.getresponse(); js = json.loads(r.read())
    d = tempfile.mkdtemp()
    if r.status == 200:
        open(os.path.join(d, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        open(os.path.join(d, "c.pem"), "w").write(js["cert_pem"])
    return r.status, js, d


admin = Console()
pw = os.environ["PDP_ADMIN_PASSWORD"]
st, js = admin.call("POST", "/api/login", {"username": "admin", "password": pw})
check(st == 200 and js["role"] == "admin", "admin login")
st, js = admin.call("GET", "/api/me")
check(st == 200 and js["username"] == "admin" and js["role"] == "admin", "/api/me returns username and role")
check(Console().call("GET", "/api/endpoints")[0] == 401, "unauthenticated console call -> 401")
st, js = admin.call("GET", "/healthz")
check(st == 200 and js["ok"], "gateway /healthz")

# ---- users and roles
uname = "analyst" + uuid.uuid4().hex[:6]
st, js = admin.call("POST", "/api/users", {"username": uname, "password": "short", "role": "analyst"})
check(st == 400, "weak password rejected")
st, js = admin.call("POST", "/api/users", {"username": uname, "password": "analyst-pass-123", "role": "analyst"})
check(st == 200, "admin creates analyst"); uid = js.get("id")
analyst = Console()
check(analyst.call("POST", "/api/login", {"username": uname, "password": "analyst-pass-123"})[0] == 200, "analyst login")
check(analyst.call("POST", "/api/endpoints", {"name": "x"})[0] == 403, "analyst cannot create enrolment tokens")
check(analyst.call("GET", "/api/users")[0] == 403, "analyst cannot list users")
check(analyst.call("POST", "/api/me/password", {"old_password": "wrong", "new_password": "a-new-password-1"})[0] == 400, "password change needs the current password")
check(analyst.call("POST", "/api/me/password", {"old_password": "analyst-pass-123", "new_password": "a-new-password-1"})[0] == 200, "analyst changes own password")
check(Console().call("POST", "/api/login", {"username": uname, "password": "a-new-password-1"})[0] == 200, "new password works")
check(admin.call("DELETE", f"/api/users/{js and uid}")[0] == 200, "admin deletes user")
check(analyst.call("GET", "/api/endpoints")[0] == 401, "a deleted user's open session is refused at once")
st, auth_cfg = Console().call("GET", "/api/auth/config")
check(st == 200 and auth_cfg["password"] is True and "sso" in auth_cfg, "sign-in methods are published to the login page")
victim = "lockout" + uuid.uuid4().hex[:6]
admin.call("POST", "/api/users", {"username": victim, "password": "lockout-pass-789", "role": "analyst"})
bad = Console()
codes = [bad.call("POST", "/api/login", {"username": victim, "password": f"wrong-{i}"})[0] for i in range(6)]
check(codes[:5] == [401] * 5 and codes[5] == 429, "repeated failed sign-ins are throttled")
check(bad.call("POST", "/api/login", {"username": victim, "password": "lockout-pass-789"})[0] == 429, "even the right password waits out the back-off")
check(admin.call("GET", "/api/me")[0] == 200, "throttling one account does not affect others")
st, me = admin.call("GET", "/api/me")
check(admin.call("DELETE", f"/api/users/{me['user_id']}")[0] == 400, "admin cannot delete self")

# ---- enrolment token carries the CA fingerprint
st, tok = admin.call("POST", "/api/endpoints", {"name": "e2e-endpoint"})
check(st == 200 and tok["ca_sha256"] == CA_DER_SHA and tok["token"] in tok["enroll_command"] and "--ca-sha256" in tok["enroll_command"],
      "token response has the CA DER sha256 and a ready enrol command")
st, js, cert_dir = enroll(tok["token"])
check(st == 200 and js["config"]["baseline_days"] == 7, "agent enrolment over TLS")
eid = js["endpoint_id"]
cn = x509.load_pem_x509_certificate(js["cert_pem"].encode()).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
check(cn == eid, "client certificate CN is forced to the endpoint id (CSR subject ignored)")
check(enroll(tok["token"])[0] == 403, "enrolment token is single use")

# ---- agent protocol over mTLS
st, js = agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status")
check(st == 200 and js["phase"] == "baseline" and js["commands"] == [], "agent status over mTLS")
st, tok2 = admin.call("POST", "/api/endpoints", {"name": "e2e-other"})
_, js2, cert2 = enroll(tok2["token"])
other_test_eid = js2.get("endpoint_id")
check(agent_call(cert2, "GET", f"/v1/endpoints/{eid}/status")[0] == 403, "another endpoint's certificate is refused for this endpoint")
ents = [{"uuid": f"u{i}", "ntype": "file", "label": f"file /x{i}", "display": {}, "dense_id": i} for i in range(5)]
check(agent_call(cert_dir, "POST", f"/v1/endpoints/{eid}/entities", ndjson=ents)[0] == 200, "entities upload with dense ids")
evs = [{"ts_ns": 10**18 + i, "src": "u0", "op": "READ", "dst": "u1", "event_uuid": f"e{i}"} for i in range(3)]
st, js = agent_call(cert_dir, "POST", f"/v1/endpoints/{eid}/events", ndjson=evs, headers={"X-Batch-Id": "b1"})
st2, js2 = agent_call(cert_dir, "POST", f"/v1/endpoints/{eid}/events", ndjson=evs, headers={"X-Batch-Id": "b1"})
check(st == 200 and js2.get("duplicate") is True, "event batch upload is exactly-once by batch id")
hb = {"agent_version": "0.2.0", "queue_depth": 7, "last_window_end_ns": 123, "cpu_pct": 1.5, "rss_mb": 300.0}
check(agent_call(cert_dir, "POST", f"/v1/endpoints/{eid}/heartbeat", hb)[0] == 200, "heartbeat")
st, js = admin.call("GET", f"/api/endpoints/{eid}")
h = js["endpoint"]["health"] or {}
check(h.get("queue_depth") == 7 and h.get("rss_mb") == 300.0 and "at" in h and "hb" not in js["endpoint"]["config"], "heartbeat stored as endpoint health (not in config)")

# ---- config validation
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"fp_budget": "97"}})[0] == 400, "invalid fp_budget rejected")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"tz": "Mars/Base"}})[0] == 400, "invalid timezone rejected")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"train": {"nope": 1}}})[0] == 400, "unknown train key rejected")
st, js = admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"fp_budget": "99.9", "baseline_days": 3}})
check(st == 400 and "eason" in str(js), "0.6: a shorter baseline weakens detection and needs a reason")
st, js = admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"fp_budget": "99.9", "baseline_days": 3}, "reason": "e2e: short test baseline"})
check(st == 200 and js["config"]["fp_budget"] == "99.9", "valid config accepted")
check(admin.call("POST", "/api/sim/campaigns", {"name": "x", "endpoint_id": eid, "spec": {}})[0] == 409, "simulation refused without a bundle")

# ---- commands: queue -> delivered with id -> ack -> done (delivered once)
st, js = admin.call("POST", f"/api/endpoints/{eid}/commands", {"command": "refetch_bundle"})
check(st == 200, "admin queues a command"); cid = js["id"]
check(admin.call("POST", f"/api/endpoints/{eid}/commands", {"command": "rm -rf"})[0] == 400, "unknown command rejected")
st, js = agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status")
check([c.get("id") for c in js["commands"]] == [cid] and js["commands"][0]["command"] == "refetch_bundle", "agent receives the command with its id")
check(agent_call(cert_dir, "POST", f"/v1/endpoints/{eid}/commands/{cid}/ack", {"result": "ok"})[0] == 200, "agent acknowledges")
st, js = agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status")
check(js["commands"] == [], "acknowledged command is not delivered again")

# ---- alerts: export formats and status validation
st, hdr, body = admin.call("GET", f"/api/alerts/export?format=csv&endpoint_id={eid}", raw_body=True)
check(st == 200 and body.startswith(b"id,endpoint,hostname") and "attachment" in hdr.get("content-disposition", ""), "alert export CSV")
st, hdr, body = admin.call("GET", "/api/alerts/export?format=ndjson", raw_body=True)
check(st == 200 and "ndjson" in hdr.get("content-type", ""), "alert export NDJSON")
check(admin.call("GET", "/api/alerts/export?format=xml", raw_body=True)[0] == 400, "unknown export format rejected")
check(admin.call("POST", "/api/alerts/999999999", {"status": "pwned"})[0] == 400, "invalid alert status rejected")
check(admin.call("POST", "/api/alerts/999999999", {"status": "ack"})[0] == 404, "unknown alert -> 404")

# ---- layered alerts (0.3): layer / rule / reason stored, filterable, exported; layer-1 approvals
lay = [{"window_start_ns": 10**18, "node": {"uuid": "u2", "ntype": "subject", "label": "subject /tmp/.x /tmp/.x", "display": {}},
        "fused": 0.4, "r1": 0.3, "r2": 0.5, "context": {"nodes": [], "edges": []}, "layer": "novelty", "rule": "novel_executable",
        "reason": "runs /tmp/.x, which never ran during the baseline",
        "reasons": [{"layer": "novelty", "rule": "novel_executable", "key": "/tmp/.x", "detail": "runs /tmp/.x, which never ran during the baseline"}]},
       {"window_start_ns": 10**18, "node": {"uuid": "u3", "ntype": "file", "label": "file /x3", "display": {}},
        "fused": 2.5, "r1": 2.0, "r2": 3.0, "context": {"nodes": [], "edges": []}}]          # pre-0.3 agent: no layer fields
check(agent_call(cert_dir, "POST", f"/v1/endpoints/{eid}/alerts", ndjson=lay)[0] == 200, "layered alert upload (new and pre-0.3 agents)")
st, js = admin.call("GET", f"/api/alerts?endpoint_id={eid}")
by = {a["label"]: a for a in js["alerts"]}
check(by["subject /tmp/.x /tmp/.x"]["layer"] == "novelty" and "never ran" in by["subject /tmp/.x /tmp/.x"]["reason"] and by["file /x3"]["layer"] == "learned",
      "alerts list carries layer and reason (missing layer = learned)")
st, js = admin.call("GET", f"/api/alerts?endpoint_id={eid}&layer=novelty")
check([a["label"] for a in js["alerts"]] == ["subject /tmp/.x /tmp/.x"], "alerts filter by layer")
st, hdr, body = admin.call("GET", f"/api/alerts/export?format=csv&endpoint_id={eid}", raw_body=True)
check(b",layer,rule,reason," in body.split(b"\n")[0] and b"novel_executable" in body, "CSV export has layer / rule / reason")
# ---- access control: roles (admin / analyst / viewer) and endpoint scope
st, eps_all = admin.call("GET", "/api/endpoints")
other = next(e["id"] for e in eps_all["endpoints"] if e["id"] != eid)
other_alert = next((a["id"] for a in admin.call("GET", f"/api/alerts?endpoint_id={other}&limit=1")[1]["alerts"]), None)
st, incs = admin.call("GET", f"/api/incidents?endpoint_id={eid}")
check(st == 200 and incs["incidents"] and incs["incidents"][0]["endpoint_id"] == eid and "title" in incs["incidents"][0]
      and "fused" not in json.dumps(incs), "incidents group the endpoint's alerts, without scores")
inc_id = incs["incidents"][0]["id"]
st, inc = admin.call("GET", f"/api/incidents/{inc_id}")
check(st == 200 and inc["graph"]["nodes"] and inc["alerts"] and all("order" in e for e in inc["graph"]["edges"]),
      "incident detail has the attack graph, story and alerts")
vname = "viewer" + uuid.uuid4().hex[:6]
st, js = admin.call("POST", "/api/users", {"username": vname, "password": "viewer-pass-123", "role": "viewer", "display_name": "Vera Viewer",
                                          "endpoints": [eid]})
check(st == 200, "admin creates a viewer limited to one endpoint"); vid = js.get("id")
check(admin.call("POST", "/api/users", {"username": "x" + vname, "password": "viewer-pass-123", "role": "viewer", "endpoints": ["not-an-id"]})[0] == 400,
      "endpoint access must name real endpoints")
viewer = Console()
viewer.call("POST", "/api/login", {"username": vname, "password": "viewer-pass-123"})
st, m = viewer.call("GET", "/api/me")
check(st == 200 and m["role"] == "viewer" and m["can"] == {"manage_users": False, "manage_endpoints": False, "triage": False, "run_checks": False, "manage_org": False, "operate": False}
      and m["endpoints"] == [eid], "viewer: read-only permissions and endpoint scope in /api/me")
st, ve = viewer.call("GET", "/api/endpoints")
check(st == 200 and [e["id"] for e in ve["endpoints"]] == [eid], "a scoped user sees only their endpoints")
check(viewer.call("GET", f"/api/endpoints/{other}")[0] == 404 and viewer.call("GET", f"/api/endpoints/{other}/overview")[0] == 404,
      "other endpoints answer 404 (not 403) to a scoped user")
st, va = viewer.call("GET", "/api/alerts?limit=1000")
check(st == 200 and va["alerts"] and {a["endpoint_id"] for a in va["alerts"]} == {eid}, "alerts list is scoped")
check(viewer.call("GET", f"/api/alerts?endpoint_id={other}")[0] == 404, "alerts of another endpoint: 404")
st, vi = viewer.call("GET", "/api/incidents")
check(st == 200 and {i["endpoint_id"] for i in vi["incidents"]} == {eid}, "incidents list is scoped")
st, ov = viewer.call("GET", "/api/overview")
check(st == 200 and ov["endpoints"]["total"] == 1, "overview counts only visible endpoints")
st, hdr, body = viewer.call("GET", "/api/alerts/export?format=ndjson", raw_body=True)
check(st == 403, "0.6: viewers cannot bulk-export alerts (analysts and admins can, audited)")
if other_alert:
    check(viewer.call("GET", f"/api/alerts/{other_alert}/graph")[0] == 404, "another endpoint's alert graph: 404")
    check(viewer.call("GET", f"/api/incidents/{other_alert}")[0] == 404, "another endpoint's incident: 404")
check(viewer.call("GET", f"/api/incidents/{inc_id}")[0] == 200, "the viewer opens incidents of their endpoint")
check(viewer.call("POST", f"/api/incidents/{inc_id}/status", {"status": "investigating"})[0] == 403, "a viewer cannot triage incidents")
check(viewer.call("POST", f"/api/alerts/{inc['alerts'][0]['id']}", {"status": "ack"})[0] == 403, "a viewer cannot triage alerts")
check(viewer.call("POST", f"/api/endpoints/{eid}/checks")[0] == 403, "a viewer cannot run detection checks")
check(viewer.call("GET", "/api/users")[0] == 403 and viewer.call("GET", "/api/jobs")[0] == 403, "a viewer cannot see users or jobs")
st, _ = admin.call("PATCH", f"/api/users/{vid}", {"role": "analyst"})
st2, m = viewer.call("GET", "/api/me")
check(st == 200 and m["role"] == "analyst" and m["can"]["triage"], "role change applies to the open session")
check(viewer.call("POST", f"/api/incidents/{inc_id}/status", {"status": "investigating"})[0] == 200, "an analyst triages an incident")
st, inc2 = admin.call("GET", f"/api/incidents/{inc_id}")
check(inc2["incident"]["status"] == "investigating" and all(a["status"] == "ack" for a in inc2["alerts"]), "incident status applies to all its alerts")
if other_alert:
    check(viewer.call("POST", f"/api/alerts/{other_alert}", {"status": "ack"})[0] == 404, "a scoped analyst cannot triage other endpoints' alerts")
admin.call("PATCH", f"/api/users/{vid}", {"endpoints": None})
check(len(viewer.call("GET", "/api/endpoints")[1]["endpoints"]) == len(eps_all["endpoints"]), "endpoint access 'all' restores full visibility")
admin.call("PATCH", f"/api/users/{vid}", {"disabled": True})
check(viewer.call("GET", "/api/me")[0] == 401, "disabling a user ends their session")
check(Console().call("POST", "/api/login", {"username": vname, "password": "viewer-pass-123"})[0] == 401, "a disabled user cannot sign in")
st, me_ = admin.call("GET", "/api/me")
check(admin.call("PATCH", f"/api/users/{me_['user_id']}", {"role": "viewer"})[0] == 400, "an admin cannot remove their own admin access")
check(admin.call("PATCH", f"/api/users/{vid}", {"password": "short"})[0] == 400, "password reset enforces the minimum length")
check(admin.call("DELETE", f"/api/users/{vid}")[0] == 200, "admin removes the user")
admin.call("POST", f"/api/incidents/{inc_id}/status", {"status": "open"})

uname2 = "analyst" + uuid.uuid4().hex[:6]
admin.call("POST", "/api/users", {"username": uname2, "password": "analyst-pass-456", "role": "analyst"})
analyst = Console()
analyst.call("POST", "/api/login", {"username": uname2, "password": "analyst-pass-456"})
check(analyst.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["/tmp/.x"]})[0] == 403, "analyst cannot approve programs")
check(admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": [""] * 0 + [1]})[0] == 422, "approval payload validated")
check(admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["/tmp/.x"]})[0] == 400, "0.6: an approval needs a reason")
check(admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["tool"], "note": "e2e"})[0] == 400, "0.6: a program approval needs a full path")
check(admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["/bin/bash"], "note": "e2e"})[0] == 400, "0.6: approving a shell needs force")
st, js = admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["/tmp/.x", "/opt/app/bin/tool"], "note": "e2e"})
check(st == 200 and js["approved_executables"] == ["/opt/app/bin/tool", "/tmp/.x"], "admin approves programs")
st, js = admin.call("GET", f"/api/alerts?endpoint_id={eid}&layer=novelty")
check(js["alerts"][0]["status"] == "false_positive", "open novelty alerts of an approved program are resolved as false positives")
st, js = agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status")
check(js["config"].get("approved_executables") == ["/opt/app/bin/tool", "/tmp/.x"], "the agent receives the approvals with its configuration")
fsha = js["config"].get("fleet_sha")
check(js["config"].get("fleet_prevalence") == "drop" and isinstance(js["config"].get("fleet_programs"), dict) and fsha,
      "0.10: the agent receives the fleet prevalence setting, its fleet's programs and their hash")
st, js2 = agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status?fleet={fsha}")
check(st == 200 and "fleet_programs" not in js2["config"] and js2["config"].get("fleet_sha") == fsha,
      "0.10: an unchanged fleet program list is not sent again")
st, js = admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["/tmp/.x"], "approve": False, "note": "e2e"})
check(st == 200 and js["approved_executables"] == ["/opt/app/bin/tool"], "revoke an approval")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"learned_daily_budget": -1}})[0] == 400, "invalid learned budget rejected")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"learned_daily_budget": 5}})[0] == 200, "learned budget accepted")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"learned_alerts": "no"}})[0] == 400, "learned_alerts must be boolean")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"learned_alerts": False}})[0] == 200, "learned layer can be set to ranking only")

# ---- allow list
check(admin.call("POST", "/api/allowlist", {"kind": "address", "value": "10.0.0.0/8"})[0] == 400, "allow list refuses networks larger than /16")
check(admin.call("POST", "/api/allowlist", {"kind": "address", "value": "not-an-ip"})[0] == 400, "allow list validates addresses")
st, ae = admin.call("POST", "/api/allowlist", {"kind": "address", "value": "203.0.113.0/24", "endpoints": [eid], "note": "e2e"})
check(st == 200, "admin adds a network to the allow list")
check(admin.call("POST", "/api/allowlist", {"kind": "address", "value": "203.0.113.0/24", "endpoints": [eid], "note": "e2e"})[0] == 409, "duplicate entries are refused")
st, js = agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status")
check(st == 200 and "203.0.113.0/24" in js["config"]["trusted_addresses"], "the agent receives allow-listed addresses with its configuration")
check(admin.call("POST", "/api/allowlist", {"kind": "program", "value": "x-e2e-prog", "endpoints": [eid], "note": "e2e"})[0] == 400,
      "0.6: a bare program name is refused (it would match the name anywhere)")
st, ap = admin.call("POST", "/api/allowlist", {"kind": "program", "value": "/opt/x/x-e2e-prog", "endpoints": [eid], "note": "e2e"})
lay2 = [{"window_start_ns": 10**18 + 5, "node": {"uuid": "u9", "ntype": "subject", "label": "subject /opt/x/x-e2e-prog x-e2e-prog", "display": {}},
         "fused": 0.1, "r1": 0.1, "r2": 0.1, "context": {"nodes": [], "edges": []}, "layer": "novelty", "rule": "novel_executable",
         "reason": "runs /opt/x/x-e2e-prog, which never ran during the baseline",
         "reasons": [{"layer": "novelty", "rule": "novel_executable", "key": "/opt/x/x-e2e-prog", "detail": "..."}]}]
agent_call(cert_dir, "POST", f"/v1/endpoints/{eid}/alerts", ndjson=lay2)
st, al = admin.call("GET", f"/api/alerts?endpoint_id={eid}&limit=1000")
mine = [a for a in al["alerts"] if a["label"].startswith("subject /opt/x/x-e2e-prog")]
check(mine and mine[0]["allowed_by"] == ap["id"] and mine[0]["status"] == "false_positive",
      "an alert an older agent still raises for an allowed program (bare name) is marked as allowed at upload")
st, incs2 = admin.call("GET", f"/api/incidents?endpoint_id={eid}")
check(all(mine[0]["id"] not in [a["id"] for a in admin.call("GET", f"/api/incidents/{i['id']}")[1]["alerts"]] for i in incs2["incidents"]),
      "allowed alerts are not part of any incident")
check(admin.call("GET", f"/api/alerts/{mine[0]['id']}/allow-options")[0] == 200, "allow options for an alert")
st, lst = admin.call("GET", f"/api/allowlist?endpoint_id={eid}")
check(st == 200 and {e["id"] for e in lst["entries"]} >= {ae["id"], ap["id"]}, "allow list filtered by endpoint")
for e in (ae, ap):
    admin.call("DELETE", f"/api/allowlist/{e['id']}")
check(ae["id"] not in {e["id"] for e in admin.call("GET", "/api/allowlist")[1]["entries"]}, "allow-list entries can be removed")

# ---- install progress (one-line installer -> console) and deleting an endpoint
st, tok3 = admin.call("POST", "/api/endpoints", {"name": "e2e-install"})
key = tok3.get("progress_key", "")
def report(stage, detail=None, token=None):
    return Console().call("POST", "/api/public/install/progress", {"token": token or tok3["token"], "stage": stage, "detail": detail, "host": "web-e2e"})[0]
check(st == 200 and len(key) == 16, "an enrolment token comes with a progress key")
st, pr = admin.call("GET", f"/api/install-progress/{key}")
check(st == 200 and pr["installer"] == [] and pr["endpoint"] is None, "before the command runs: no progress yet")
check(report("started") == 200 and report("checks_ok", "x86_64, kernel 6.8") == 200, "the installer reports its stages with the token")
check(report("pwned") == 400 and report("started", token="not-a-real-token-123") == 404, "unknown stages and tokens are refused")
def report_bytes(done, total):
    return Console().call("POST", "/api/public/install/progress", {"token": tok3["token"], "stage": "downloading", "detail": "x",
                                                                   "done_bytes": done, "total_bytes": total})[0]
report("downloading", "3 of 12 layers"); time.sleep(1.1); report_bytes(120_000_000, 245_000_000)
st, pr = admin.call("GET", f"/api/install-progress/{key}")
stages = [e["stage"] for e in pr["installer"]]
dl = pr["installer"][-1]
check(stages == ["started", "checks_ok", "downloading"] and dl["done_bytes"] == 120_000_000 and dl["total_bytes"] == 245_000_000
      and dl["since"] < dl["at"] and pr["installer"][0]["host"] == "web-e2e",
      f"the console sees the stages; download bytes updated in place, with when it started ({stages})")
check(report_bytes(-1, 5) == 422, "negative byte counts are refused")
check(Console().call("GET", f"/api/install-progress/{key}")[0] == 401 and admin.call("GET", "/api/install-progress/0000000000000000")[0] == 404,
      "progress needs a session and a known key")
st, js3, cert3 = enroll(tok3["token"])
eid3 = js3.get("endpoint_id")
agent_call(cert3, "POST", f"/v1/endpoints/{eid3}/heartbeat", hb)
st, pr = admin.call("GET", f"/api/install-progress/{key}")
check(st == 200 and pr["endpoint"] and pr["endpoint"]["id"] == eid3 and pr["endpoint"]["reporting"] is True and pr["endpoint"]["first_data_at"] is None,
      "after enrolment the console follows the endpoint itself (reporting, no data yet)")
check(report("enrolled") == 200 and report("failed", "late") == 200, "the installer can still report until the token expires")
check(admin.call("DELETE", f"/api/endpoints/{eid3}")[0] == 200, "admin deletes the endpoint permanently")
check(admin.call("GET", f"/api/endpoints/{eid3}")[0] == 404 and eid3 not in [e["id"] for e in admin.call("GET", "/api/endpoints")[1]["endpoints"]],
      "a deleted endpoint is gone, retired list included")
check(agent_call(cert3, "GET", f"/v1/endpoints/{eid3}/status")[0] in (401, 403, 404), "the deleted endpoint's agent is refused")
check(admin.call("DELETE", f"/api/endpoints/{eid3}")[0] == 404, "deleting twice: 404")
check(admin.call("GET", f"/api/install-progress/{key}")[1]["endpoint"] is None, "progress of a deleted endpoint no longer links to it")

# ---- retire
check(admin.call("POST", f"/api/endpoints/{eid}/retire")[0] == 200, "retire endpoint")
admin.call("POST", f"/api/endpoints/{other_test_eid}/retire")      # the second test endpoint as well
for u in admin.call("GET", "/api/users")[1]["users"]:                 # and the test users
    if u["username"] in (uname2, victim):
        admin.call("DELETE", f"/api/users/{u['id']}")
check(agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status")[0] == 404, "retired endpoint's agent is refused")
admin.call("POST", f"/api/endpoints/{js2 and js2.get('endpoint_id') or ''}/retire")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
