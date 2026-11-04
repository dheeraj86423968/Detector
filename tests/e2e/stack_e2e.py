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
check(analyst.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["/tmp/.x"]})[0] == 403, "analyst cannot approve programs")
check(admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": [""] * 0 + [1]})[0] == 422, "approval payload validated")
st, js = admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["/tmp/.x", "/opt/app/bin/tool"]})
check(st == 200 and js["approved_executables"] == ["/opt/app/bin/tool", "/tmp/.x"], "admin approves programs")
st, js = admin.call("GET", f"/api/alerts?endpoint_id={eid}&layer=novelty")
check(js["alerts"][0]["status"] == "false_positive", "open novelty alerts of an approved program are resolved as false positives")
st, js = agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status")
check(js["config"].get("approved_executables") == ["/opt/app/bin/tool", "/tmp/.x"], "the agent receives the approvals with its configuration")
st, js = admin.call("POST", f"/api/endpoints/{eid}/approved-executables", {"executables": ["/tmp/.x"], "approve": False})
check(st == 200 and js["approved_executables"] == ["/opt/app/bin/tool"], "revoke an approval")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"learned_daily_budget": -1}})[0] == 400, "invalid learned budget rejected")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"learned_daily_budget": 5}})[0] == 200, "learned budget accepted")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"learned_alerts": "no"}})[0] == 400, "learned_alerts must be boolean")
check(admin.call("POST", f"/api/endpoints/{eid}/config", {"config": {"learned_alerts": False}})[0] == 200, "learned layer can be set to ranking only")

# ---- retire
check(admin.call("POST", f"/api/endpoints/{eid}/retire")[0] == 200, "retire endpoint")
check(agent_call(cert_dir, "GET", f"/v1/endpoints/{eid}/status")[0] == 404, "retired endpoint's agent is refused")
admin.call("POST", f"/api/endpoints/{js2 and js2.get('endpoint_id') or ''}/retire")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
