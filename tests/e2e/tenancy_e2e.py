"""Multi-tenant isolation, sign-up, invites, endpoint limits and operator controls, against a running stack.

  docker run --rm --network pdp_edge -v $PWD:/src:ro -w /src -e PDP_ADMIN_PASSWORD=<operator pw> \
      -e PDP_SIGNUP_CODE=<code> --entrypoint python pdp/server:dev tests/e2e/tenancy_e2e.py

Creates two client organisations (A and B), checks that neither can see or touch the other's or the internal
organisation's data through any console route, then deletes both (operator offboarding).
"""
import gzip
import hashlib
import http.client
import json
import os
import secrets
import ssl
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST = os.environ.get("PDP_GATEWAY", "gateway")
fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg, flush=True)
    fails += 0 if cond else 1


raw = ssl.create_default_context(); raw.check_hostname = False; raw.verify_mode = ssl.CERT_NONE
c0 = http.client.HTTPSConnection(HOST, 443, context=raw); c0.request("GET", "/dl/ca.pem"); CA_PEM = c0.getresponse().read()
ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem"); ca_file.write(CA_PEM); ca_file.close()
ctx = ssl.create_default_context(cafile=ca_file.name)


class Console:
    def __init__(self):
        self.cookie = None

    def call(self, method, path, body=None):
        con = http.client.HTTPSConnection(HOST, 443, context=ctx)
        h = {"Content-Type": "application/json"}
        if self.cookie:
            h["Cookie"] = self.cookie
        con.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = con.getresponse(); data = r.read()
        sc = r.getheader("Set-Cookie")
        if sc and "pdp_session=" in sc:
            self.cookie = sc.split(";", 1)[0]
        try:
            return r.status, json.loads(data or b"{}")
        except json.JSONDecodeError:
            return r.status, {"raw": data[:200]}


def enroll(token):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(key, hashes.SHA256())
    con = http.client.HTTPSConnection(HOST, 443, context=ctx)
    con.request("POST", "/v1/enroll", body=json.dumps({"token": token, "hostname": "tenant-e2e", "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}),
                headers={"Content-Type": "application/json"})
    r = con.getresponse(); js = json.loads(r.read())
    d = tempfile.mkdtemp()
    if r.status == 200:
        open(os.path.join(d, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        open(os.path.join(d, "c.pem"), "w").write(js["cert_pem"])
    return r.status, js, d


def agent_call(cert_dir, method, path, body=None, ndjson=None):
    actx = ssl.create_default_context(cafile=ca_file.name)
    actx.load_cert_chain(os.path.join(cert_dir, "c.pem"), os.path.join(cert_dir, "k.pem"))
    con = http.client.HTTPSConnection(HOST, 8443, context=actx)
    h = {}
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


run = secrets.token_hex(3)
CODE = os.environ.get("PDP_SIGNUP_CODE", "")
op = Console()
st, _ = op.call("POST", "/api/login", {"username": "admin", "password": os.environ["PDP_ADMIN_PASSWORD"]})
check(st == 200, "operator signs in")
st, me = op.call("GET", "/api/me")
check(me.get("operator") is True and me["can"].get("operate") and me.get("org", {}).get("name"), f"operator flag and organisation in /api/me ({me.get('org')})")
internal_eps = [e["id"] for e in op.call("GET", "/api/endpoints")[1]["endpoints"]]
internal_incs = op.call("GET", "/api/incidents?status=all&limit=5")[1]["incidents"]
internal_alerts = op.call("GET", "/api/alerts?limit=5")[1].get("alerts", [])
check(len(internal_eps) > 0, f"internal organisation has endpoints to protect ({len(internal_eps)})")
victim_ep = internal_eps[0]

# ---------------------------------------------------------------- sign-up
st, cfg = Console().call("GET", "/api/auth/config")
check(cfg.get("signup") in ("code", "open"), f"sign-up advertised ({cfg.get('signup')})")
st, _ = Console().call("POST", "/api/signup", {"organisation": "Nope", "name": "N", "email": f"n-{run}@example.com", "password": "long-password-1", "code": "wrong"})
check(st == 403 if cfg["signup"] == "code" else True, "wrong sign-up code refused")
A, B = Console(), Console()
emailA, emailB = f"alice-{run}@a-corp.example", f"bob-{run}@b-corp.example"
st, js = A.call("POST", "/api/signup", {"organisation": f"A Corp {run}", "name": "Alice", "email": emailA, "password": "alice-password-1", "code": CODE})
check(st == 200 and js.get("role") == "admin" and js["org"]["name"] == f"A Corp {run}" and not js.get("operator"), f"organisation A signs up, its first user is admin ({st})")
st, js = B.call("POST", "/api/signup", {"organisation": f"B Corp {run}", "name": "Bob", "email": emailB, "password": "bob-password-12", "code": CODE})
check(st == 200 and js["org"]["name"] == f"B Corp {run}", "organisation B signs up")
st, _ = Console().call("POST", "/api/signup", {"organisation": "Dup", "name": "D", "email": emailA.upper(), "password": "long-password-1", "code": CODE})
check(st == 409, "an email can register only once (case-insensitive)")
st, _ = Console().call("POST", "/api/signup", {"organisation": "X", "name": "X", "email": "not-an-email", "password": "long-password-1", "code": CODE})
check(st == 400, "invalid email refused")
st, _ = Console().call("POST", "/api/signup", {"organisation": "X Corp", "name": "X", "email": f"x-{run}@x.example", "password": "short", "code": CODE})
check(st == 400, f"short password refused ({st})")
st, js = Console().call("POST", "/api/login", {"username": emailA, "password": "alice-password-1"})
check(st == 200, "sign in with email")
orgA = A.call("GET", "/api/me")[1]["org"]["id"]; orgB = B.call("GET", "/api/me")[1]["org"]["id"]

# ---------------------------------------------------------------- a new organisation sees nothing of anyone else
check(A.call("GET", "/api/endpoints")[1]["endpoints"] == [], "A sees no endpoints")
check(A.call("GET", "/api/incidents?status=all")[1]["incidents"] == [], "A sees no incidents")
check(A.call("GET", "/api/alerts")[1].get("alerts", []) == [], "A sees no alerts")
st, ov = A.call("GET", "/api/overview")
check(st == 200 and ov["endpoints"]["total"] == 0 and ov["incidents"]["open"] == 0, "A's overview is empty")
check([u["username"] for u in A.call("GET", "/api/users")[1]["users"]] == [emailA], "A's user list holds only A's users")
check(A.call("GET", "/api/allowlist")[1]["entries"] == [], "A's allow list is empty")
check(A.call("GET", "/api/jobs")[1].get("jobs", []) == [], "A sees no jobs")
check(A.call("GET", "/api/sim/campaigns")[1].get("campaigns", []) == [], "A sees no detection checks")

# every endpoint-keyed route answers 404 for another organisation's endpoint
probes = [("GET", f"/api/endpoints/{victim_ep}", None), ("GET", f"/api/endpoints/{victim_ep}/overview", None),
          ("GET", f"/api/endpoints/{victim_ep}/checks", None), ("POST", f"/api/endpoints/{victim_ep}/checks", {}),
          ("POST", f"/api/endpoints/{victim_ep}/config", {"config": {"fp_budget": "99"}}),
          ("POST", f"/api/endpoints/{victim_ep}/approved-executables", {"executables": ["/bin/x"], "approve": True}),
          ("POST", f"/api/endpoints/{victim_ep}/commands", {"command": "refetch_bundle"}),
          ("POST", f"/api/endpoints/{victim_ep}/retrain", {}), ("GET", f"/api/endpoints/{victim_ep}/incident", None),
          ("GET", f"/api/incidents?endpoint_id={victim_ep}", None), ("GET", f"/api/alerts?endpoint_id={victim_ep}", None),
          ("GET", f"/api/allowlist?endpoint_id={victim_ep}", None), ("GET", f"/api/alerts/export?endpoint_id={victim_ep}", None),
          ("POST", "/api/sim/campaigns", {"name": "probe", "endpoint_id": victim_ep, "spec": {}}),
          ("POST", f"/api/endpoints/{victim_ep}/retire", {})]
for m, path, body in probes:
    st, _ = A.call(m, path, body)
    check(st == 404, f"A: {m} {path.replace(victim_ep, '<internal endpoint>')} -> 404 ({st})")
st, ep_after = op.call("GET", f"/api/endpoints/{victim_ep}")
check(st == 200 and ep_after["endpoint"]["phase"] != "retired", "internal endpoint untouched after A's attempts")
if internal_incs:
    iid = internal_incs[0]["id"]
    check(A.call("GET", f"/api/incidents/{iid}")[0] == 404, "A cannot open an internal incident")
    check(A.call("POST", f"/api/incidents/{iid}/status", {"status": "resolved"})[0] == 404, "A cannot triage an internal incident")
if internal_alerts:
    aid = internal_alerts[0]["id"]
    check(A.call("GET", f"/api/alerts/{aid}/graph")[0] == 404, "A cannot open an internal alert graph")
    check(A.call("POST", f"/api/alerts/{aid}", {"status": "closed"})[0] == 404, "A cannot change an internal alert")
    check(A.call("GET", f"/api/alerts/{aid}/allow-options")[0] == 404, "A cannot read an internal alert's allow options")
st, _ = A.call("POST", "/api/users", {"username": f"sneaky-{run}", "password": "sneaky-password-1", "role": "viewer", "endpoints": [victim_ep]})
check(st == 400, "A cannot grant a user access to another organisation's endpoint")
st, _ = A.call("POST", "/api/allowlist", {"kind": "program", "value": "/bin/x", "endpoints": [victim_ep]})
check(st == 400, "A cannot add an allow-list entry for another organisation's endpoint")
op_users = op.call("GET", "/api/users")[1]["users"]
victim_user = next(u for u in op_users if u["username"] != "admin")["id"] if len(op_users) > 1 else op_users[0]["id"]
check(A.call("PATCH", f"/api/users/{victim_user}", {"role": "admin"})[0] == 404, "A cannot change an internal user")
check(A.call("DELETE", f"/api/users/{victim_user}")[0] == 404, "A cannot delete an internal user")
check(A.call("GET", "/api/operator/orgs")[0] == 404, "the operator view is not visible to clients")
check(A.call("POST", "/api/endpoints", {"name": "bench", "kind": "benchmark", "dataset": "cadets"})[0] == 403, "clients cannot create benchmark endpoints")

# ---------------------------------------------------------------- enrolment, agent data and the allow list stay in the organisation
st, tok = A.call("POST", "/api/endpoints", {"name": f"a-web-{run}"})
check(st == 200 and tok["install_command"].startswith("curl -fsSL https://") and "/install.sh | sudo bash -s -- --token " + tok["token"] in tok["install_command"],
      f"one-line install command ({tok.get('install_command', '')[:60]}...)")
st, js, certA = enroll(tok["token"])
check(st == 200, "A's agent enrols")
epA = js["endpoint_id"]
check([e["id"] for e in A.call("GET", "/api/endpoints")[1]["endpoints"]] == [epA], "A sees its endpoint")
check(epA not in [e["id"] for e in B.call("GET", "/api/endpoints")[1]["endpoints"]], "B does not see A's endpoint")
check(epA not in [e["id"] for e in op.call("GET", "/api/endpoints")[1]["endpoints"]], "the operator does not see A's endpoint among its own")
check(B.call("GET", f"/api/endpoints/{epA}")[0] == 404 and op.call("GET", f"/api/endpoints/{epA}/overview")[0] == 404,
      "B and the operator get 404 for A's endpoint")
# an alert from A's agent stays in A
alert = {"window_start_ns": 1_700_000_000_000_000_000, "node": {"uuid": "proc:tenant:1", "ntype": "subject", "label": "subject /tmp/.x/kworker kworker"},
         "fused": 1.0, "r1": 1.0, "r2": 1.0, "layer": "novelty", "rule": "novel_executable",
         "reason": "runs /tmp/.x/kworker, which never ran during the baseline",
         "reasons": [{"rule": "novel_executable", "key": "/tmp/.x/kworker"}], "context": {"nodes": [], "edges": []}}
st, _ = agent_call(certA, "POST", f"/v1/endpoints/{epA}/alerts", ndjson=[alert])
check(st == 200, f"A's agent uploads an alert ({st})")
a_alerts = A.call("GET", "/api/alerts")[1].get("alerts", [])
check(len(a_alerts) == 1 and a_alerts[0]["endpoint_id"] == epA, "A sees its alert")
check(all(x["endpoint_id"] != epA for x in B.call("GET", "/api/alerts")[1].get("alerts", [])), "B does not see A's alert")
check(all(x["endpoint_id"] != epA for x in op.call("GET", "/api/alerts?limit=1000")[1].get("alerts", [])), "the operator does not see A's alert")
a_inc = A.call("GET", "/api/incidents?status=all")[1]["incidents"]
check(len(a_inc) == 1, "A's alert forms an incident for A")
if a_inc:
    check(B.call("GET", f"/api/incidents/{a_inc[0]['id']}")[0] == 404, "B cannot open A's incident")
# allow-list entry for all of A's endpoints does not reach B or the internal organisation
st, js = A.call("POST", "/api/allowlist", {"kind": "address", "value": "198.51.100.0/24", "endpoints": None, "note": "tenant test"})
check(st == 200, "A adds an allow-list entry for all its endpoints")
st, stat = agent_call(certA, "GET", f"/v1/endpoints/{epA}/status")
check(st == 200 and "198.51.100.0/24" in stat.get("config", {}).get("trusted_addresses", []), "A's agent receives A's entry")
check(B.call("GET", "/api/allowlist")[1]["entries"] == [] and
      all(e.get("note") != "tenant test" for e in op.call("GET", "/api/allowlist")[1]["entries"]), "B and the operator do not see A's entry")
st, tokB = B.call("POST", "/api/endpoints", {"name": f"b-db-{run}"})
st, js, certB = enroll(tokB["token"])
epB = js.get("endpoint_id")
st, statB = agent_call(certB, "GET", f"/v1/endpoints/{epB}/status")
check(st == 200 and "198.51.100.0/24" not in statB.get("config", {}).get("trusted_addresses", []), "B's agent does not receive A's entry")
check(agent_call(certA, "GET", f"/v1/endpoints/{epB}/status")[0] == 403, "A's agent certificate cannot act for B's endpoint")

# ---------------------------------------------------------------- invites
st, inv = A.call("POST", "/api/invites", {"role": "viewer", "endpoints": [epA]})
check(st == 200 and "/#/join/" in inv["invite"]["link"], "A creates an invite link")
token = inv["invite"]["link"].rsplit("/", 1)[1]
st, info = Console().call("GET", f"/api/invites/{token}")
check(st == 200 and info["organisation"] == f"A Corp {run}" and info["role"] == "viewer", "invite shows organisation and role publicly")
check(B.call("DELETE", f"/api/invites/{inv['invite']['id']}")[0] == 404, "B cannot revoke A's invite")
check(len(B.call("GET", "/api/invites")[1]["invites"]) == 0, "B does not see A's invites")
V = Console()
st, js = V.call("POST", f"/api/invites/{token}/accept", {"name": "Vera", "email": f"vera-{run}@a-corp.example", "password": "vera-password-1"})
check(st == 200 and js["org"]["id"] == orgA and js["role"] == "viewer", "invite accepted: viewer in A")
check([e["id"] for e in V.call("GET", "/api/endpoints")[1]["endpoints"]] == [epA], "the invited viewer sees A's endpoint")
check(V.call("POST", "/api/invites", {"role": "admin"})[0] == 403, "a viewer cannot invite")
check(Console().call("POST", f"/api/invites/{token}/accept", {"name": "Eve", "email": f"eve-{run}@x.example", "password": "eve-password-12"})[0] == 404,
      "an invite works once")
st, inv2 = A.call("POST", "/api/invites", {"email": f"fixed-{run}@a-corp.example", "role": "analyst", "endpoints": None})
t2 = inv2["invite"]["link"].rsplit("/", 1)[1]
check(Console().call("POST", f"/api/invites/{t2}/accept", {"name": "Mallory", "email": f"other-{run}@x.example", "password": "mallory-pass-1"})[0] == 400,
      "an invite for a named email cannot be used with another email")
check(A.call("DELETE", f"/api/invites/{inv2['invite']['id']}")[0] == 200 and Console().call("GET", f"/api/invites/{t2}")[0] == 404, "a revoked invite is dead")

# ---------------------------------------------------------------- endpoint limit, disable, offboarding
orgs = op.call("GET", "/api/operator/orgs")[1]
rowA = next((o for o in orgs["orgs"] if o["id"] == orgA), None)
check(rowA is not None and rowA["endpoints"] == 1 and rowA["users"] == 2, f"operator sees A's usage ({rowA and (rowA['endpoints'], rowA['users'])})")
check(all("alerts" not in o and "incidents" not in o for o in orgs["orgs"]), "the operator view carries usage, not data")
check(op.call("PATCH", f"/api/operator/orgs/{orgA}", {"max_endpoints": 1})[0] == 200, "operator sets A's endpoint limit to 1")
st, js = A.call("POST", "/api/endpoints", {"name": "one-too-many"})
check(st == 403 and "limit of 1" in str(js), "A cannot exceed its endpoint limit")
check(op.call("PATCH", f"/api/operator/orgs/{orgB}", {"disabled": True})[0] == 200, "operator disables B")
check(B.call("GET", "/api/me")[0] == 401, "B's session ends")
check(Console().call("POST", "/api/login", {"username": emailB, "password": "bob-password-12"})[0] == 403, "B cannot sign in while disabled")
check(op.call("DELETE", f"/api/operator/orgs/{orgA}")[0] == 400, "an enabled organisation cannot be deleted")
internal_org = me["org"]["id"]
check(op.call("PATCH", f"/api/operator/orgs/{internal_org}", {"disabled": True})[0] == 400, "the internal organisation cannot be disabled")
for org in (orgA, orgB):
    op.call("PATCH", f"/api/operator/orgs/{org}", {"disabled": True})
    st, js = op.call("DELETE", f"/api/operator/orgs/{org}")
    check(st == 200, f"operator offboards {'A' if org == orgA else 'B'} ({js.get('endpoints_deleted')} endpoint deleted)")
check(all(o["id"] not in (orgA, orgB) for o in op.call("GET", "/api/operator/orgs")[1]["orgs"]), "both test organisations are gone")
check(agent_call(certA, "GET", f"/v1/endpoints/{epA}/status")[0] in (403, 404), "a deleted organisation's agent is refused")
check(Console().call("POST", "/api/login", {"username": emailA, "password": "alice-password-1"})[0] == 401, "a deleted organisation's users are gone")
check(sorted(e["id"] for e in op.call("GET", "/api/endpoints")[1]["endpoints"]) == sorted(internal_eps), "internal endpoints unchanged")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
