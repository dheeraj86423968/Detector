"""End-to-end check of the console fleet controls (0.10.1) through the real gateway: the fleet summary on the endpoint
page, setting and clearing a fleet name, the prevalence mode and the endpoint count, and which of those changes ask
for a reason (weakening) - as the console's Settings tab sends them.

  docker run --rm --network pdp-staging_edge -v $PWD:/src:ro -w /src -e PDP_ADMIN_PASSWORD=<pw> \
    --entrypoint python pdp/agent:dev tests/e2e/fleet_e2e.py
"""
import hashlib  # noqa: F401
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
PORT = 443
fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg, flush=True)
    fails += 0 if cond else 1


raw = ssl.create_default_context(); raw.check_hostname = False; raw.verify_mode = ssl.CERT_NONE
c = http.client.HTTPSConnection(HOST, PORT, context=raw); c.request("GET", "/dl/ca.pem"); CA_PEM = c.getresponse().read()
ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem"); ca_file.write(CA_PEM); ca_file.close()
ctx = ssl.create_default_context(cafile=ca_file.name)
cookie = None


def call(method, path, body=None):
    global cookie
    con = http.client.HTTPSConnection(HOST, PORT, context=ctx)
    h = {"Content-Type": "application/json", **({"Cookie": cookie} if cookie else {})}
    con.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
    r = con.getresponse(); data = r.read()
    sc = r.getheader("Set-Cookie")
    if sc and "pdp_session=" in sc:
        cookie = sc.split(";", 1)[0]
    try:
        return r.status, json.loads(data or b"{}")
    except json.JSONDecodeError:
        return r.status, {"raw": data[:200]}


def enroll(token):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(key, hashes.SHA256())
    con = http.client.HTTPSConnection(HOST, PORT, context=ctx)
    con.request("POST", "/v1/enroll", body=json.dumps({"token": token, "hostname": "fleet-e2e", "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}),
                headers={"Content-Type": "application/json"})
    r = con.getresponse()
    return r.status, json.loads(r.read())


st, js = call("POST", "/api/login", {"username": "admin", "password": os.environ["PDP_ADMIN_PASSWORD"]})
check(st == 200, "admin login")
tag = uuid.uuid4().hex[:6]
eids = []
for n in ("a", "b"):
    st, tok = call("POST", "/api/endpoints", {"name": f"fleet-e2e-{tag}-{n}"})
    st2, js = enroll(tok.get("token", ""))
    check(st == 200 and st2 == 200, f"endpoint {n} enrolled")
    eids.append(js.get("endpoint_id"))
a, b = eids


def fleet(eid):
    return call("GET", f"/api/endpoints/{eid}")[1].get("fleet") or {}


def cfg(eid, config, reason=None):
    return call("POST", f"/api/endpoints/{eid}/config", {"config": config, **({"reason": reason} if reason else {})})


try:
    f = fleet(a)
    check(f.get("label") == "org" and f.get("named") is None and f.get("mode") == "drop" and f.get("min_endpoints") == 2
          and f.get("defaults") == {"mode": "drop", "min_endpoints": 2}, f"a live endpoint is in its organisation's fleet with the defaults ({f})")
    check(b in {m["id"] for m in f.get("members", [])} and a not in {m["id"] for m in f.get("members", [])},
          "members: the other live endpoints, not itself")
    check(f.get("known_programs") == 0 and f.get("trained_members", -1) >= 0, "no baselines yet: no programs known")

    st, js = cfg(a, {"fleet": "servers"})
    check(st == 400 and "reason" in json.dumps(js).lower(), "joining another fleet asks for a reason")
    st, _ = cfg(a, {"fleet": "servers"}, "e2e: servers apart from workstations")
    f = fleet(a)
    check(st == 200 and f.get("label") == "servers" and f.get("named") == "servers" and b not in {m["id"] for m in f.get("members", [])},
          "named fleet: b (organisation fleet) is no longer a member")
    check(a not in {m["id"] for m in fleet(b).get("members", [])}, "and a left b's fleet")

    check(cfg(a, {"fleet_prevalence": "evidence"})[0] == 200 and fleet(a).get("mode") == "evidence", "drop -> evidence (stricter): no reason")
    check(cfg(a, {"fleet_prevalence": "off"})[0] == 200 and fleet(a).get("mode") == "off", "evidence -> off (stricter): no reason")
    check(cfg(a, {"fleet_min_endpoints": 1})[0] == 200, "fewer endpoints while prevalence is off: no reason (nothing is dropped)")
    check(cfg(a, {"fleet_prevalence": "drop"})[0] == 400, "off -> drop asks for a reason")
    check(cfg(a, {"fleet_prevalence": "drop", "fleet_min_endpoints": 3}, "e2e")[0] == 200 and fleet(a).get("min_endpoints") == 3, "with a reason: applied")
    check(cfg(a, {"fleet_min_endpoints": 2})[0] == 400, "3 -> 2 endpoints asks for a reason")
    check(cfg(a, {"fleet_min_endpoints": 0})[0] in (400, 422) and cfg(a, {"fleet": "bad;name"})[0] in (400, 422), "invalid values refused")

    st, js = cfg(a, {"fleet": None})
    check(st == 400, "clearing the name of a live endpoint joins the organisation fleet: asks for a reason")
    st, _ = cfg(a, {"fleet": None}, "e2e: back to the organisation fleet")
    f = fleet(a)
    check(st == 200 and f.get("label") == "org" and f.get("named") is None and b in {m["id"] for m in f.get("members", [])},
          "name cleared: back in the organisation fleet with b")
finally:
    for e in eids:
        if e:
            call("DELETE", f"/api/endpoints/{e}")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
