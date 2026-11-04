"""Threat hunting on a stack (staging): a search reaches the organisation's reporting 0.3.17+ agents as a command, their
answers come back per endpoint, older agents are skipped, another organisation can neither see the search nor answer it,
viewers cannot start one (run with the gateway reachable, like triage_e2e.py)."""
import gzip
import http.client
import json
import os
import secrets
import ssl
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST = os.environ.get("PDP_GATEWAY", "gateway")
fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg, flush=True)
    fails += 0 if ok else 1


raw = ssl.create_default_context(); raw.check_hostname = False; raw.verify_mode = ssl.CERT_NONE
c0 = http.client.HTTPSConnection(HOST, 443, context=raw); c0.request("GET", "/dl/ca.pem"); CA = c0.getresponse().read()
caf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem"); caf.write(CA); caf.close()
ctx = ssl.create_default_context(cafile=caf.name)


class Console:
    def __init__(self):
        self.cookie = None

    def call(self, method, path, body=None):
        con = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=60)
        h = {"Content-Type": "application/json", **({"Cookie": self.cookie} if self.cookie else {})}
        con.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = con.getresponse(); data = r.read()
        sc = r.getheader("Set-Cookie")
        if sc and "pdp_session=" in sc:
            self.cookie = sc.split(";", 1)[0]
        return r.status, json.loads(data or b"{}")




def enroll(console, name, version):
    st, tok = console.call("POST", "/api/endpoints", {"name": name})
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(key, hashes.SHA256())
    con = http.client.HTTPSConnection(HOST, 8443, context=ctx)
    con.request("POST", "/v1/enroll", body=json.dumps({"token": tok["token"], "hostname": name, "agent_version": version,
                                                       "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}), headers={"Content-Type": "application/json"})
    enr = json.loads(con.getresponse().read())
    d = tempfile.mkdtemp()
    open(os.path.join(d, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(os.path.join(d, "c.pem"), "w").write(enr["cert_pem"])
    actx = ssl.create_default_context(cafile=caf.name); actx.load_cert_chain(os.path.join(d, "c.pem"), os.path.join(d, "k.pem"))
    ag = Agent(enr["endpoint_id"], actx)
    ag.call("POST", "heartbeat", {"agent_version": version, "queue_depth": 0})
    return ag


class Agent:
    def __init__(self, eid, actx):
        self.eid, self.actx = eid, actx

    def call(self, method, sub, body=None, ndjson=None, eid=None):
        con = http.client.HTTPSConnection(HOST, 8443, context=self.actx, timeout=60)
        if ndjson is not None:
            data, h = gzip.compress("\n".join(json.dumps(r) for r in ndjson).encode()), {"Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"}
        else:
            data, h = (json.dumps(body).encode() if body is not None else None), {"Content-Type": "application/json"}
        con.request(method, f"/v1/endpoints/{eid or self.eid}/{sub}", body=data, headers=h)
        r = con.getresponse(); out = r.read()
        try:
            return r.status, json.loads(out or b"{}")
        except ValueError:
            return r.status, {}

    def hunt_cmds(self):
        return [c for c in self.call("GET", "status")[1].get("commands", []) if c.get("command") == "hunt"]


run = secrets.token_hex(3)
A, B = Console(), Console()
check(A.call("POST", "/api/signup", {"organisation": f"Hunt A {run}", "name": "Alice", "email": f"ha-{run}@a.example", "password": "hunt-password-1", "code": "x"})[0] == 200, "organisation A signs up")
time.sleep(2)
check(B.call("POST", "/api/signup", {"organisation": f"Hunt B {run}", "name": "Bob", "email": f"hb-{run}@b.example", "password": "hunt-password-2", "code": "x"})[0] == 200, "organisation B signs up")
new1, new2, old = enroll(A, f"web-{run}", "0.3.17"), enroll(A, f"db-{run}", "0.3.18"), enroll(A, f"legacy-{run}", "0.3.16")
other = enroll(B, f"b-{run}", "0.3.17")

check(A.call("POST", "/api/hunts", {"q": "x"})[0] == 422 and A.call("POST", "/api/hunts", {"q": "curl", "kind": "dns"})[0] == 400, "too-short query and unknown kind refused")
st, h = A.call("POST", "/api/hunts", {"q": "203.0.113.9", "kind": None})
check(st == 200 and h["endpoints"] == 2 and h["skipped"] == 1, f"hunt sent to the two 0.3.17+ agents, the 0.3.16 agent skipped ({h})")
hid = h["id"]
c1, c2, c0, cb = new1.hunt_cmds(), new2.hunt_cmds(), old.hunt_cmds(), other.hunt_cmds()
check(len(c1) == 1 and c1[0]["hunt_id"] == hid and c1[0]["q"] == "203.0.113.9" and len(c2) == 1 and c0 == [] and cb == [],
      "each new agent got the hunt command; the old agent and organisation B's agent got nothing")

t = time.time_ns()
match = [{"kind": "net", "program": "/usr/bin/curl", "object": "203.0.113.9:80", "first_ns": t - 10**12, "last_ns": t, "count": 3}]
check(new1.call("POST", f"hunts/{hid}", ndjson=match)[0] == 200, "agent 1 answers with a match")
st, r = A.call("GET", f"/api/hunts/{hid}")
e1 = [e for e in r["endpoints"] if e["id"] == new1.eid][0]; e2 = [e for e in r["endpoints"] if e["id"] == new2.eid][0]
check(st == 200 and e1["answered"] and e1["rows"][0]["object"] == "203.0.113.9:80" and not e2["answered"] and r["endpoints"][0]["id"] == new1.eid,
      "results: agent 1's match first, agent 2 still pending")
check(new2.call("POST", f"hunts/{hid}", ndjson=[{"none": True}])[0] == 200, "agent 2 answers: nothing found")
r = A.call("GET", f"/api/hunts/{hid}")[1]
e2 = [e for e in r["endpoints"] if e["id"] == new2.eid][0]
check(e2["answered"] and e2["rows"] == [], "an explicit no-match is answered with no rows")
lst = A.call("GET", "/api/hunts")[1]["hunts"]
check(lst and lst[0]["id"] == hid and lst[0]["asked"] == 2 and lst[0]["answered"] == 2 and lst[0]["matches"] == 1, f"hunt list counts ({lst[:1]})")

check(old.call("POST", f"hunts/{hid}", ndjson=match)[0] == 404, "an endpoint that was not asked cannot answer")
check(other.call("POST", f"hunts/{hid}", ndjson=match)[0] == 404, "organisation B's agent cannot answer A's hunt")
check(other.call("POST", f"hunts/{hid}", ndjson=match, eid=new1.eid)[0] in (401, 403, 404), "an agent cannot answer in another endpoint's name")
check(B.call("GET", f"/api/hunts/{hid}")[0] == 404 and all(x["id"] != hid for x in B.call("GET", "/api/hunts")[1]["hunts"]), "organisation B cannot see A's hunt")

st, inv = A.call("POST", "/api/invites", {"role": "viewer", "email": f"hv-{run}@a.example"})
V = Console()
tok = inv["invite"]["link"].rsplit("/", 1)[1]
check(V.call("POST", f"/api/invites/{tok}/accept", {"name": "Viewer", "password": "hunt-viewer-pw-1"})[0] == 200, "a viewer joins A")
check(V.call("POST", "/api/hunts", {"q": "curl"})[0] == 403 and V.call("GET", f"/api/hunts/{hid}")[0] == 200, "viewers can read hunts but not start one")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
