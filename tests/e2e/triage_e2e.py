"""Incident triage on a stack (staging): owner, notes, status history, owner filters, isolation between
organisations, the weekly report (run with the gateway reachable, like refresh_e2e.py)."""
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


run = secrets.token_hex(3)
A, B = Console(), Console()
check(A.call("POST", "/api/signup", {"organisation": f"Triage A {run}", "name": "Alice", "email": f"ta-{run}@a.example", "password": "triage-password-1", "code": "x"})[0] == 200, "organisation A signs up")
check(B.call("POST", "/api/signup", {"organisation": f"Triage B {run}", "name": "Bob", "email": f"tb-{run}@b.example", "password": "triage-password-2", "code": "x"})[0] == 200, "organisation B signs up")
me = A.call("GET", "/api/me")[1]
st, tok = A.call("POST", "/api/endpoints", {"name": f"web-{run}"})
key = ec.generate_private_key(ec.SECP256R1())
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(key, hashes.SHA256())
con = http.client.HTTPSConnection(HOST, 8443, context=ctx)
con.request("POST", "/v1/enroll", body=json.dumps({"token": tok["token"], "hostname": "triage", "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}),
            headers={"Content-Type": "application/json"})
enr = json.loads(con.getresponse().read())
d = tempfile.mkdtemp()
open(os.path.join(d, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open(os.path.join(d, "c.pem"), "w").write(enr["cert_pem"])
actx = ssl.create_default_context(cafile=caf.name); actx.load_cert_chain(os.path.join(d, "c.pem"), os.path.join(d, "k.pem"))
alert = {"window_start_ns": time.time_ns() - 3600 * 10**9, "node": {"uuid": f"p:{run}", "ntype": "subject", "label": "subject /tmp/x x"}, "fused": 0, "r1": 0, "r2": 0,
         "layer": "rules", "rule": "untrusted_exec", "reason": "executes /tmp/x, whose content came from untrusted netflow 203.0.113.7", "reasons": [], "context": {"nodes": [], "edges": []}}
con = http.client.HTTPSConnection(HOST, 8443, context=actx)
con.request("POST", f"/v1/endpoints/{enr['endpoint_id']}/alerts", body=gzip.compress(json.dumps(alert).encode()), headers={"Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"})
con.getresponse().read()
inc = A.call("GET", "/api/incidents?status=all")[1]["incidents"][0]
iid = inc["id"]
st, det = A.call("GET", f"/api/incidents/{iid}")
check(st == 200 and det["assignee"] is None and det["history"] == [] and any(p["id"] == me["user_id"] for p in det["assignable"]), "a new incident has no owner and no history; A's admin is assignable")
check(A.call("POST", f"/api/incidents/{iid}/assign", {"user_id": me["user_id"]})[0] == 200, "A takes the incident")
check(A.call("POST", f"/api/incidents/{iid}/notes", {"text": "Checked with the web team: not a deployment."})[0] == 200, "A adds a note")
check(A.call("POST", f"/api/incidents/{iid}/status", {"status": "investigating", "note": "Isolating the host"})[0] == 200, "A sets investigating with a note")
st, det = A.call("GET", f"/api/incidents/{iid}")
kinds = [h["kind"] for h in det["history"]]
check(det["assignee"] and det["assignee"]["id"] == me["user_id"] and kinds == ["assign", "note", "status"] and det["history"][2]["text"] == "Isolating the host"
      and det["history"][1]["by"], f"owner and history recorded in order, with author ({kinds})")
mine = A.call("GET", "/api/incidents?status=all&assignee=me")[1]["incidents"]
none_ = A.call("GET", "/api/incidents?status=all&assignee=none")[1]["incidents"]
check([i["id"] for i in mine] == [iid] and iid not in [i["id"] for i in none_] and mine[0]["assignee"]["name"], "owner filters: mine / no owner")
check([B.call("POST", f"/api/incidents/{iid}/assign", {"user_id": None})[0], B.call("POST", f"/api/incidents/{iid}/notes", {"text": "x"})[0],
       B.call("GET", f"/api/incidents/{iid}")[0]] == [404, 404, 404], "organisation B cannot assign, comment on or open A's incident")
bme = B.call("GET", "/api/me")[1]
check(A.call("POST", f"/api/incidents/{iid}/assign", {"user_id": bme["user_id"]})[0] == 400, "A cannot assign its incident to B's user")
check(A.call("POST", f"/api/incidents/{iid}/notes", {"text": ""})[0] == 400, "empty notes are refused")
st, w = A.call("GET", "/api/reports/weekly")
check(st == 200 and w["incidents_new"] == 1 and w["incidents_open"] == 1 and w["endpoints"] == 1 and w["top"][0]["id"] == iid, f"weekly report: {w.get('incidents_new')} new, {w.get('incidents_open')} open")
st, wb = B.call("GET", "/api/reports/weekly")
check(wb["incidents_new"] == 0 and wb["endpoints"] == 0, "B's weekly report holds nothing of A")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
