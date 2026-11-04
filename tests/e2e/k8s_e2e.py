"""Kubernetes clusters on a stack (staging): a fleet token enrols at most max_nodes nodes, each as its own endpoint
named after the node; the manifest is a DaemonSet with the token in a Secret; closing the token stops new enrolments;
other organisations cannot see or use it (run with the gateway reachable, like triage_e2e.py)."""
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




def enroll(token, hostname):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(key, hashes.SHA256())
    con = http.client.HTTPSConnection(HOST, 8443, context=ctx)
    con.request("POST", "/v1/enroll", body=json.dumps({"token": token, "hostname": hostname, "agent_version": "0.3.18",
                                                       "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}), headers={"Content-Type": "application/json"})
    r = con.getresponse()
    return r.status, json.loads(r.read() or b"{}")


def raw(console, path):
    con = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=60)
    con.request("GET", path, headers={"Cookie": console.cookie})
    r = con.getresponse()
    return r.status, r.read().decode()


run = secrets.token_hex(3)
A, B = Console(), Console()
check(A.call("POST", "/api/signup", {"organisation": f"K8s A {run}", "name": "Alice", "email": f"ka-{run}@a.example", "password": "k8s-password-1", "code": "x"})[0] == 200, "organisation A signs up")
time.sleep(2)
check(B.call("POST", "/api/signup", {"organisation": f"K8s B {run}", "name": "Bob", "email": f"kb-{run}@b.example", "password": "k8s-password-2", "code": "x"})[0] == 200, "organisation B signs up")
check(A.call("POST", "/api/clusters", {"cluster": "bad/name"})[0] == 400 and A.call("POST", "/api/clusters", {"cluster": "c", "max_nodes": 0})[0] == 422, "bad cluster name / node count refused")
st, cl = A.call("POST", "/api/clusters", {"cluster": f"prod-{run}", "max_nodes": 2, "days": 7})
check(st == 200 and cl["max_nodes"] == 2, "cluster token created")
m = cl["manifest"]
tok = m.split("token: ", 1)[1].split("\n", 1)[0].strip('"')
check("kind: DaemonSet" in m and "hostPID: true" in m and "fieldPath: spec.nodeName" in m and "secretKeyRef: {name: pdp-enroll, key: token}" in m
      and "operator: Exists" in m and len(tok) > 20, "manifest: privileged DaemonSet on every node, token in a Secret, node name as host name")
try:
    import yaml  # noqa
    docs = [d for d in yaml.safe_load_all(m) if d]
    check([d["kind"] for d in docs][:2] == ["Namespace", "Secret"] and docs[-1]["kind"] == "DaemonSet", f"manifest parses as YAML ({[d['kind'] for d in docs]})")
except ImportError:
    print("SKIP yaml parse (no PyYAML)")
s1, e1 = enroll(tok, f"node-a-{run}"); s2, e2 = enroll(tok, f"node-b-{run}"); s3, e3 = enroll(tok, f"node-c-{run}")
check(s1 == 200 and s2 == 200 and e1["endpoint_id"] != e2["endpoint_id"], "two nodes enrol with the same token")
check(s3 == 403 and "all 2 nodes" in e3.get("detail", ""), f"a third node is refused ({s3} {e3.get('detail')})")
eps = {e["name"]: e for e in A.call("GET", "/api/endpoints")[1]["endpoints"]}
check(f"node-a-{run}" in eps and f"node-b-{run}" in eps, "each node is an endpoint named after the node")
lst = A.call("GET", "/api/clusters")[1]["clusters"]
check(len(lst) == 1 and lst[0]["uses"] == 2 and lst[0]["endpoints"] == 2 and lst[0]["active"], f"cluster list ({lst})")
key = lst[0]["key"]
st, body = raw(A, f"/api/clusters/{key}/manifest")
check(st == 200 and tok in body and "kind: DaemonSet" in body, "manifest downloadable again (for updates)")
check(B.call("GET", "/api/clusters")[1]["clusters"] == [] and raw(B, f"/api/clusters/{key}/manifest")[0] == 404
      and B.call("POST", f"/api/clusters/{key}/revoke")[0] == 404, "organisation B cannot see, download or close A's cluster token")
st, cl2 = A.call("POST", "/api/clusters", {"cluster": f"stage-{run}", "max_nodes": 5})
tok2 = cl2["manifest"].split("token: ", 1)[1].split("\n", 1)[0].strip('"')
k2 = [c["key"] for c in A.call("GET", "/api/clusters")[1]["clusters"] if c["cluster"] == f"stage-{run}"][0]
check(A.call("POST", f"/api/clusters/{k2}/revoke")[0] == 200 and enroll(tok2, f"late-{run}")[0] == 403 and raw(A, f"/api/clusters/{k2}/manifest")[0] == 410,
      "a closed token enrols no node and its manifest is no longer handed out")
st, single = A.call("POST", "/api/endpoints", {"name": f"single-{run}"})
check(st == 200 and enroll(single["token"], "h1")[0] == 200 and enroll(single["token"], "h2")[0] == 403, "single-endpoint tokens stay single-use")

# kernels without BTF: an enrolled agent fetches its kernel's BTF from the server (fixture written by run_e2e.sh)
key = ec.generate_private_key(ec.SECP256R1())
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(key, hashes.SHA256())
st, single = A.call("POST", "/api/endpoints", {"name": f"nobtf-{run}"})
con = http.client.HTTPSConnection(HOST, 8443, context=ctx)
con.request("POST", "/v1/enroll", body=json.dumps({"token": single["token"], "hostname": "nobtf", "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}),
            headers={"Content-Type": "application/json"})
enr = json.loads(con.getresponse().read())
dd = tempfile.mkdtemp()
open(os.path.join(dd, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open(os.path.join(dd, "c.pem"), "w").write(enr["cert_pem"])
actx = ssl.create_default_context(cafile=caf.name); actx.load_cert_chain(os.path.join(dd, "c.pem"), os.path.join(dd, "k.pem"))


def btf(rel, eid=None):
    con = http.client.HTTPSConnection(HOST, 8443, context=actx)
    con.request("GET", f"/v1/endpoints/{eid or enr['endpoint_id']}/btf/{rel}")
    r = con.getresponse()
    return r.status, r.read()


if os.environ.get("PDP_E2E_BTF_FIXTURE"):
    st, body = btf("0.0.0-pdp-e2e")
    check(st == 200 and body == b"\x9f\xeb\x01\x00pdp-e2e", f"BTF served for a kernel the operator stocked ({st})")
else:
    print("SKIP BTF fixture (PDP_E2E_BTF_FIXTURE not set)")
check(btf("0.0.0-unknown")[0] == 404 and btf("..%2F..%2Fetc%2Fpasswd")[0] in (400, 404), "unknown kernel: 404; path tricks refused")
check(btf("0.0.0-pdp-e2e", eid=e1["endpoint_id"])[0] == 403, "an agent fetches only in its own name")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
