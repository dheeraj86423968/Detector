"""Periodic retraining end to end on a stack (staging): a simulated agent 0.3.13 learns 3 short days, gets its final
model, one of its alerts is marked a false alarm, the console asks for a retraining, the agent uploads the two fresh
days it is asked for (with ids it pruned meanwhile left out), and the retrained model covers the fresh days and the
verdict. Run in a server container of the stack (it reads the database to check the bundles):
  docker compose -p pdp-staging --env-file staging.env -f docker-compose.yml run --rm --no-deps -T -v $PWD/..:/src:ro \
      -e PYTHONPATH=/src/server:/src/engine --entrypoint python worker-ingest /src/tests/e2e/refresh_e2e.py"""
import gzip
import http.client
import json
import os
import random
import secrets
import ssl
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pdp_server import db

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
cookie = [None]


def console(method, path, body=None):
    con = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=60)
    h = {"Content-Type": "application/json", **({"Cookie": cookie[0]} if cookie[0] else {})}
    con.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
    r = con.getresponse(); data = r.read()
    sc = r.getheader("Set-Cookie")
    if sc and "pdp_session=" in sc:
        cookie[0] = sc.split(";", 1)[0]
    return r.status, json.loads(data or b"{}")


run = secrets.token_hex(3)
st, _ = console("POST", "/api/signup", {"organisation": f"Refresh {run}", "name": "R", "email": f"r-{run}@refresh.example", "password": "refresh-password-1", "code": "x"})
check(st == 200, "organisation signs up")
st, tok = console("POST", "/api/endpoints", {"name": f"refresh-{run}"})
key = ec.generate_private_key(ec.SECP256R1())
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(key, hashes.SHA256())
con = http.client.HTTPSConnection(HOST, 8443, context=ctx)
con.request("POST", "/v1/enroll", body=json.dumps({"token": tok["token"], "hostname": "refresh-e2e", "agent_version": "0.3.13",
                                                   "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}), headers={"Content-Type": "application/json"})
enr = json.loads(con.getresponse().read())
d = tempfile.mkdtemp()
open(os.path.join(d, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open(os.path.join(d, "c.pem"), "w").write(enr["cert_pem"])
actx = ssl.create_default_context(cafile=caf.name); actx.load_cert_chain(os.path.join(d, "c.pem"), os.path.join(d, "k.pem"))
eid = enr["endpoint_id"]
# 0.6: a live endpoint's events may not predate its enrolment by more than a day (forged history is refused); this
# test uploads days from the past week, so the endpoint is recorded as enrolled a week ago
with db.conn() as c:
    db.q(c, "UPDATE endpoints SET enrolled_at = now() - interval '7 days' WHERE id=%s", (eid,))
B = f"/v1/endpoints/{eid}"


def agent(method, path, body=None, ndjson=None, batch=None):
    con = http.client.HTTPSConnection(HOST, 8443, context=actx, timeout=120)
    h = {"X-Batch-Id": batch} if batch else {}
    if ndjson is not None:
        data = gzip.compress("\n".join(json.dumps(r) for r in ndjson).encode()); h.update({"Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"})
    else:
        data = json.dumps(body).encode() if body is not None else None; h["Content-Type"] = "application/json"
    con.request(method, path, body=data, headers=h)
    r = con.getresponse(); out = r.read()
    return r.status, json.loads(out or b"{}")


st, _ = console("POST", f"/api/endpoints/{eid}/config", {"config": {"baseline_days": 2, "early_models": False, "train": {
    "orthrus_epochs": 1, "velox_epochs": 1, "velox_runs": 1, "orthrus_seeds": [0], "w2v_epochs": 2, "emb_dim": 16,
    "orthrus_hid_dim": 16, "orthrus_out_dim": 16, "velox_out_dim": 16}}, "reason": "e2e: short baseline for a test endpoint"})
check(st == 200, "small training configuration (2 baseline days, tiny models; weakening, so with a reason)")
agent("POST", B + "/heartbeat", {"agent_version": "0.3.13"})
rng = random.Random(1)
progs = ["/usr/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd", "/usr/bin/curl"]
E = 400
ents = []
for k in range(E):
    if k < 4:
        ents.append({"uuid": f"file:{progs[k]}", "ntype": "file", "label": f"file {progs[k]}"})
    elif k < 60:
        ents.append({"uuid": f"file:/etc/c{k}", "ntype": "file", "label": f"file /etc/c{k}"})
    else:
        p = progs[k % 4]
        ents.append({"uuid": f"p:{k}", "ntype": "subject", "label": f"subject {p} {p} {k % 3}"})
for k, e in enumerate(ents):
    e.update({"display": {}, "dense_id": k})
agent("POST", B + "/entities", ndjson=ents)


def day_events(date, lo, hi):
    t0 = int(time.mktime(time.strptime(date + " 08:00", "%Y-%m-%d %H:%M")) - time.timezone) * 10**9
    out = []
    for k in range(3000):
        pid = rng.randrange(lo, hi)
        ts = t0 + k * 2 * 10**9
        out.append({"ts_ns": ts, "src": f"file:{progs[pid % 4]}", "op": "EXECUTE", "dst": f"p:{pid}", "event_uuid": f"{date}:{k}:a"})
        out.append({"ts_ns": ts + 1, "src": f"file:/etc/c{4 + pid % 56}", "op": "READ", "dst": f"p:{pid}", "event_uuid": f"{date}:{k}:b"})
    return out


today = time.strftime("%Y-%m-%d", time.gmtime())
past = [time.strftime("%Y-%m-%d", time.gmtime(time.time() - k * 86400)) for k in (5, 4, 3)]
for day in past:
    agent("POST", B + "/events", ndjson=day_events(day, 60, E), batch=f"b-{day}")
    agent("POST", B + "/day-complete", {"date": day})
deadline = time.time() + 1200
first = None
while time.time() < deadline:
    with db.conn() as c:
        r = db.q(c, "SELECT phase, current_bundle FROM endpoints WHERE id=%s", (eid,), one=True)
    if r["phase"] == "protected" and r["current_bundle"]:
        first = str(r["current_bundle"]); break
    time.sleep(10)
check(first is not None, f"baseline ingested and the final model trained ({first})")

# a false alarm, marked as such by the analyst
alert = {"window_start_ns": int(time.time() * 1e9), "node": {"uuid": "p:61", "ntype": "subject", "label": ents[61]["label"]}, "fused": 1.5, "r1": 1, "r2": 1,
         "layer": "learned", "rule": "learned_score", "reason": "learned score 1.5x", "reasons": [],
         "context": {"nodes": [], "edges": [{"src": "file:/etc/c7", "dst": "p:61", "op": "WRITE", "ts_ns": int(time.time() * 1e9), "loss": 3.0},
                                             {"src": "p:61", "dst": "file:/etc/c8", "op": "WRITE", "ts_ns": int(time.time() * 1e9) + 1, "loss": 3.0}]}}
agent("POST", B + "/alerts", ndjson=[alert])
st, al = console("GET", f"/api/alerts?endpoint_id={eid}")
aid = al["alerts"][0]["id"]
st, _ = console("POST", f"/api/alerts/{aid}", {"status": "false_positive"})
check(st == 200, "the analyst marks the alert a false alarm")

st, rr = console("POST", f"/api/endpoints/{eid}/retrain")
fresh = rr.get("refresh_days") or []
check(st == 200 and len(fresh) == 2, f"retraining a protected endpoint asks for two fresh days {fresh}")
st, stt = agent("GET", B + "/status")
check((stt.get("config") or {}).get("refresh_days") == fresh, "the agent sees the requested days in its status")
st, _ = console("POST", f"/api/endpoints/{eid}/retrain")
check(st == 409, "a second request while collecting is refused")
# the server asks for the next two whole days; this test cannot wait for them, and since 0.6 events more than a day
# in the future are refused, so the request is moved to the two most recent past days (test only)
fresh = [time.strftime("%Y-%m-%d", time.gmtime(time.time() - k * 86400)) for k in (2, 1)]
with db.conn() as c:
    db.q(c, "UPDATE endpoints SET config = config || jsonb_build_object('refresh_days', %s::jsonb) WHERE id=%s", (json.dumps(fresh), eid))

# the agent pruned ids E..E+4 meanwhile (never uploaded); new entities follow with their own ids
new = [{"uuid": f"p:new{k}", "ntype": "subject", "label": f"subject /usr/bin/python3 python3 job{k % 3}", "display": {}, "dense_id": E + 5 + k} for k in range(40)]
agent("POST", B + "/entities", ndjson=new)
for day in fresh:
    evs = day_events(day, 60, E) + [{"ts_ns": int(time.mktime(time.strptime(day + " 12:00", "%Y-%m-%d %H:%M")) - time.timezone) * 10**9 + k,
                                     "src": "file:/usr/bin/python3", "op": "EXECUTE", "dst": f"p:new{k}", "event_uuid": f"{day}:n{k}"} for k in range(40)]
    agent("POST", B + "/events", ndjson=evs, batch=f"b-{day}")
    agent("POST", B + "/day-complete", {"date": day})
second, man = None, None
deadline = time.time() + 1200
while time.time() < deadline:
    with db.conn() as c:
        r = db.q(c, "SELECT e.phase, e.current_bundle, e.config, b.manifest FROM endpoints e LEFT JOIN bundles b ON b.id=e.current_bundle WHERE e.id=%s", (eid,), one=True)
    if r["current_bundle"] and str(r["current_bundle"]) != first:
        second, man, cfg = str(r["current_bundle"]), r["manifest"], r["config"]; break
    time.sleep(10)
check(second is not None and r["phase"] == "protected", f"the retrained model is published, the endpoint stays protected ({second})")
if man:
    check(man.get("refresh") is True and set(fresh) <= set(man["train_days"] + [man["val_day"]]), f"trained on the most recent days {man['train_days']} / {man['val_day']}")
    check((man.get("feedback_windows") or 0) >= 1 and "feedback" in man["train_days"], f"the false-alarm verdict is in the training data ({man.get('feedback_windows')} window)")
    check(man["num_nodes"] == E + 45, f"pruned ids kept aligned with placeholders ({man['num_nodes']} = {E} + 5 placeholders + 40 new)")
    check("refresh_days" not in cfg and "refresh_queued" not in cfg, "the request is cleared")
console("POST", f"/api/endpoints/{eid}/retire")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
