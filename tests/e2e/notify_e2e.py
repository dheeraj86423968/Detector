"""Notifications end to end (run by tests/e2e/notify_e2e.sh inside the notifier service's container: database
access, the gateway, and the receiver at https://hooks.pdp-e2e.example:9443 which records into /out)."""
import gzip
import hashlib
import hmac
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
HOOK = "https://hooks.pdp-e2e.example:9443"
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
    con = http.client.HTTPSConnection(HOST, 8443, context=ctx)
    con.request("POST", "/v1/enroll", body=json.dumps({"token": token, "hostname": "notify-e2e", "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}),
                headers={"Content-Type": "application/json"})
    r = con.getresponse(); js = json.loads(r.read())
    d = tempfile.mkdtemp()
    open(os.path.join(d, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    open(os.path.join(d, "c.pem"), "w").write(js.get("cert_pem", ""))
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
    r = con.getresponse(); r.read()
    return r.status


def received(path=None):
    try:
        rows = [json.loads(x) for x in open("/out/requests.ndjson")]
    except FileNotFoundError:
        return []
    return [r for r in rows if path is None or r["path"] == path]


run = secrets.token_hex(3)
CODE = os.environ.get("PDP_SIGNUP_CODE", "")
A, B = Console(), Console()
st, _ = A.call("POST", "/api/signup", {"organisation": f"Notify A {run}", "name": "Alice", "email": f"alice-{run}@notify-a.example", "password": "alice-password-1", "code": CODE})
check(st == 200, f"organisation A signs up ({st})")
st, _ = B.call("POST", "/api/signup", {"organisation": f"Notify B {run}", "name": "Bob", "email": f"bob-{run}@notify-b.example", "password": "bob-password-12", "code": CODE})
check(st == 200, "organisation B signs up")
orgA = A.call("GET", "/api/me")[1]["org"]["id"]

# ---------------------------------------------------------------- channels: validation and organisation isolation
st, js = A.call("GET", "/api/notifications/channels")
check(st == 200 and js["channels"] == [] and js["notifier_running"], f"A has no channels; the notifier service is running ({js.get('notifier_running')})")
bad = [("webhook", "http://hooks.example.com/x"), ("webhook", "https://10.0.0.5/x"), ("webhook", "https://localhost/x"),
       ("slack", "https://169.254.169.254/latest"), ("syslog", "https://siem:6514"), ("email", "nobody")]
codes = [A.call("POST", "/api/notifications/channels", {"name": "bad", "kind": k, "target": t})[0] for k, t in bad]
check(codes == [400] * len(bad), f"plain http, internal addresses, bad syslog/e-mail targets refused ({codes})")
st, wh = A.call("POST", "/api/notifications/channels", {"name": "SOC webhook", "kind": "webhook", "target": HOOK + "/hook", "secret": "e2e-secret",
                                                         "min_severity": "high", "events": ["incident"]})
check(st == 200 and wh["channel"]["has_secret"] and "secret" not in wh["channel"], "A adds a signed webhook (the secret is never returned)")
st, sl = A.call("POST", "/api/notifications/channels", {"name": "Slack #sec", "kind": "slack", "target": HOOK + "/slack", "min_severity": "critical", "events": ["incident"]})
st2, ops = A.call("POST", "/api/notifications/channels", {"name": "Ops", "kind": "teams", "target": HOOK + "/ops", "events": ["agent_offline"]})
st3, feed = A.call("POST", "/api/notifications/channels", {"name": "SIEM feed", "kind": "webhook", "target": HOOK + "/feed", "events": [], "every_alert": True})
check(st == st2 == st3 == 200, "A adds a Slack channel (critical only), a Teams channel (agent offline) and a SIEM feed (every alert)")
whid = wh["channel"]["id"]
check(B.call("GET", "/api/notifications/channels")[1]["channels"] == [], "B does not see A's channels")
check([B.call(m, p, b)[0] for m, p, b in (("PATCH", f"/api/notifications/channels/{whid}", {"enabled": False}),
                                         ("DELETE", f"/api/notifications/channels/{whid}", None),
                                         ("POST", f"/api/notifications/channels/{whid}/test", None),
                                         ("GET", f"/api/notifications/log?channel_id={whid}", None))] == [404] * 4,
      "B cannot change, delete, test or read A's channel")

# ---------------------------------------------------------------- the deployed notifier refuses internal targets
st, _ = A.call("POST", f"/api/notifications/channels/{whid}/test")
log = []
for _ in range(30):
    log = A.call("GET", f"/api/notifications/log?channel_id={whid}")[1]["log"]
    if log and log[0]["state"] != "queued":
        break
    time.sleep(2)
check(log and log[0]["state"] == "failed" and "internal address" in (log[0]["detail"] or "") and not received("/hook"),
      f"the deployed notifier refuses a destination that resolves to an internal address ({(log[0]['detail'] if log else '')[:90]})")
ch = A.call("GET", "/api/notifications/channels")[1]["channels"]
check(any(c["id"] == whid and c["last_error"] for c in ch), "the channel shows the error in the console")

# ---------------------------------------------------------------- delivery: this process runs notifier rounds itself
os.environ.update({"PDP_NOTIFY_ALLOW_PRIVATE": "1", "PDP_NOTIFY_MAX_PER_HOUR": "3", "PDP_NOTIFY_OFFLINE_MIN": "0.05",
                   "SSL_CERT_FILE": "/out/ca.pem", "PDP_CONSOLE_URL": "https://console.pdp-e2e.example"})
from pdp_server import notify as N   # noqa: E402  (reads the limits at import)


def round_():
    return N.run_once([orgA])


for _ in range(3):        # the deployed notifier may take a queued test first (and refuse it); queue again then
    A.call("POST", f"/api/notifications/channels/{whid}/test")
    round_()
    if any(json.loads(r["body"]).get("type") == "test" for r in received("/hook")):
        break
check(any(json.loads(r["body"]).get("type") == "test" for r in received("/hook")), "a queued test message is delivered")

st, tok = A.call("POST", "/api/endpoints", {"name": f"web-{run}"})
st, js, cert = enroll(tok["token"])
check(st == 200, "A's agent enrols")
ep = js["endpoint_id"]
check(agent_call(cert, "POST", f"/v1/endpoints/{ep}/heartbeat", {"agent_version": "e2e"}) == 200, "agent heartbeat (agent online)")
T = time.time_ns() - 6 * 3600 * 10**9
H30 = 31 * 60 * 10**9


def alert(i, ts, layer, rule, reason, label=None):
    return {"window_start_ns": ts, "node": {"uuid": f"proc:e2e:{run}:{i}", "ntype": "subject", "label": label or f"subject /tmp/tool{i} tool{i}"},
            "fused": 0.0, "r1": 0.0, "r2": 0.0, "layer": layer, "rule": rule, "reason": reason, "reasons": [{"layer": layer, "rule": rule}],
            "context": {"nodes": [], "edges": []}}


# incident 1: a dropped program runs (high)
agent_call(cert, "POST", f"/v1/endpoints/{ep}/alerts", ndjson=[alert(1, T, "rules", "untrusted_exec", "executes /tmp/tool1, whose content came from untrusted netflow 203.0.113.9")])
round_()
hk = [json.loads(r["body"]) for r in received("/hook") if json.loads(r["body"]).get("type") == "incident"]
check(len(hk) == 1 and hk[0]["severity"] == "high" and hk[0]["endpoint"]["id"] == ep and hk[0]["link"].startswith("https://console.pdp-e2e.example/#/incidents/"),
      f"high incident -> webhook with severity, endpoint and console link ({[h.get('title') for h in hk]})")
r0 = [r for r in received("/hook") if json.loads(r["body"]).get("type") == "incident"][0]
sig = "sha256=" + hmac.new(b"e2e-secret", r0["headers"]["X-PDP-Timestamp"].encode() + b"." + r0["body"].encode(), hashlib.sha256).hexdigest()
check(r0["headers"].get("X-PDP-Signature") == sig, "webhook signature verifies with the channel secret")
check(not received("/slack"), "Slack (critical only) stays quiet for a high incident")
round_()
check(len([r for r in received("/hook") if json.loads(r["body"]).get("type") == "incident"]) == 1, "nothing is sent twice")

# the same incident escalates: sensitive data leaves for an untrusted address (critical)
agent_call(cert, "POST", f"/v1/endpoints/{ep}/alerts", ndjson=[alert(1, T + 60 * 10**9, "rules", "exfiltration", "sends /etc/shadow data to untrusted netflow 203.0.113.9")])
round_()
hk = [json.loads(r["body"]) for r in received("/hook") if json.loads(r["body"]).get("type") == "incident"]
check(len(hk) == 2 and hk[1]["severity"] == "critical" and hk[1]["escalated_from"] == "high" and hk[1]["incident_id"] == hk[0]["incident_id"],
      "escalation to critical -> one more message, marked as escalated")
sk = [json.loads(r["body"]) for r in received("/slack")]
check(len(sk) == 1 and "*Critical*" in sk[0]["text"], "Slack now receives the critical incident")

# a medium incident (a new program only) stays below the webhook's minimum
agent_call(cert, "POST", f"/v1/endpoints/{ep}/alerts", ndjson=[alert(50, T + 2 * H30, "novelty", "novel_executable", "runs /opt/new/app, which never ran during the baseline", "subject /opt/new/app app")])
round_()
check(len([r for r in received("/hook") if json.loads(r["body"]).get("type") == "incident"]) == 2, "a medium incident is not sent to a high-minimum channel")

# a flood: four more high incidents; at most 3 messages per channel and hour, the rest in one digest
agent_call(cert, "POST", f"/v1/endpoints/{ep}/alerts", ndjson=[alert(10 + k, T + (4 + 2 * k) * H30, "rules", "untrusted_exec", f"executes /tmp/flood{k}, whose content came from untrusted netflow 203.0.113.{k}") for k in range(4)])
round_()
bodies = [json.loads(r["body"]) for r in received("/hook")]
inc_msgs = [b for b in bodies if b.get("type") == "incident"]
dig = [b for b in bodies if b.get("type") == "digest"]
log = A.call("GET", f"/api/notifications/log?channel_id={whid}&limit=100")[1]["log"]
supp = [x for x in log if x["state"] == "suppressed"]
check(len(inc_msgs) == 3 and len(supp) == 3 and len(dig) == 1 and dig[0]["count"] == 3,
      f"hourly limit: {len(inc_msgs)} incident messages, {len(supp)} held back, one digest listing {dig[0]['count'] if dig else 0}")

# SIEM feed: every alert of A, in order, once
feed_alerts = [a for r in received("/feed") for a in json.loads(r["body"]).get("alerts", [])]
check(len(feed_alerts) == 7 and all(a["endpoint_id"] == ep for a in feed_alerts) and [a["id"] for a in feed_alerts] == sorted(a["id"] for a in feed_alerts),
      f"SIEM feed: all {len(feed_alerts)} of A's alerts, in order")
round_()
check(len([a for r in received("/feed") for a in json.loads(r["body"]).get("alerts", [])]) == 7, "the feed sends each alert once")

# agent offline and back
time.sleep(4)
round_()
opsm = [json.loads(r["body"]) for r in received("/ops")]
check(any("has not reported" in m["text"] for m in opsm), "agent silent longer than the limit -> Teams 'not reported' message")
agent_call(cert, "POST", f"/v1/endpoints/{ep}/heartbeat", {"agent_version": "e2e"})
round_()
opsm = [json.loads(r["body"]) for r in received("/ops")]
check(any("reporting again" in m["text"] for m in opsm), "agent back -> 'reporting again' message")

# B's channels never see A's events
st, bwh = B.call("POST", "/api/notifications/channels", {"name": "B hook", "kind": "webhook", "target": HOOK + "/b", "events": ["incident", "agent_offline"], "min_severity": "low"})
N.run_once([B.call("GET", "/api/me")[1]["org"]["id"]])
check(not received("/b"), "B's channel receives nothing of A's incidents or agents")

for cid in (whid, sl["channel"]["id"], ops["channel"]["id"], feed["channel"]["id"]):
    A.call("DELETE", f"/api/notifications/channels/{cid}")
check(A.call("GET", "/api/notifications/channels")[1]["channels"] == [], "channels deleted")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
