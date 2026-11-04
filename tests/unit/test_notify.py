"""Notifier: target validation and the internal-address guard, message formats, webhook signature, e-mail, Slack /
Teams / webhook / syslog delivery to local receivers. (Channel selection, limits and digests run against a database:
tests/e2e/notify_e2e.py.)"""
import hashlib
import hmac
import json
import os
import socket
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ["PDP_CONSOLE_URL"] = "https://pdp.example"
from pdp_server import notify as N   # noqa: E402

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


def raises(fn, *a):
    try:
        fn(*a)
    except N.TargetError as e:
        return str(e)
    return None


# 1. validation and the internal-address guard (hosted service: no requests into our own network)
os.environ.pop("PDP_NOTIFY_ALLOW_PRIVATE", None)
check(N.validate("email", "a@x.com; b@y.org") == "a@x.com, b@y.org", "e-mail list normalised")
check(raises(N.validate, "email", "not-an-address") is not None, "bad e-mail address refused")
check(raises(N.validate, "webhook", "http://hooks.example.com/x") is not None, "plain http refused")
check(raises(N.validate, "webhook", "https://user:pw@hooks.example.com/x") is not None, "credentials in the URL refused")
check(raises(N.validate, "syslog", "https://siem:6514") is not None and N.validate("syslog", "tls://siem.example.com:6514"), "syslog needs udp/tcp/tls")
for host in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "localhost", "::1"):
    check(raises(N.resolve_public, host, 443) is not None, f"internal target {host} refused")
os.environ["PDP_NOTIFY_ALLOW_PRIVATE"] = "1"
check(N.resolve_public("127.0.0.1", 443) == ["127.0.0.1"], "PDP_NOTIFY_ALLOW_PRIVATE=1 allows internal targets (on-premises, tests)")
os.environ["PDP_NOTIFY_ALLOW_HTTP"] = "1"

# 2. messages
inc = {"id": 42, "severity": "high", "title": "Remote shell opened by nginx", "endpoint_id": "e1", "endpoint_name": "web-01",
       "first_ns": 1_790_000_000 * 10**9, "alerts": 3, "behaviours": [{"label": "Remote shell"}], "tactics": ["Execution"], "status": "open"}
m = N.incident_message(inc, escalated_from="medium")
check(m["subject"] == "[PDP] High: Remote shell opened by nginx (web-01)" and "https://pdp.example/#/incidents/42" in m["text"]
      and "(was medium)" in m["text"] and m["data"]["behaviours"] == ["Remote shell"], "incident message: subject, escalation, link, behaviours")

# 3. HTTP receivers: webhook (signature), Slack, Teams
got = []


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        got.append((self.path, dict(self.headers), body))
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{srv.server_port}"
ch = {"kind": "webhook", "target": url + "/hook?x=1", "secret": "s3cret", "name": "SOC"}
N.deliver(ch, m)
path, hdr, body = got[-1]
sig = hdr.get("X-PDP-Signature", "")
expect = "sha256=" + hmac.new(b"s3cret", hdr["X-PDP-Timestamp"].encode() + b"." + body, hashlib.sha256).hexdigest()
check(path == "/hook?x=1" and json.loads(body)["incident_id"] == 42 and hdr["X-PDP-Event"] == "incident", "webhook: JSON incident to the URL")
check(sig == expect, "webhook: HMAC-SHA256 over timestamp.body in X-PDP-Signature")
N.deliver({"kind": "slack", "target": url + "/slack"}, m)
s = json.loads(got[-1][2])
check("*High* Remote shell opened by nginx" in s["text"] and "<https://pdp.example/#/incidents/42|" in s["text"], "Slack: severity, title, console link")
N.deliver({"kind": "teams", "target": url + "/teams"}, m)
t = json.loads(got[-1][2])
check(t["@type"] == "MessageCard" and t["potentialAction"][0]["targets"][0]["uri"].endswith("/#/incidents/42"), "Teams: message card with a console button")
N.deliver_alerts({"kind": "webhook", "target": url + "/feed", "secret": None},
                 [{"id": 7, "endpoint_id": "e1", "endpoint": "web-01", "hostname": "web-01", "window_start_ns": 1_790_000_000 * 10**9,
                   "node_uuid": "u", "ntype": "subject", "label": "subject /bin/sh sh", "fused": 0.0, "r1": 0.0, "r2": 0.0,
                   "status": "open", "layer": "rules", "rule": "untrusted_exec", "reason": "executes x"}])
f = json.loads(got[-1][2])
check(f["event"] == "alerts" and f["alerts"][0]["id"] == 7 and f["alerts"][0]["rule"] == "untrusted_exec", "SIEM feed: every alert as JSON")

# 4. e-mail through an SMTP relay (minimal local receiver)
mail = []


class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: self.wfile.write((s + "\r\n").encode())
        w("220 test")
        data = False
        buf = []
        for raw in self.rfile:
            line = raw.decode().rstrip("\r\n")
            if data:
                if line == ".":
                    mail.append("\n".join(buf)); data = False; w("250 queued")
                else:
                    buf.append(line)
                continue
            cmd = line.split(" ")[0].upper()
            if cmd in ("EHLO", "HELO"):
                w("250 test")
            elif cmd == "DATA":
                data = True; w("354 go")
            elif cmd == "QUIT":
                w("221 bye"); return
            else:
                w("250 ok")


smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SMTP)
threading.Thread(target=smtp.serve_forever, daemon=True).start()
os.environ["PDP_SMTP_URL"] = f"smtp+plain://127.0.0.1:{smtp.server_address[1]}"
os.environ["PDP_SMTP_FROM"] = "PDP <alerts@pdp.example>"
N.deliver({"kind": "email", "target": "soc@corp.example, oncall@corp.example"}, m)
check(mail and "Subject: [PDP] High: Remote shell opened by nginx (web-01)" in mail[0] and "To: soc@corp.example, oncall@corp.example" in mail[0]
      and "https://pdp.example/#/incidents/42" in mail[0], "e-mail: subject, recipients, console link")

# 5. syslog CEF over TCP
lines = []


class Sys(socketserver.StreamRequestHandler):
    def handle(self):
        lines.append(self.rfile.read())


sy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Sys)
threading.Thread(target=sy.serve_forever, daemon=True).start()
N.deliver({"kind": "syslog", "target": f"tcp://127.0.0.1:{sy.server_address[1]}"}, m)
import time
for _ in range(50):
    if lines:
        break
    time.sleep(0.05)
check(lines and b"CEF:0|PDP|Provenance Detection Platform|0.3|pdp-incident|Remote shell opened by nginx|8|" in lines[0], "syslog: CEF incident event")

srv.shutdown(); smtp.shutdown(); sy.shutdown()
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
