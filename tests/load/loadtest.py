"""Load test: N simulated agents against a stack (staging), behaving like real agents in baseline / protected phase.

  docker run --rm --network pdp-staging_edge -v $PWD:/src:ro -w /src --entrypoint python pdp/server:dev \
      tests/load/loadtest.py --agents 50 --minutes 10 --events-per-min 3000

Each agent: enrols (own key and certificate), uploads its entities, then every minute uploads a gzip NDJSON batch of
events (the baseline upload), polls status every 30 s, sends a heartbeat every 60 s, and every 15 minutes posts a window
summary (protected agents do; a fraction also posts an alert). Prints per-route latency percentiles and errors, and the
server-side state at the end (events stored, jobs). One organisation per 150 agents (sign-up must be open).
"""
from __future__ import annotations

import argparse
import gzip
import http.client
import json
import os
import random
import secrets
import ssl
import statistics
import sys
import tempfile
import threading
import time
from collections import defaultdict

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST = os.environ.get("PDP_GATEWAY", "gateway")
lat = defaultdict(list)
errs = defaultdict(int)
lock = threading.Lock()

raw = ssl.create_default_context(); raw.check_hostname = False; raw.verify_mode = ssl.CERT_NONE
c0 = http.client.HTTPSConnection(HOST, 443, context=raw); c0.request("GET", "/dl/ca.pem"); CA = c0.getresponse().read()
caf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem"); caf.write(CA); caf.close()
ctx = ssl.create_default_context(cafile=caf.name)


def timed(route, fn):
    t = time.perf_counter()
    try:
        st = fn()
    except Exception as e:  # noqa
        st = f"exc {type(e).__name__}"
    dt = time.perf_counter() - t
    with lock:
        lat[route].append(dt)
        if st != 200:
            errs[(route, str(st))] += 1
    return st


class Console:
    def __init__(self):
        self.cookie = None

    def call(self, method, path, body=None):
        con = http.client.HTTPSConnection(HOST, 443, context=ctx, timeout=60)
        h = {"Content-Type": "application/json"}
        if self.cookie:
            h["Cookie"] = self.cookie
        con.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = con.getresponse(); data = r.read()
        sc = r.getheader("Set-Cookie")
        if sc and "pdp_session=" in sc:
            self.cookie = sc.split(";", 1)[0]
        return r.status, json.loads(data or b"{}")


class Agent(threading.Thread):
    def __init__(self, i, token, args, stop):
        super().__init__(daemon=True)
        self.i, self.token, self.a, self.stop = i, token, args, stop
        self.rng = random.Random(i)

    def enroll(self):
        key = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(key, hashes.SHA256())
        res = {}

        def go():
            con = http.client.HTTPSConnection(HOST, 8443, context=ctx, timeout=60)
            con.request("POST", "/v1/enroll", body=json.dumps({"token": self.token, "hostname": f"load-{self.i}", "agent_version": self.a.agent_version,
                                                               "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode()}),
                        headers={"Content-Type": "application/json"})
            r = con.getresponse(); res.update(json.loads(r.read() or b"{}")); return r.status
        if timed("enroll", go) != 200:
            return False
        d = tempfile.mkdtemp()
        open(os.path.join(d, "k.pem"), "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        open(os.path.join(d, "c.pem"), "w").write(res["cert_pem"])
        self.actx = ssl.create_default_context(cafile=caf.name)
        self.actx.load_cert_chain(os.path.join(d, "c.pem"), os.path.join(d, "k.pem"))
        self.eid = res["endpoint_id"]
        return True

    def call(self, route, method, path, body=None, ndjson=None, batch=None):
        def go():
            con = http.client.HTTPSConnection(HOST, 8443, context=self.actx, timeout=120)
            h = {"X-Batch-Id": batch} if batch else {}
            if ndjson is not None:
                data = gzip.compress("\n".join(json.dumps(r) for r in ndjson).encode()); h.update({"Content-Type": "application/x-ndjson", "Content-Encoding": "gzip"})
            else:
                data = json.dumps(body).encode() if body is not None else None; h["Content-Type"] = "application/json"
            con.request(method, path, body=data, headers=h)
            r = con.getresponse(); r.read(); return r.status
        return timed(route, go)

    def run(self):
        time.sleep(self.rng.random() * 10)
        if not self.enroll():
            return
        base = f"/v1/endpoints/{self.eid}"
        ents = [{"uuid": f"e{self.i}:{k}", "ntype": "subject" if k % 3 == 0 else "file", "label": f"file /var/lib/app{k % 97}/f{k}" if k % 3 else f"subject /usr/bin/p{k % 40} p{k % 40}",
                 "display": {}, "dense_id": k} for k in range(2000)]
        for k in range(0, len(ents), 1000):
            self.call("entities", "POST", base + "/entities", ndjson=ents[k:k + 1000])
        seq, nxt = 0, {"status": 0, "hb": 0, "events": 0, "window": time.time() + self.rng.random() * 900}
        while not self.stop.is_set():
            now = time.time()
            if now >= nxt["status"]:
                self.call("status", "GET", base + "/status"); nxt["status"] = now + 30
            if now >= nxt["hb"]:
                self.call("heartbeat", "POST", base + "/heartbeat", {"agent_version": self.a.agent_version, "queue_depth": 0, "cpu_pct": 1.0, "rss_mb": 300}); nxt["hb"] = now + 60
            if now >= nxt["events"]:
                n = self.a.events_per_min
                ts = time.time_ns()
                evs = [{"ts_ns": ts + j, "src": f"e{self.i}:{self.rng.randrange(2000)}", "op": self.rng.choice(["READ", "WRITE", "OPEN", "EXECUTE", "CONNECT"]),
                        "dst": f"e{self.i}:{self.rng.randrange(2000)}", "event_uuid": f"l{self.i}:{seq + j:010d}"} for j in range(n)]
                seq += n
                self.call("events", "POST", base + "/events", ndjson=evs, batch=f"load-{seq}"); nxt["events"] = now + 60
            if now >= nxt["window"]:
                st = time.time_ns() - 900 * 10**9
                self.call("windows", "POST", base + "/windows", ndjson=[{"start_ns": st, "end_ns": st + 900 * 10**9, "edges": 1000, "nodes": 200, "alerts": 0,
                                                                           "max_fused": 0.5, "max_r1": 0.4, "max_r2": 0.3}])
                nxt["window"] = now + 900
            self.stop.wait(1)


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(p / 100 * len(v)))] if v else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", type=int, default=50)
    ap.add_argument("--minutes", type=float, default=10)
    ap.add_argument("--events-per-min", type=int, default=3000)
    ap.add_argument("--agent-version", default="load", help="reported version (0.3.12+ gets rules-only early models)")
    a = ap.parse_args()
    run = secrets.token_hex(3)
    tokens = []
    for o in range((a.agents + 149) // 150):
        c = Console()
        st, js = c.call("POST", "/api/signup", {"organisation": f"Load {run}-{o}", "name": "Load", "email": f"load-{run}-{o}@load.example", "password": "load-test-password", "code": "x"})
        if st != 200:
            sys.exit(f"sign-up failed ({st} {js}); open sign-up on the target stack")
        for k in range(min(150, a.agents - o * 150)):
            st, tok = c.call("POST", "/api/endpoints", {"name": f"load-{o}-{k}"})
            if st != 200:
                sys.exit(f"endpoint {k}: {st} {tok}")
            tokens.append(tok["token"])
    stop = threading.Event()
    agents = [Agent(i, t, a, stop) for i, t in enumerate(tokens)]
    t0 = time.time()
    for g in agents:
        g.start()
    while time.time() - t0 < a.minutes * 60:
        time.sleep(30)
        with lock:
            n = sum(len(v) for v in lat.values()); e = sum(errs.values())
        print(f"{time.time() - t0:5.0f}s  requests {n}  errors {e}", flush=True)
    stop.set()
    for g in agents:
        g.join(timeout=30)
    dur = time.time() - t0
    print(f"\n{len(agents)} agents, {dur / 60:.1f} min, {a.events_per_min} events/min each ({len(agents) * a.events_per_min * 60 / 1e6:.1f} M events/hour in total)")
    print(f"{'route':<12}{'n':>7}{'p50 ms':>9}{'p95 ms':>9}{'p99 ms':>9}{'max ms':>9}")
    for r, v in sorted(lat.items()):
        print(f"{r:<12}{len(v):>7}{1000 * pct(v, 50):>9.0f}{1000 * pct(v, 95):>9.0f}{1000 * pct(v, 99):>9.0f}{1000 * max(v):>9.0f}")
    print("errors:", dict(errs) or "none")
    print(json.dumps({"agents": len(agents), "minutes": round(dur / 60, 1), "requests": sum(len(v) for v in lat.values()), "errors": sum(errs.values()),
                      "p95_ms": {r: round(1000 * pct(v, 95)) for r, v in lat.items()}}))


if __name__ == "__main__":
    main()
