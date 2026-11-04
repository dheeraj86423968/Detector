"""Unit tests for the agent's server-facing logic with a fake transport (no server, no kernel):
baseline day completion for live vs replay sources, dense-id upload order, command acknowledgement, heartbeat.
Run: PYTHONPATH=engine:agent python tests/unit/test_agent.py   (needs torch: run it in the agent or server image)
"""
import sys
import tempfile
import time

from pdp_engine.schema import Entity, Event
from pdp_agent.agent import Agent, day_end_ns, day_of
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
check(set(h) == {"agent_version", "queue_depth", "last_window_end_ns", "cpu_pct", "rss_mb", "spool_mb", "spool_dropped_unscored",
                 "spool_dropped_unuploaded"} and h["rss_mb"] > 0, f"health {h}")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
