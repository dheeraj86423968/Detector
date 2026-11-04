"""Agent-level registry compaction: global ids in the spool and uploads, live-set save/load, restart replay of the
open window, entities that come back after being dropped. (Detection equality itself: test_compaction.py.)
Run in the server image (trains a tiny model with gensim)."""
import os
import random
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from pdp_engine.bundle import sign_manifest
from pdp_engine.data import WindowStore, ingest_day
from pdp_engine.schema import Entity, Event, Registry
from pdp_engine.trainer import TrainConfig, Trainer
from pdp_agent.agent import Agent
from pdp_agent.config import Config

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


class FakeTransport:
    def __init__(self):
        self.calls = []

    def post_ndjson(self, path, rows, batch_id=None):
        self.calls.append(("ndjson", path, rows, batch_id)); return {"ok": True}

    def request(self, method, path, body=None, **kw):
        self.calls.append((method, path, body)); return {"ok": True}


rng = random.Random(3)
MIN = 60 * 10**9
seq = [0]
progs = ["/usr/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd", "/usr/bin/curl"]
files = [f"/etc/conf{i}" for i in range(10)]


def activity(t0, minutes, tag):
    out = []
    for m in range(minutes):
        for k in range(20):
            ts = t0 + m * MIN + k * 10**9
            exe = rng.choice(progs)
            p = Entity.process(f"p:{tag}:{m}:{k}", exe, f"{exe} {k % 3}", pid=k)
            f = Entity.file(f"file:{rng.choice(files)}", rng.choice(files))
            t = Entity.file(f"file:/tmp/{tag}-{m}-{k}", f"/tmp/{tag}-{m}-{k}")
            for a, op, b in ((Entity.file(f"file:{exe}", exe), "EXECUTE", p), (f, "READ", p), (p, "WRITE", t)):
                seq[0] += 1
                out.append(([a, b], Event(ts, a.uuid, op, b.uuid, f"e{seq[0]:010d}")))
    return out


now = time.time_ns()
WIN = 5 * MIN
tmp = tempfile.mkdtemp()
# a tiny model on a baseline whose entities come first in the agent's registry too (same global ids)
base = activity(now - 6 * 60 * MIN, 90, "base")
store = WindowStore(os.path.join(tmp, "store"))
reg = Registry()
for ents, _ in base:
    for e in ents:
        reg.add(e)
store.add_day("d1", ingest_day(reg, (ev for _, ev in base[: len(base) * 2 // 3]), None, window_ns=WIN))
store.add_day("d2", ingest_day(reg, (ev for _, ev in base[len(base) * 2 // 3:]), None, window_ns=WIN))
store.save_registry(reg)
bdir = os.path.join(tmp, "data", "bundles", "b1", "bundle")
os.makedirs(bdir)
cfg_t = TrainConfig(device="cpu", w2v_epochs=2, emb_dim=16, velox_epochs=1, velox_runs=1, orthrus_seeds=(0,), orthrus_epochs=1,
                    orthrus_hid_dim=16, orthrus_out_dim=16, velox_out_dim=16, neighbor_size=5)
Trainer(store, ["d1"], "d2", cfg_t, bdir).run({"bundle_id": "b1", "window_ns": WIN})
key = ed25519.Ed25519PrivateKey.generate()
sign_manifest(bdir, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

data = os.path.join(tmp, "data")
os.makedirs(os.path.join(data, "pki"), exist_ok=True)
open(os.path.join(data, "pki", "bundle_signing.pub"), "wb").write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
cfg = Config(data_dir=data, pki_dir=os.path.join(data, "pki"), source={"kind": "ebpf"}, day_tz="UTC",
             entity_max_age_h=0.25, compact_min_entities=0, compact_interval_s=0)


def new_agent():
    a = Agent(cfg)
    a.state.set("endpoint_id", "e1"); a.state.set("config", {"baseline_days": 30, "tz": "UTC"})
    a.eid, a.tr = "e1", FakeTransport()
    return a


a = new_agent()
a.ingest(base)                     # the baseline the model was trained on (same order -> same global ids)
check(a.reg.gids is None and len(a.reg) == len(reg) and all(a.reg.get(e.uuid) == reg.get(e.uuid) for e in reg.entities[:50]),
      "agent registry positions = global ids = the server's registry before any compaction")
a._load_bundle("b1", bdir)
a.state.c.execute("UPDATE events SET scored=1")          # the baseline itself is not scored
a.runtime.last_seen[:] = now - 6 * 60 * MIN              # as if the model had been loaded hours ago
part1 = activity(now - 3 * 60 * MIN, 30, "p1")
a.ingest(part1)
a.score_backlog()
a.upload_baseline()               # as in the run loop: uploads and the spool purge come before a compaction
a.purge_spool()
n_before = len(a.reg)
a._last_compact = 0
a.maybe_compact(time.time())
check(len(a.reg) < n_before * 0.6 and os.path.exists(os.path.join(data, "live_entities.npy")),
      f"compaction: {n_before} -> {len(a.reg)} entities, live set saved")
check(a.reg.gids is not None and a.reg.gid(0) == a.state.gid_for(a.reg[0].uuid), "kept entities keep their global ids")

# part 2 brings back a dropped entity (an old temp file) and new ones
gone = "file:/tmp/p1-0-0"
check(a.reg.get(gone) is None, "an old one-off temp file was dropped")
back = Entity.file(gone, "/tmp/p1-0-0")
p = Entity.process("p:again", "/usr/bin/cat", "cat /tmp/p1-0-0")
part2 = activity(now - 60 * MIN, 12, "p2") + [([back, p], Event(now - 47 * MIN, back.uuid, "READ", p.uuid, "e-back"))]
part2.sort(key=lambda x: x[1].ts_ns)
a.ingest(part2)
check(a.reg.gid(a.reg.get(gone)) == a.state.gid_for(gone), "a dropped entity that comes back gets its old global id")
a.score_backlog()
open_rows = a.state.unscored_count()
check(open_rows > 0 and len(a._open_ids) == open_rows, f"rows of the open window stay unscored until it closes ({open_rows})")

# uploads: every spooled event goes out with its original uuids
a.upload_baseline()
sent = {r["event_uuid"]: (r["src"], r["dst"]) for c in a.tr.calls if c[0] == "ndjson" and c[1].endswith("/events") for r in c[2]}
orig = {ev.event_uuid: (ev.src, ev.dst) for _, ev in base + part1 + part2}
check(len(sent) == len(orig) and all(sent[k] == v for k, v in orig.items()), f"all {len(orig)} events uploaded with their own entity uuids")
ents = [r for c in a.tr.calls if c[0] == "ndjson" and c[1].endswith("/entities") for r in c[2]]
check([r["dense_id"] for r in ents] == list(range(len(ents))) and ents[0]["uuid"] == reg.entities[0].uuid,
      f"entities uploaded with consecutive global ids ({len(ents)})")
total = a.state.next_gid()

# restart: only the live set (+ newer + spool-referenced) is loaded; the open window is replayed
del a
b = new_agent()
check(len(b.reg) < total and b.reg.gids is not None, f"restart loads {len(b.reg)} of {total} entities")
b._load_bundle("b1", bdir)
check(b.state.unscored_count() == open_rows, "open-window rows are still waiting after the restart")
part3 = activity(now - 40 * MIN, 35, "p3")
b.ingest(part3)
b.score_backlog()
reported = [r for c in b.tr.calls if c[0] == "ndjson" and c[1].endswith("/windows") for r in c[2]]
check(len(reported) >= 2 and b.state.unscored_count() < open_rows + len(part3),
      f"after the restart the replayed and new events are scored ({len(reported)} windows)")
check(all(b.reg.get(ev.src) is not None and b.reg.get(ev.dst) is not None for _, ev in part3), "new entities registered after the restart")

# disk pruning (final model): entities after the baseline that are not live are deleted, ids never reused
b.cfg.prune_entities_always = True
b.upload_baseline(); b.purge_spool()
rows0 = b.state.c.execute("SELECT count(*) FROM entities").fetchone()[0]
nxt = b.next_gid
b.runtime.last_seen[:] = now - 6 * 60 * MIN
b._last_compact = 0
b.maybe_compact(time.time())
rows1 = b.state.c.execute("SELECT count(*) FROM entities").fetchone()[0]
base_kept = b.state.c.execute("SELECT count(*) FROM entities WHERE dense_id - 1 < ?", (int(b.runtime.N),)).fetchone()[0]
check(rows1 < rows0 and base_kept == int(b.runtime.N), f"entity records on disk {rows0} -> {rows1}; all {base_kept} baseline records kept")
check(all(b.state.gid_for(b.reg[i].uuid) == b.reg.gid(i) for i in range(len(b.reg))), "every live entity still has its record")
check(b.state.next_gid() == nxt, f"next global id unchanged by the deletion ({nxt})")

# an entity registered after the deletion gets the next id on disk too (not sqlite's max rowid + 1)
b.state.c.execute("DELETE FROM entities WHERE dense_id = (SELECT max(dense_id) FROM entities)")   # highest row gone
nx = b.next_gid
newp = Entity.process("p:after-prune", "/usr/bin/true", "true")
b.ingest([([newp, newp], Event(now, newp.uuid, "CLONE", newp.uuid, "e-after"))])
check(b.state.gid_for(newp.uuid) == nx == b.reg.gid(b.reg.get(newp.uuid)), f"new entity stored at global id {nx} on disk and in memory")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
