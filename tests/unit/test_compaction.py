"""Registry compaction on a long-running agent: dropping entities nobody needs any more must not change detection.

A tiny model is trained on synthetic activity. The same later stream is then scored twice, without and with a
compaction in between that drops the short-lived entities of the first part. Every later window must give the
same scores and alerts (node ids compared through their uuids). A runtime loaded onto an already compacted
registry (agent restart) must also match a fresh one.
"""
import os
import random
import shutil
import sys
import tempfile

import numpy as np

from pdp_engine.data import WindowStore, ingest_day
from pdp_engine.runtime import Runtime
from pdp_engine.schema import Entity, Event, Registry
from pdp_engine.trainer import TrainConfig, Trainer
from pdp_engine.windows import WindowBuilder

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


rng = random.Random(7)
MIN = 60 * 10**9
T0 = 1_790_000_000 * 10**9
progs = ["/usr/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd", "/usr/bin/curl", "/usr/bin/cron", "/usr/bin/tar"]
files = [f"/etc/conf{i}" for i in range(20)] + [f"/var/log/app{i}.log" for i in range(10)]
seq = [0]


def activity(t0, minutes, tag, ephemeral):
    """(entities, Event) stream: long-lived files/sockets plus processes; ephemeral=True adds one-off temp files."""
    out = []
    for m in range(minutes):
        for k in range(25):
            ts = t0 + m * MIN + k * 10**9
            pid = rng.randrange(10**6)
            exe = rng.choice(progs)
            p = Entity.process(f"p:{tag}:{m}:{k}:{pid}", exe, f"{exe} -x {k % 3}")
            f = Entity.file(f"file:{rng.choice(files)}", rng.choice(files))
            ex = Entity.file(f"file:{exe}", exe)
            ev = [(ex, "EXECUTE", p), (f, "READ" if k % 2 else "OPEN", p)]
            if ephemeral:
                tmp = f"/tmp/{tag}-{m}-{k}.tmp"
                ev.append((p, "WRITE", Entity.file(f"file:{tmp}", tmp)))
            if k % 5 == 0:
                s = Entity.socket(f"net:10.0.0.{k}:443", f"10.0.0.{k}", 443)
                ev.append((p, "CONNECT", s))
            for a, op, b in ev:
                seq[0] += 1
                out.append(([a, b], Event(ts, a.uuid, op, b.uuid, f"e{seq[0]:010d}")))
    return out


tmp = tempfile.mkdtemp()
store = WindowStore(os.path.join(tmp, "store"))
reg = Registry()
WIN = 5 * MIN
for d, day in enumerate(["2026-01-01", "2026-01-02", "2026-01-03"]):
    items = activity(T0 + d * 90 * MIN, 60, f"d{d}", ephemeral=True)
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
N = len(reg)

# live stream after the baseline: part 1 has one-off temp files, part 2 only long-lived entities
t1 = T0 + 400 * MIN
part1 = activity(t1, 40, "live1", ephemeral=True)
part2 = activity(t1 + 60 * MIN, 40, "live2", ephemeral=False)


from pdp_engine.schema import EDGE_TYPE_ID

# global ids: the append-only order in which entities were first registered (the agent's sqlite rowids)
GID, ALL = {}, {}
for e in reg.entities:
    GID[e.uuid] = len(GID); ALL[GID[e.uuid]] = e
for ents, _ in part1 + part2:
    for e in ents:
        if e.uuid not in GID:
            GID[e.uuid] = len(GID); ALL[GID[e.uuid]] = e


def run(compact_between: bool, restart_after_compact: bool = False):
    r = store.load_registry()
    rt = Runtime(bdir, r, keep_reset_state=False, seen_at_load_ns=t1)
    b = WindowBuilder(window_ns=WIN, chunk=100)
    out = []

    def feed(items):
        res = []
        for ents, ev in items:
            for e in ents:
                if r.get(e.uuid) is None:
                    r.add(e, gid=GID[e.uuid])
            for w in b.push(r.get(ev.src), r.get(ev.dst), ev.ts_ns, EDGE_TYPE_ID[ev.op], ev.event_uuid):
                res.append(rt.score(w))
        for w in b.finish():
            res.append(rt.score(w))
        return res

    feed(part1)
    info = {}
    if compact_between:
        keep = rt.compaction_keep(now_ns=t1 + 41 * MIN, max_age_ns=15 * MIN, extra=b.node_ids())
        info["before"], info["kept"] = len(r), int(keep.sum())
        old2new = rt.compact(keep)
        b.remap(old2new)
        if restart_after_compact:   # agent restart: a new runtime on the compacted registry (bundle state remapped)
            rt = Runtime(bdir, r, keep_reset_state=False, seen_at_load_ns=t1,
                         ensure_entities=lambda gids: [r.add(ALL[g], gid=g) for g in gids])
            info["restart"] = True
    for x in feed(part2):
        out.append({"start": x.start_ns, "alerts": sorted(r[int(n)].uuid for n in x.alerts),
                    "fused": {r[int(n)].uuid: round(float(f), 5) for n, f in zip(x.node_ids, x.fused)}})
    return out, info, r


ref, _, r_ref = run(False)
got, info, r_c = run(True)
check(info["kept"] < info["before"] * 0.8, f"compaction dropped {info['before'] - info['kept']} of {info['before']} entities")
check(len(ref) == len(got) and len(ref) > 3, f"same number of later windows ({len(ref)})")
same_alerts = all(a["alerts"] == b["alerts"] for a, b in zip(ref, got))
maxdiff = max(abs(a["fused"][u] - b["fused"].get(u, 1e9)) for a, b in zip(ref, got) for u in a["fused"])
check(same_alerts and maxdiff < 1e-4, f"later windows: identical alerts, fused scores within {maxdiff:.1e}")
check(r_c.gids is not None and all(r_c.gid(r_c.get(e.uuid)) == r_ref.get(e.uuid) for e in r_c.entities[:200]),
      "kept entities keep their global ids")
# after a restart on the compacted registry the state comes from the bundle again (as for any agent restart), so
# compare with a fresh runtime that also starts from the bundle at that point
got2, info2, _ = run(True, restart_after_compact=True)
r3 = store.load_registry()
rt3 = Runtime(bdir, r3, keep_reset_state=False)
b3 = WindowBuilder(window_ns=WIN, chunk=100)
ref2 = []
for ents, ev in part2:
    for e in ents:
        r3.add(e)
    for w in b3.push(r3.get(ev.src), r3.get(ev.dst), ev.ts_ns, EDGE_TYPE_ID[ev.op], ev.event_uuid):
        x = rt3.score(w); ref2.append({u: round(float(f), 5) for u, f in zip((r3[int(n)].uuid for n in x.node_ids), x.fused)})
for w in b3.finish():
    x = rt3.score(w); ref2.append({u: round(float(f), 5) for u, f in zip((r3[int(n)].uuid for n in x.node_ids), x.fused)})
d2 = max(abs(a[u] - b["fused"][u]) for a, b in zip(ref2, got2) for u in a)
check(d2 < 1e-4, f"restart on a compacted registry: bundle state mapped to the new positions (max diff {d2:.1e})")

shutil.rmtree(tmp, ignore_errors=True)
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
