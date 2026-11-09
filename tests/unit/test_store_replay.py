"""Store replay (agent source "store-replay", benchmark endpoints): the edges kept in window stores come back exactly
(entities, edge type, time, event uuid, stored order), each day from the store that has it; a one-window day is built
again into the stored window; days already replayed are skipped after a restart.
Run: PYTHONPATH=engine:agent python tests/unit/test_store_replay.py"""
import os
import sys
import tempfile

import numpy as np

from pdp_agent.sources.live import StoreReplay
from pdp_engine.data import WindowStore, ingest_day
from pdp_engine.schema import EDGE_TYPES, Entity, Event, Registry

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


M = 60 * 10**9
ents = [Entity.process("p1", "/bin/sh", "sh -c x"), Entity.file("f1", "/etc/passwd"), Entity.socket("n1", "10.0.0.1", 443),
        Entity.process("p2", "/usr/bin/curl", "curl x", pid=7)]
look = {e.uuid: e for e in ents}


def day_events(day, base, n, ops=("READ", "WRITE", "CONNECT", "CLONE")):
    pairs = {"READ": ("f1", "p1"), "WRITE": ("p1", "f1"), "CONNECT": ("p2", "n1"), "CLONE": ("p1", "p2")}
    return [Event(base + i * 7 * M, *(lambda s, d: (s, op, d))(*pairs[op]), f"{day}-{i}") for i, op in
            ((i, ops[i % len(ops)]) for i in range(n))]


tmp = tempfile.mkdtemp()
days = {"2024-01-01": day_events("a", 0, 40), "2024-01-02": day_events("b", 24 * 60 * M, 25),
        "2024-01-03": day_events("c", 48 * 60 * M, 30)}
reg = Registry()
base, ev = WindowStore(os.path.join(tmp, "baseline")), WindowStore(os.path.join(tmp, "eval-test"))
for d in ("2024-01-01", "2024-01-02"):
    base.add_day(d, ingest_day(reg, days[d], look))
base.save_registry(reg)
ev.add_day("2024-01-03", ingest_day(reg, days["2024-01-03"], look))
ev.save_registry(reg)            # the later store's registry extends the earlier one (dense ids agree)


def replay(roots, ds, state=None):
    """Every batch until the idle tick that follows the last day to replay (the source then idles until stopped)."""
    todo = len([d for d in ds if d not in ((state.get("replay_days_done") or []) if state else [])])
    out, idle = [], 0
    for b in StoreReplay(roots, ds, batch=16, state=state).batches(lambda: False):
        out.extend(b)
        idle += not b
        if idle == todo:
            break
    return out


roots = [base.root, ev.root]
items = replay(roots, ["2024-01-01", "2024-01-02", "2024-01-03"])
got = [it[1] for it in items]
uu = {}
for d, st in (("2024-01-01", base), ("2024-01-02", base), ("2024-01-03", ev)):
    r = st.load_registry()
    for w in st.windows(d):
        for s_, t_, e_, ts_, u_ in zip(w.src.tolist(), w.dst.tolist(), w.etype.tolist(), w.t.tolist(), w.event_uuid):
            uu.setdefault(d, []).append((ts_, r.entities[s_].uuid, EDGE_TYPES[e_], r.entities[t_].uuid, u_))
want = uu["2024-01-01"] + uu["2024-01-02"] + uu["2024-01-03"]
check([(e.ts_ns, e.src, e.op, e.dst, e.event_uuid) for e in got] == want and 0 < len(want) < 95,
      f"every stored (fused) edge comes back with its time, entities, edge type and uuid, in stored order ({len(got)} of {len(want)}, from 95 raw events)")
check(all(it[0][0].uuid == it[1].src and it[0][1].uuid == it[1].dst for it in items), "each event carries its two entities")
check({it[0][0].label for it in items if it[0][0].uuid == "p2"} == {"subject /usr/bin/curl curl x"}
      and next(it[0][0] for it in items if it[0][0].uuid == "p2").display == {"pid": 7}, "labels and display details are kept")
# a day in one window (< 1024 raw events): the window built again from the replay (the server's ingest of the upload)
# has the stored window's edges (fusing fused edges changes nothing)
reg2 = Registry()
for d, st in (("2024-01-01", base), ("2024-01-02", base), ("2024-01-03", ev)):
    a = list(st.windows(d))
    b = list(ingest_day(reg2, [e for e in got if e.event_uuid[0] == "abc"[["2024-01-01", "2024-01-02", "2024-01-03"].index(d)]], look))
    key = lambda w, r: [(r.entities[s_].uuid, r.entities[t_].uuid, int(ts_), int(e_), u_) for s_, t_, ts_, e_, u_ in
                        zip(w.src.tolist(), w.dst.tolist(), w.t.tolist(), w.etype.tolist(), w.event_uuid)]
    r1 = st.load_registry()
    check(len(a) == len(b) == 1 and key(a[0], r1) == key(b[0], reg2) and a[0].start_ns == b[0].start_ns,
          f"{d}: the window built again from the replayed edges has the stored window's edges and start")
# a day in no store is refused up front; a day in both stores comes from the first listed
try:
    StoreReplay(roots, ["2024-01-01", "2024-01-09"])
    check(False, "a day in no store is refused")
except ValueError as e:
    check("2024-01-09" in str(e), "a day in no store is refused")


class FakeState:
    def __init__(self, done=()):
        self.kv = {"replay_days_done": list(done)}
        self.completed = []

    def get(self, k, default=None):
        return self.kv.get(k, default)

    def set(self, k, v):
        self.kv[k] = v

    def days(self):
        return [(d, 0, 0) for d in self.completed]

    def complete_day(self, d):
        self.completed.append(d)


st = FakeState(done=["2024-01-01"])
st.kv["bundle_id"] = "b"         # a model is deployed: days after the baseline are not held back
items = replay(roots, ["2024-01-01", "2024-01-02", "2024-01-03"], state=st)
check({it[1].event_uuid[0] for it in items} == {"b", "c"} and st.completed == ["2024-01-02", "2024-01-03"]
      and st.get("replay_days_done") == ["2024-01-01", "2024-01-02", "2024-01-03"],
      "after a restart, days already replayed are skipped and each finished day is marked complete")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
