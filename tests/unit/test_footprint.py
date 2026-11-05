"""Agent footprint: compact spool (purge, cap, migration), per-slot edge types, deduplicated node features."""
import os
import sqlite3
import sys
import tempfile
import time

import numpy as np
import torch

from pdp_engine.models import LastNeighborLoader, TGNState
from pdp_engine.runtime import NodeFeatures
from pdp_engine.schema import EDGE_TYPES, Entity, Registry
from pdp_agent.state import State

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


tmp = tempfile.mkdtemp()
now = time.time_ns()
DAY = "2026-11-04"

# 1. spool: compact rows round-trip, purge finished rows, uploaded+unscored kept while a model scores
st = State(os.path.join(tmp, "a", "state.sqlite"))
check(st.c.execute("PRAGMA auto_vacuum").fetchone()[0] == 2, "new spool uses incremental auto-vacuum")
st.add_events([(now + i, i % 7, "READ", (i + 1) % 7, f"r:{i:010d}", DAY) for i in range(1000)])
rows = st.pending_events(DAY, 10)
check(rows[0][2:5] == (0, "READ", 1) and rows[0][5] == "r:0000000000", f"rows come back with registry ids and op names {rows[0]}")
ids = [r[0] for r in st.pending_events(DAY, 2000)]
st.mark_events_uploaded(ids[:600])
st.mark_scored(ids[300:900])
r = st.purge([DAY], scoring=True)
left = st.c.execute("SELECT count(*) FROM events").fetchone()[0]
check(r["finished"] == 300 and left == 700, f"only uploaded+scored baseline rows are deleted ({r}, {left} left)")
# a non-baseline day (protected): scored rows go without upload
st.add_events([(now + i, 1, "WRITE", 2, f"r:{i:010d}", "2026-11-20") for i in range(50)])
st.mark_scored([r[0] for r in st.unscored_events() if r[1] >= now and r[3] == "WRITE"])
r = st.purge([DAY], scoring=True)
check(r["finished"] == 50, f"scored rows of later days are deleted without upload ({r})")

# 2. no model yet: uploaded baseline rows older than the limit stop waiting for scoring
old = now - 8 * 3600 * 10**9
st2 = State(os.path.join(tmp, "b", "state.sqlite"))
st2.add_events([(old + i, 0, "OPEN", 1, f"r:{i:010d}", DAY) for i in range(100)] + [(now + i, 0, "OPEN", 1, f"s:{i:010d}", DAY) for i in range(100)])
st2.mark_events_uploaded([r[0] for r in st2.pending_events(DAY, 1000)])
r = st2.purge([DAY], scoring=False, unscored_max_age_s=6 * 3600)
check(r["trained_on"] == 100 and r["finished"] == 100, f"8-hour-old uploaded rows leave without a model, recent ones wait ({r})")
r = st2.purge([DAY], scoring=True)
check(r["trained_on"] == 0 and st2.unscored_count() == 100, "with a model loaded nothing is aged out")

# 3. size cap: uploaded rows are dropped first, then anything; counted
st3 = State(os.path.join(tmp, "c", "state.sqlite"))
pad = "x" * 200
st3.add_events([(now + i, 0, "OPEN", 1, f"{pad}{i}", DAY) for i in range(20000)])
st3.mark_events_uploaded([r[0] for r in st3.pending_events(DAY, 10000)])
size = st3.size_bytes()
r = st3.purge([DAY], scoring=True, max_bytes=size // 2)
check(9000 <= r["dropped_unscored"] <= 13000 and r["dropped_unuploaded"] == 0 and st3.size_bytes() <= size // 2, f"cap drops uploaded rows first ({r}, {st3.size_bytes()} <= {size // 2})")
r = st3.purge([DAY], scoring=True, max_bytes=size // 6)
check(0 < r["dropped_unuploaded"] < 10000 and st3.size_bytes() <= size // 6 and st3.get("dropped_unuploaded") == r["dropped_unuploaded"],
      f"then the oldest un-uploaded rows, counted in kv ({r})")
first = st3.pending_events(DAY, 1)[0][5]
check(first.endswith(str(19999 - st3.unuploaded_count() + 1)), f"the newest rows survive ({first[-6:]})")

# 4. migration of a 0.3.3 spool (uuid strings, finished rows kept for two days)
p = os.path.join(tmp, "d", "state.sqlite"); os.makedirs(os.path.dirname(p))
c = sqlite3.connect(p)
c.executescript("""
CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE entities (dense_id INTEGER PRIMARY KEY, uuid TEXT UNIQUE NOT NULL, ntype TEXT NOT NULL, label TEXT NOT NULL, display TEXT, uploaded INTEGER DEFAULT 0);
CREATE TABLE spool (id INTEGER PRIMARY KEY, ts_ns INTEGER NOT NULL, src TEXT NOT NULL, op TEXT NOT NULL, dst TEXT NOT NULL, event_uuid TEXT NOT NULL, day TEXT NOT NULL, uploaded INTEGER DEFAULT 0, scored INTEGER DEFAULT 0);
CREATE TABLE days (day TEXT PRIMARY KEY, completed INTEGER DEFAULT 0, reported INTEGER DEFAULT 0);
""")
c.executemany("INSERT INTO entities (uuid, ntype, label, display) VALUES (?,?,?,?)",
              [("p:1", "subject", "subject /bin/sh sh", '{"pid": 1}'), ("file:/etc/passwd", "file", "file /etc/passwd", "{}")])
c.execute("INSERT INTO days (day) VALUES (?)", (DAY,))
rows = [(now + i, "p:1", "READ", "file:/etc/passwd", f"r:{i}", DAY, int(i < 80), int(i < 50)) for i in range(100)]
c.executemany("INSERT INTO spool (ts_ns, src, op, dst, event_uuid, day, uploaded, scored) VALUES (?,?,?,?,?,?,?,?)", rows)
c.commit(); c.close()
st4 = State(p)
reg = st4.load_registry(display=False)
check(reg[0].display == {} and reg.get("file:/etc/passwd") == 1, "registry loads without display data")
check(st4.displays(["p:1"]) == {"p:1": {"pid": 1}}, "display data is read from disk on demand")
n = st4.migrate_spool(reg, [DAY])
check(n == 50 and not st4.has_old_spool() and st4.c.execute("PRAGMA auto_vacuum").fetchone()[0] == 2,
      f"migration keeps the 50 rows with work left, drops the old table, switches to auto-vacuum ({n})")
check(st4.unscored_count() == 50 and st4.unuploaded_count() == 20, "upload/score flags carried over")

# 5. per-slot edge types == PIDSMaker's global edge-type history
torch.manual_seed(0)
N, size = 50, 5
L = LastNeighborLoader(N, size)
hist = []
for _ in range(40):
    k = int(torch.randint(1, 30, (1,)))
    s, d = torch.randint(0, N, (k,)), torch.randint(0, N, (k,))
    et = torch.randint(0, len(EDGE_TYPES), (k,))
    L.insert(s, d, et)
    hist.extend(et.tolist())
q = torch.randint(0, N, (20,)).unique()
n_id, ei, e_id, slot_et = L(q, with_etype=True)
ref = torch.tensor(hist, dtype=torch.int8)[e_id]
check(torch.equal(slot_et, ref), f"slot edge types equal the global history lookup over {len(hist)} edges")
# an old-format snapshot (global history) loads into the same slot types
st_old = {"neighbors": L.neighbors.clone(), "e_id": L.e_id.clone(), "cur_e_id": L.cur_e_id, "etype": torch.tensor(hist, dtype=torch.int8), "n": len(hist)}
T = TGNState(N + 10, size)
T.load_state(st_old)
check(torch.equal(T.loader.etype[:N][L.e_id >= 0], L.etype[L.e_id >= 0]) and T.loader.e_id[N:].eq(-1).all(), "old snapshots convert to per-slot types; extra rows empty")

# 6. deduplicated node features equal the plain matrix
class Feat:
    def features(self, labels, types):
        return np.stack([np.full(4, (hash(l) % 1000) / 1000.0, dtype=np.float32) for l in labels])
F = Feat()
reg = Registry()
for i in range(30):
    reg.add(Entity(f"u{i}", "subject", f"subject /bin/x {i % 4}"))
X = NodeFeatures(4, "cpu")
X.resize(35)
X.assign([(i, reg[i].label, reg[i].ntype) for i in range(30)], F)
plain = torch.zeros((35, 4)); plain[:30] = torch.from_numpy(F.features([reg[i].label for i in range(30)], None))
idx = torch.tensor([0, 5, 29, 31, 3])
check(torch.equal(X[idx], plain[idx]) and X.shape == (35, 4) and X.rows == 5, f"feature rows match the plain matrix, stored once per label ({X.rows - 1} labels)")
X.resize(10)
check(X.shape == (10, 4) and torch.equal(X[torch.arange(10)], plain[:10]), "truncate keeps the base rows")

# after the final model: baseline processes and connections nobody holds are deleted, baseline files stay (the rules
# tell pre-existing files by global id), held ones and post-baseline rows are untouched, ids are never reused
st5 = State(os.path.join(tmp, "e", "state.sqlite"))
kinds = ["subject", "file", "netflow"]
st5.add_entities([(Entity(f"e{i}", kinds[i % 3], f"{kinds[i % 3]} /x/{i}", {"pid": i}), i) for i in range(3000)])
n_pre = 2400
held = {3, 4, 5, 2500}
gone = st5.prune_baseline_transients(held, n_pre)
left = dict(st5.c.execute("SELECT dense_id - 1, ntype FROM entities").fetchall())
check(gone == 1600 - 2 and all(left.get(g) == "file" for g in range(1, n_pre, 3)), f"baseline processes/connections deleted ({gone}), files kept")
check(3 in left and 5 in left and all(g in left for g in range(n_pre, 3000)), "held entities and post-baseline rows kept")
check(st5.next_gid() == 3000, "global ids are not reused after pruning")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
