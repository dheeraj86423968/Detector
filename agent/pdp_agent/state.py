"""Agent local state (sqlite): identity, phase, entity registry persistence, event spool and upload cursors.

The spool is a work queue, not an archive: an event stays only until it has been uploaded (baseline days) and scored
(once a model is loaded), then it is deleted. Rows are compact (registry ids instead of entity uuids, which for files
are whole paths), the WAL is kept small, freed pages are returned to the file system, and a hard size cap protects the
host's disk when the server is unreachable for a long time: the oldest rows are dropped first, and every drop is
counted and reported in the heartbeat.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time

from pdp_engine.schema import EDGE_TYPE_ID, EDGE_TYPES, NO_DISPLAY, Entity, Registry

DDL = """
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS entities (dense_id INTEGER PRIMARY KEY, uuid TEXT UNIQUE NOT NULL, ntype TEXT NOT NULL, label TEXT NOT NULL, display TEXT, uploaded INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS days (day TEXT PRIMARY KEY, completed INTEGER DEFAULT 0, reported INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts_ns INTEGER NOT NULL, src INTEGER NOT NULL, op INTEGER NOT NULL, dst INTEGER NOT NULL, eid TEXT NOT NULL, day INTEGER NOT NULL, uploaded INTEGER NOT NULL DEFAULT 0, scored INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS events_upload ON events(day, id) WHERE uploaded=0;
CREATE INDEX IF NOT EXISTS events_score ON events(ts_ns, id) WHERE scored=0;
"""
WAL_LIMIT = 64 << 20          # the WAL is truncated back to this size after a checkpoint


class State:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.c = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.execute("PRAGMA synchronous=NORMAL")
        self.c.execute(f"PRAGMA journal_size_limit={WAL_LIMIT}")
        need_vacuum = self.c.execute("PRAGMA auto_vacuum").fetchone()[0] != 2
        if need_vacuum:
            # incremental auto-vacuum lets the purge hand freed pages back to the file system; switching an existing
            # database needs one VACUUM (instant on a new one; after the old spool is migrated on an upgraded one)
            self.c.execute("PRAGMA auto_vacuum=INCREMENTAL")
        for stmt in DDL.strip().split(";"):
            if stmt.strip():
                self.c.execute(stmt)
        if need_vacuum and not self.has_old_spool():
            self._vacuum()
        self._day_ids: dict[str, int] = {}

    def _vacuum(self):
        self.c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.c.execute("VACUUM")
        self.c.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # kv
    def get(self, k: str, default=None):
        r = self.c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else default

    def set(self, k: str, v) -> None:
        self.c.execute("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v)))

    def bump(self, k: str, n: int) -> None:
        if n:
            self.set(k, int(self.get(k, 0)) + int(n))

    # registry
    def load_registry(self, display: bool = True, gids=None, after_gid: int | None = None) -> Registry:
        """display=False: entity display data (pid, argv, hashes ...) stays on disk and is read per alert with
        `displays()`; on a busy host the registry holds millions of entities and the dicts would dominate memory.
        Labels are interned: process instances of one program share one label string.

        Global id = dense_id - 1 (the append-only order the server's registry follows). gids / after_gid load only
        those entities (a compacted agent's live set and everything registered after it), in global-id order."""
        reg = Registry()
        intern = sys.intern
        cols = "dense_id - 1, uuid, ntype, label" + (", display" if display else "")

        def add(row):
            disp = (json.loads(row[4]) if row[4] else {}) if display else NO_DISPLAY
            reg.add(Entity(row[1], intern(row[2]), intern(row[3]), disp), gid=row[0])
        if gids is None:
            for row in self.c.execute(f"SELECT {cols} FROM entities ORDER BY dense_id"):
                add(row)
            return reg
        want = sorted({int(g) for g in gids})
        rows = []
        for i in range(0, len(want), 900):
            part = [g + 1 for g in want[i:i + 900]]
            rows += self.c.execute(f"SELECT {cols} FROM entities WHERE dense_id IN ({','.join('?' * len(part))})", part).fetchall()
        if after_gid is not None:
            rows += self.c.execute(f"SELECT {cols} FROM entities WHERE dense_id - 1 > ? ORDER BY dense_id", (int(after_gid),)).fetchall()
        seen = set()
        for row in sorted(rows, key=lambda r: r[0]):
            if row[0] not in seen:
                seen.add(row[0]); add(row)
        if reg.gids is None and len(reg):      # a subset is never an identity mapping, even if it happens to start at 0
            reg._split_gids()
        return reg

    def next_gid(self) -> int:
        """Next global id. Also kept in kv: pruning may delete the highest rows, and a global id is never reused."""
        n = int(self.c.execute("SELECT coalesce(max(dense_id), 0) FROM entities").fetchone()[0])
        return max(n, int(self.get("next_gid", 0) or 0))

    def prune_entities(self, keep_gids, min_gid: int, next_gid: int, require_uploaded: bool = True) -> int:
        """Delete entity rows with global id >= min_gid (registered after the model's baseline) that are not in
        keep_gids (the live set) - and uploaded, unless require_uploaded is False (protected endpoints upload no
        entities): the table would otherwise grow by every entity ever seen. Baseline entities stay (the rules
        tell pre-existing files by their global id)."""
        self.set("next_gid", int(next_gid))
        self.c.execute("CREATE TEMP TABLE IF NOT EXISTS keep_g (g INTEGER PRIMARY KEY)")
        self.c.execute("DELETE FROM keep_g")
        ks = [(int(g),) for g in keep_gids if int(g) >= min_gid]
        self._tx(lambda: self.c.executemany("INSERT OR IGNORE INTO keep_g VALUES (?)", ks))
        hi = self.next_gid()
        n = 0
        for a in range(int(min_gid), hi, 100_000):       # in slices: a bounded WAL
            n += self._tx(lambda: self.c.execute(
                "DELETE FROM entities WHERE dense_id - 1 >= ? AND dense_id - 1 < ? AND (uploaded = 1 OR ?) "
                "AND NOT EXISTS (SELECT 1 FROM keep_g WHERE g = dense_id - 1)", (a, a + 100_000, 0 if require_uploaded else 1)).rowcount)
            self.c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.c.execute("DELETE FROM keep_g")
        self.compact()
        return n

    def gid_for(self, uuid: str) -> int | None:
        r = self.c.execute("SELECT dense_id - 1 FROM entities WHERE uuid=?", (uuid,)).fetchone()
        return None if r is None else int(r[0])

    def entities_by_gid(self, gids) -> list[tuple]:
        """(gid, Entity without display) for the given global ids."""
        out, want = [], [int(g) + 1 for g in gids]
        for i in range(0, len(want), 900):
            part = want[i:i + 900]
            for g, u, t, l in self.c.execute(f"SELECT dense_id - 1, uuid, ntype, label FROM entities WHERE dense_id IN ({','.join('?' * len(part))})", part):
                out.append((int(g), Entity(u, sys.intern(t), sys.intern(l), NO_DISPLAY)))
        return out

    def spool_gids(self) -> set[int]:
        """Global ids of entities referenced by spooled events that still need uploading or scoring."""
        out = set()
        for (a,) in self.c.execute("SELECT DISTINCT src FROM events UNION SELECT DISTINCT dst FROM events"):
            out.add(int(a))
        return out

    def displays(self, uuids: list[str]) -> dict[str, dict]:
        out = {}
        for i in range(0, len(uuids), 500):
            part = uuids[i:i + 500]
            for u, d in self.c.execute(f"SELECT uuid, display FROM entities WHERE uuid IN ({','.join('?' * len(part))})", part):
                out[u] = json.loads(d) if d else {}
        return out

    def add_entities(self, ents: list) -> None:
        """ents: Entity (row id assigned by sqlite) or (Entity, global id): the row is written at dense_id = gid + 1,
        so it matches the agent's registry even after pruning deleted the highest rows."""
        rows = [(None if isinstance(x, Entity) else int(x[1]) + 1,) + ((x.uuid, x.ntype, x.label, json.dumps(x.display)) if isinstance(x, Entity)
                else (x[0].uuid, x[0].ntype, x[0].label, json.dumps(x[0].display))) for x in ents]
        self._tx(lambda: self.c.executemany("INSERT OR IGNORE INTO entities (dense_id, uuid, ntype, label, display) VALUES (?,?,?,?,?)", rows))

    def pending_entities(self, limit: int = 5000) -> list[dict]:
        """Entities not yet uploaded, with their global id as `dense_id` (the server's registry position)."""
        rows = self.c.execute("SELECT dense_id - 1, uuid, ntype, label, display FROM entities WHERE uploaded=0 ORDER BY dense_id LIMIT ?", (limit,)).fetchall()
        return [{"uuid": u, "ntype": t, "label": l, "display": json.loads(d) if d else {}, "dense_id": int(g)} for g, u, t, l, d in rows]

    def mark_entities_uploaded(self, uuids: list[str]) -> None:
        self._tx(lambda: self.c.executemany("UPDATE entities SET uploaded=1 WHERE uuid=?", [(u,) for u in uuids]))

    # spool
    def _tx(self, fn):
        self.c.execute("BEGIN")
        try:
            r = fn()
            self.c.execute("COMMIT")
            return r
        except BaseException:
            self.c.execute("ROLLBACK")
            raise

    def day_id(self, day: str) -> int:
        i = self._day_ids.get(day)
        if i is None:
            self.c.execute("INSERT OR IGNORE INTO days (day) VALUES (?)", (day,))
            i = self.c.execute("SELECT rowid FROM days WHERE day=?", (day,)).fetchone()[0]
            self._day_ids[day] = i
        return i

    def add_events(self, evs: list[tuple]) -> None:
        """evs: (ts_ns, src registry id, op, dst registry id, event_uuid, day); op is an EDGE_TYPES name."""
        rows = [(ts, s, EDGE_TYPE_ID[op], d, eid, self.day_id(day)) for ts, s, op, d, eid, day in evs]
        self._tx(lambda: self.c.executemany("INSERT INTO events (ts_ns, src, op, dst, eid, day) VALUES (?,?,?,?,?,?)", rows))

    @staticmethod
    def _rows(cur) -> list[tuple]:
        """(id, ts_ns, src id, op name, dst id, event_uuid)"""
        return [(i, ts, s, EDGE_TYPES[op], d, e) for i, ts, s, op, d, e in cur]

    def pending_events(self, day: str, limit: int = 20000) -> list[tuple]:
        return self._rows(self.c.execute("SELECT id, ts_ns, src, op, dst, eid FROM events WHERE day=? AND uploaded=0 ORDER BY id LIMIT ?",
                                         (self.day_id(day), limit)))

    def mark_events_uploaded(self, ids: list[int]) -> None:
        self._tx(lambda: self.c.executemany("UPDATE events SET uploaded=1 WHERE id=?", [(i,) for i in ids]))

    def unscored_events(self, limit: int = 200000, after: tuple | None = None, max_id: int = 0) -> list[tuple]:
        """Unscored rows in time order. after=(ts_ns, id), max_id: only rows not handed out yet - later in time than
        `after`, or inserted after `max_id` (a late event with an older timestamp)."""
        if after is None:
            return self._rows(self.c.execute("SELECT id, ts_ns, src, op, dst, eid FROM events WHERE scored=0 ORDER BY ts_ns, id LIMIT ?", (limit,)))
        ts, i = after
        return self._rows(self.c.execute("SELECT id, ts_ns, src, op, dst, eid FROM events WHERE scored=0 AND (ts_ns > ? OR (ts_ns = ? AND id > ?) OR id > ?) "
                                         "ORDER BY ts_ns, id LIMIT ?", (ts, ts, i, max_id, limit)))

    def unscored_count(self) -> int:
        return self.c.execute("SELECT count(*) FROM events WHERE scored=0").fetchone()[0]

    def unuploaded_count(self) -> int:
        return self.c.execute("SELECT count(*) FROM events WHERE uploaded=0").fetchone()[0]

    def mark_scored(self, ids: list[int]) -> None:
        self._tx(lambda: self.c.executemany("UPDATE events SET scored=1 WHERE id=?", [(i,) for i in ids]))

    def mark_days_scored(self, days: list[str]) -> int:
        """Baseline days the bundle was trained/calibrated on are not scored again."""
        ids = [r[0] for d in days if d for r in self.c.execute("SELECT rowid FROM days WHERE day=?", (d,))]   # never creates days
        return self._tx(lambda: sum(self.c.execute("UPDATE events SET scored=1 WHERE day=? AND scored=0", (i,)).rowcount for i in ids))

    def mark_scored_before(self, ts_ns: int) -> int:
        """Activity a model was trained/calibrated on (up to ts_ns) is not scored again."""
        return self._tx(lambda: self.c.execute("UPDATE events SET scored=1 WHERE scored=0 AND ts_ns <= ?", (int(ts_ns),)).rowcount)

    def size_bytes(self) -> int:
        """Bytes in use: live database pages plus the WAL."""
        pc = self.c.execute("PRAGMA page_count").fetchone()[0]
        fl = self.c.execute("PRAGMA freelist_count").fetchone()[0]
        ps = self.c.execute("PRAGMA page_size").fetchone()[0]
        try:
            wal = os.path.getsize(self.path + "-wal")
        except OSError:
            wal = 0
        return (pc - fl) * ps + wal

    def purge(self, baseline_days: list[str], scoring: bool, unscored_max_age_s: float = 6 * 3600,
              max_bytes: int = 1 << 30) -> dict:
        """Delete finished rows and keep the spool under `max_bytes`. Returns counts of what was removed.

        finished    scored, and uploaded unless its day is not a baseline day (only the baseline leaves the host)
        trained_on  no model loaded yet: baseline rows already uploaded and older than `unscored_max_age_s` are not
                    kept for scoring; the server has them and every later model is trained on them
        cap         over `max_bytes`: oldest rows whose upload is done go first (they lose local scoring), then the
                    oldest rows of all (lost for the baseline); both are counted in the heartbeat
        """
        base = [self.day_id(d) for d in baseline_days]
        inb = f"day IN ({','.join('?' * len(base))})" if base else "0"
        out = {"finished": 0, "trained_on": 0, "dropped_unscored": 0, "dropped_unuploaded": 0}
        if not scoring:
            cutoff = int((time.time() - unscored_max_age_s) * 1e9)
            out["trained_on"] = self._tx(lambda: self.c.execute(
                f"UPDATE events SET scored=1 WHERE scored=0 AND ts_ns < ? AND uploaded=1 AND {inb}", (cutoff, *base)).rowcount)
        out["finished"] = self._tx(lambda: self.c.execute(
            f"DELETE FROM events WHERE scored=1 AND (uploaded=1 OR NOT {inb})", (*base,)).rowcount)
        target = int(max_bytes * 0.9)          # once over the cap, go 10% below it (no drop on every cycle)
        for key, cond in (("dropped_unscored", f"(uploaded=1 OR NOT {inb})"), ("dropped_unuploaded", "1")):
            while (size := self.size_bytes()) > max_bytes or (out[key] and size > target):
                total = self.c.execute("SELECT count(*) FROM events").fetchone()[0]
                if not total:
                    break
                # rows to drop, from the average row size (oldest rows sit together in the id-ordered table, so
                # deleting them frees whole pages); at least 1000 so a large overshoot converges quickly
                k = max(1000, int((size - target) / (size / total)) + 1)
                n = self._tx(lambda: self.c.execute(
                    f"DELETE FROM events WHERE id IN (SELECT id FROM events WHERE {cond} ORDER BY id LIMIT ?)",
                    (*base, k) if cond != "1" else (k,)).rowcount)
                if not n:
                    break
                out[key] += n
                self.c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        for k in ("dropped_unscored", "dropped_unuploaded"):
            self.bump(k, out[k])
        self.compact()
        return out

    def compact(self) -> None:
        """Return free pages to the file system and truncate the WAL."""
        if self.c.execute("PRAGMA freelist_count").fetchone()[0] > 2048:
            self.c.execute("PRAGMA incremental_vacuum")
        self.c.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def has_old_spool(self) -> bool:
        return self.c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='spool'").fetchone() is not None

    def migrate_spool(self, reg: Registry, baseline_days: list[str]) -> int:
        """Agents before 0.3.4 kept a `spool` table with uuid strings and kept finished rows for two days. Rows that
        still have work to do move into `events`; the old table is dropped and the file shrunk."""
        if not self.has_old_spool():
            return 0
        marks = ",".join("?" * len(baseline_days)) or "''"
        keep = f"NOT (scored=1 AND (uploaded=1 OR day NOT IN ({marks})))"
        n, last = 0, 0
        while True:
            rows = self.c.execute(f"SELECT id, ts_ns, src, op, dst, event_uuid, day, uploaded, scored FROM spool WHERE id > ? AND {keep} ORDER BY id LIMIT 100000",
                                  (last, *baseline_days)).fetchall()
            if not rows:
                break
            last = rows[-1][0]
            out = []
            for _, ts, s, op, d, eid, day, up, sc in rows:
                si, di = reg.get(s), reg.get(d)
                if si is not None and di is not None:
                    out.append((ts, si, EDGE_TYPE_ID[op], di, eid, self.day_id(day), up, sc))
            self._tx(lambda: self.c.executemany("INSERT INTO events (ts_ns, src, op, dst, eid, day, uploaded, scored) VALUES (?,?,?,?,?,?,?,?)", out))
            n += len(out)
        self.c.execute("DROP TABLE spool")
        self._vacuum()
        return n

    # days
    def days(self) -> list[tuple]:
        return self.c.execute("SELECT day, completed, reported FROM days ORDER BY rowid").fetchall()

    def touch_day(self, day: str) -> None:
        self.day_id(day)

    def complete_day(self, day: str) -> None:
        self.c.execute("UPDATE days SET completed=1 WHERE day=?", (day,))

    def mark_day_reported(self, day: str) -> None:
        self.c.execute("UPDATE days SET reported=1 WHERE day=?", (day,))
