"""Agent local state (sqlite): identity, phase, entity registry persistence, event spool and upload cursors."""
from __future__ import annotations

import json
import os
import sqlite3
import time

from pdp_engine.schema import Entity, Registry

DDL = """
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS entities (dense_id INTEGER PRIMARY KEY, uuid TEXT UNIQUE NOT NULL, ntype TEXT NOT NULL, label TEXT NOT NULL, display TEXT, uploaded INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS spool (id INTEGER PRIMARY KEY, ts_ns INTEGER NOT NULL, src TEXT NOT NULL, op TEXT NOT NULL, dst TEXT NOT NULL, event_uuid TEXT NOT NULL, day TEXT NOT NULL, uploaded INTEGER DEFAULT 0, scored INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS spool_day ON spool(day, uploaded);
CREATE INDEX IF NOT EXISTS spool_scored ON spool(scored, ts_ns);
CREATE TABLE IF NOT EXISTS days (day TEXT PRIMARY KEY, completed INTEGER DEFAULT 0, reported INTEGER DEFAULT 0);
"""


class State:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.c = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.execute("PRAGMA synchronous=NORMAL")
        for stmt in DDL.strip().split(";"):
            if stmt.strip():
                self.c.execute(stmt)

    # kv
    def get(self, k: str, default=None):
        r = self.c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return json.loads(r[0]) if r else default

    def set(self, k: str, v) -> None:
        self.c.execute("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, json.dumps(v)))

    # registry
    def load_registry(self) -> Registry:
        reg = Registry()
        for uuid, nt, label, disp in self.c.execute("SELECT uuid, ntype, label, display FROM entities ORDER BY dense_id"):
            reg.add(Entity(uuid, nt, label, json.loads(disp) if disp else {}))
        return reg

    def add_entities(self, ents: list[Entity]) -> None:
        self.c.executemany("INSERT OR IGNORE INTO entities (uuid, ntype, label, display) VALUES (?,?,?,?)",
                           [(e.uuid, e.ntype, e.label, json.dumps(e.display)) for e in ents])

    def pending_entities(self, limit: int = 5000) -> list[dict]:
        rows = self.c.execute("SELECT uuid, ntype, label, display FROM entities WHERE uploaded=0 ORDER BY dense_id LIMIT ?", (limit,)).fetchall()
        return [{"uuid": u, "ntype": t, "label": l, "display": json.loads(d) if d else {}} for u, t, l, d in rows]

    def mark_entities_uploaded(self, uuids: list[str]) -> None:
        self.c.executemany("UPDATE entities SET uploaded=1 WHERE uuid=?", [(u,) for u in uuids])

    # spool
    def add_events(self, evs: list[tuple]) -> None:
        """evs: (ts_ns, src, op, dst, event_uuid, day)"""
        self.c.executemany("INSERT INTO spool (ts_ns, src, op, dst, event_uuid, day) VALUES (?,?,?,?,?,?)", evs)

    def pending_events(self, day: str, limit: int = 20000) -> list[tuple]:
        return self.c.execute("SELECT id, ts_ns, src, op, dst, event_uuid FROM spool WHERE day=? AND uploaded=0 ORDER BY id LIMIT ?", (day, limit)).fetchall()

    def mark_events_uploaded(self, ids: list[int]) -> None:
        self.c.executemany("UPDATE spool SET uploaded=1 WHERE id=?", [(i,) for i in ids])

    def unscored_events(self, limit: int = 200000) -> list[tuple]:
        return self.c.execute("SELECT id, ts_ns, src, op, dst, event_uuid FROM spool WHERE scored=0 ORDER BY ts_ns, id LIMIT ?", (limit,)).fetchall()

    def mark_scored(self, ids: list[int]) -> None:
        self.c.executemany("UPDATE spool SET scored=1 WHERE id=?", [(i,) for i in ids])

    def mark_days_scored(self, days: list[str]) -> int:
        """Baseline days the bundle was trained/calibrated on are not scored again."""
        n = 0
        for d in days:
            n += self.c.execute("UPDATE spool SET scored=1 WHERE day=? AND scored=0", (d,)).rowcount
        self.c.commit()
        return n

    def mark_scored_before(self, ts_ns: int) -> int:
        """Activity a model was trained/calibrated on (up to ts_ns) is not scored again."""
        n = self.c.execute("UPDATE spool SET scored=1 WHERE ts_ns <= ? AND scored=0", (int(ts_ns),)).rowcount
        self.c.commit()
        return n

    def purge_scored(self, keep_days: int = 2, baseline_days: list[str] = ()) -> int:
        """Drop scored rows older than the retention window that no longer need uploading: baseline-day rows once
        uploaded, rows of any later day right away (only the baseline leaves the host). Returns rows removed."""
        cutoff = int((time.time() - keep_days * 86400) * 1e9)
        marks = ",".join("?" for _ in baseline_days) or "''"
        # baseline-day rows are never scored locally (the bundle is calibrated on them), so they can go as soon as the
        # server has acknowledged their upload; later days stay only until scored
        n = self.c.execute(f"DELETE FROM spool WHERE ts_ns < ? AND ((uploaded=1 AND day IN ({marks})) OR (scored=1 AND day NOT IN ({marks})))",
                           (cutoff, *baseline_days, *baseline_days)).rowcount
        if n:
            self.c.commit()
        return n

    # days
    def days(self) -> list[tuple]:
        return self.c.execute("SELECT day, completed, reported FROM days ORDER BY rowid").fetchall()

    def touch_day(self, day: str) -> None:
        self.c.execute("INSERT OR IGNORE INTO days (day) VALUES (?)", (day,))

    def complete_day(self, day: str) -> None:
        self.c.execute("UPDATE days SET completed=1 WHERE day=?", (day,))

    def mark_day_reported(self, day: str) -> None:
        self.c.execute("UPDATE days SET reported=1 WHERE day=?", (day,))
