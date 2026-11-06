"""Collector front-ends with a common interface: `batches(stop) -> iterator of lists of (entities, Event)`."""
from __future__ import annotations

import time
from typing import Callable, Iterator

from pdp_engine.schema import Entity, Event

from .auditd import AuditNormaliser, follow


class AuditdLive:
    chronological = True   # wall-clock timestamps: a calendar day is complete once it has ended

    def __init__(self, log_path: str = "/var/log/audit/audit.log", batch: int = 2000):
        self.log_path, self.batch = log_path, batch
        self.norm = AuditNormaliser()

    def batches(self, stop: Callable[[], bool]) -> Iterator[list]:
        buf, last = [], time.time()
        # idle ticks (None) while audit.log is quiet: the agent's loop keeps running (status, heartbeat, scoring) - before
        # 0.6 a quiet log held it, so a quiet host stopped sending heartbeats
        for line in follow(self.log_path, stop, idle_tick=1.0):
            if line is not None:
                buf.extend(self.norm.feed(line))
            if len(buf) >= self.batch or time.time() - last > 2:
                yield buf; buf, last = [], time.time()
        buf.extend(self.norm.flush())
        if buf:
            yield buf


class DatabaseReplay:
    """Benchmark/simulation endpoints: replay a PIDSMaker-style database day by day (runs server-side).
    `days` are emitted in order; after each day the agent marks it complete through the state object."""

    def __init__(self, database: str, days: list[str], host: str = "postgres", batch: int = 20000, state=None, pace: float = 0.0):
        from pdp_engine.sources.pg_replay import PostgresReplay
        self.src = PostgresReplay(database, host=host)
        self.days, self.batch, self.state, self.pace = days, batch, state, pace
        self.lookup = None

    def batches(self, stop: Callable[[], bool]) -> Iterator[list]:
        if self.lookup is None:
            self.lookup = self.src.entity_index()
        done = set(self.state.get("replay_days_done", [])) if self.state else set()
        for d in self.days:
            if d in done or stop():
                continue
            # days beyond the baseline are replayed only once a bundle is deployed, so they are scored as they
            # stream (like a live endpoint) instead of piling up in the spool during training
            if self.state is not None:
                need = int((self.state.get("config") or {}).get("baseline_days", 7)) + 1
                seen = [x for x, _, _ in self.state.days()]
                while len(seen) >= need and d not in seen[:need] and not self.state.get("bundle_id") and not stop():
                    yield []
                    time.sleep(5)
            buf = []
            for ev in self.src.events(d):
                es, ed = self.lookup.get(ev.src), self.lookup.get(ev.dst)
                if es is None or ed is None:
                    continue
                buf.append(([es, ed], ev))
                if len(buf) >= self.batch:
                    yield buf; buf = []
                    if self.pace:
                        time.sleep(self.pace)
            if buf:
                yield buf
            if self.state:
                self.state.complete_day(d)
                self.state.set("replay_days_done", sorted(done | {d})); done.add(d)
            yield []  # idle tick so the agent can run status/upload between days
        while not stop():   # keep serving status/heartbeat until stopped
            yield []
            time.sleep(5)
