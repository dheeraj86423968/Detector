"""Collector front-ends with a common interface: `batches(stop) -> iterator of lists of (entities, Event)`."""
from __future__ import annotations

import json
import os
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

    def __init__(self, database: str, days: list[str], host: str = "postgres", batch: int = 20000, state=None, pace: float = 0.0,
                 edr: bool = False, nodes: set[str] | None = None):
        if edr:      # Carbon Black EDR databases (ATLASv2), optionally one host's nodes of a multi-host database
            from pdp_engine.sources.edr_replay import EdrPostgresReplay
            self.src = EdrPostgresReplay(database, nodes=nodes, host=host)
        else:
            from pdp_engine.sources.pg_replay import PostgresReplay
            self.src = PostgresReplay(database, host=host)
        self.days, self.batch, self.state, self.pace = days, batch, state, pace
        self.lookup = None

    def _day_items(self, d: str) -> Iterator[tuple]:
        """([source entity, destination entity], Event) of one day, in replay order."""
        if self.lookup is None:
            self.lookup = self.src.entity_index()
        for ev in self.src.events(d):
            es, ed = self.lookup.get(ev.src), self.lookup.get(ev.dst)
            if es is not None and ed is not None:
                yield [es, ed], ev

    def batches(self, stop: Callable[[], bool]) -> Iterator[list]:
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
            for item in self._day_items(d):
                buf.append(item)
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


class StoreReplay(DatabaseReplay):
    """Benchmark endpoints: replay the edges kept in window stores (pdp_engine.data.WindowStore: <root>/registry.json,
    <root>/windows/<day>/<k>.npz), for benchmark hosts converted from databases that are no longer available. Every
    stored edge is emitted with its original entity uuids, labels, edge type, time and event uuid, in stored order;
    each day comes from the first of `roots` that has it. Day handling (baseline first, the rest once a model is
    deployed) is DatabaseReplay's.
    Not the raw stream: stored windows are fused (pdp_engine.windows: repeated operations between the same two
    entities are one edge) and were cut every 1024 raw events, so windows built again from the stored edges can be cut
    at other times on busy days. Use db-replay where the database still exists."""

    def __init__(self, roots: list[str], days: list[str], batch: int = 20000, state=None, pace: float = 0.0):
        self.roots, self.days, self.batch, self.state, self.pace = list(roots), days, batch, state, pace
        self._ents: dict[str, list] = {}
        missing = [d for d in days if self._root(d) is None]
        if missing:
            raise ValueError(f"days not in any store: {missing}")

    def _root(self, d: str) -> str | None:
        return next((r for r in self.roots if os.path.isdir(os.path.join(r, "windows", d))), None)

    def _entities(self, root: str) -> list:
        if root not in self._ents:    # one registry in memory at a time (stores of one host: the later one extends the earlier)
            self._ents = {root: [Entity(e["uuid"], e["ntype"], e["label"], e.get("display") or {})
                                 for e in json.load(open(os.path.join(root, "registry.json")))["entities"]]}
        return self._ents[root]

    def _day_items(self, d: str) -> Iterator[tuple]:
        from pdp_engine.data import WindowStore
        from pdp_engine.schema import EDGE_TYPES
        root = self._root(d)
        ents = self._entities(root)
        for w in WindowStore(root).windows(d):
            for s, t, e, ts, u in zip(w.src.tolist(), w.dst.tolist(), w.etype.tolist(), w.t.tolist(), w.event_uuid):
                es, ed = ents[s], ents[t]
                yield [es, ed], Event(int(ts), es.uuid, EDGE_TYPES[e], ed.uuid, str(u))
