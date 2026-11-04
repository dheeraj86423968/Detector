"""On-disk baseline store: registry + per-day fused windows (no pickle; npz + json)."""
from __future__ import annotations

import json
import os
from typing import Iterable, Iterator

import numpy as np

from .schema import EDGE_TYPE_ID, Entity, Event, Registry
from .windows import Window, WindowBuilder


class WindowStore:
    """<root>/registry.json, <root>/windows/<date>/<k>.npz"""

    def __init__(self, root: str):
        self.root = root
        os.makedirs(os.path.join(root, "windows"), exist_ok=True)

    # ---- registry ----
    def save_registry(self, reg: Registry) -> None:
        json.dump({"entities": [{"uuid": e.uuid, "ntype": e.ntype, "label": e.label, "display": e.display} for e in reg.entities]},
                  open(os.path.join(self.root, "registry.json"), "w"))

    def load_registry(self) -> Registry:
        reg = Registry()
        for e in json.load(open(os.path.join(self.root, "registry.json")))["entities"]:
            reg.add(Entity(e["uuid"], e["ntype"], e["label"], e.get("display", {})))
        return reg

    # ---- windows ----
    def add_day(self, date: str, windows: Iterable[Window]) -> int:
        d = os.path.join(self.root, "windows", date)
        os.makedirs(d, exist_ok=True)
        n = 0
        for k, w in enumerate(windows):
            np.savez(os.path.join(d, f"{k:05d}.npz"), src=w.src, dst=w.dst, t=w.t, etype=w.etype,
                     start=np.int64(w.start_ns), end=np.int64(w.end_ns), uuid=np.array(w.event_uuid))
            n += 1
        return n

    def days(self) -> list[str]:
        return sorted(os.listdir(os.path.join(self.root, "windows")))

    def windows(self, date: str) -> Iterator[Window]:
        d = os.path.join(self.root, "windows", date)
        for f in sorted(os.listdir(d)):
            z = np.load(os.path.join(d, f), allow_pickle=False)
            yield Window(int(z["start"]), int(z["end"]), z["src"], z["dst"], z["t"], z["etype"], z["uuid"].tolist())

    def count(self, date: str) -> int:
        return len(os.listdir(os.path.join(self.root, "windows", date)))


def ingest_day(reg: Registry, events: Iterable[Event], lookup: dict | None = None, window_ns: int | None = None,
               stats: dict | None = None) -> Iterator[Window]:
    """Map events to dense ids (registering entities on first sight when `lookup` is given) and build fused windows.
    `stats` (optional) receives the number of events dropped because an endpoint entity is unknown."""
    b = WindowBuilder(window_ns) if window_ns else WindowBuilder()
    dropped = 0
    for ev in events:
        s, d = reg.get(ev.src), reg.get(ev.dst)
        if (s is None or d is None) and lookup is not None:
            es, ed = lookup.get(ev.src), lookup.get(ev.dst)
            if es is None or ed is None:
                dropped += 1
                continue
            s, d = reg.add(es), reg.add(ed)
        if s is None or d is None:
            dropped += 1
            continue
        yield from b.push(s, d, ev.ts_ns, EDGE_TYPE_ID[ev.op], ev.event_uuid)
    yield from b.finish()
    if stats is not None:
        stats["dropped"] = stats.get("dropped", 0) + dropped


def nodes_in_days(store: WindowStore, dates: list[str]) -> np.ndarray:
    seen = set()
    for d in dates:
        for w in store.windows(d):
            seen.update(np.unique(np.concatenate([w.src, w.dst])).tolist())
    return np.array(sorted(seen), dtype=np.int64)
