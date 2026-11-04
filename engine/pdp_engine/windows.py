"""Streaming construction of time-window graphs with the research semantics.

Reproduces PIDSMaker's `gen_edge_fused_tw` (build_default_graphs.py): events are consumed in chunks of
1024 in time order; a window closes when the last event of a chunk is more than `window_ns` after the
window's first event (or at the end of the stream). Inside a window, for every (src, dst) pair the
events are sorted by time and consecutive events with the same operation are fused into one edge
(the first of each run is kept).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Iterator

import numpy as np

from .schema import EDGE_TYPE_ID, WINDOW_NS, Event

CHUNK = 1024


@dataclass
class Window:
    start_ns: int
    end_ns: int
    src: np.ndarray        # dense node ids (int64)
    dst: np.ndarray
    t: np.ndarray          # int64 ns
    etype: np.ndarray      # int64 edge type id
    event_uuid: list[str]

    @property
    def num_edges(self) -> int:
        return len(self.src)

    def nodes(self) -> np.ndarray:
        return np.unique(np.concatenate([self.src, self.dst]))

    @property
    def name(self) -> str:
        return f"{self.start_ns}~{self.end_ns}"


def fuse(events: list[tuple[int, int, int, int, str]]) -> Window:
    """events: (src_id, dst_id, ts_ns, etype_id, event_uuid) in stream order. Returns the fused window."""
    pairs: dict[tuple[int, int], list[tuple[int, int, str]]] = defaultdict(list)
    for s, d, t, e, u in events:
        pairs[(s, d)].append((t, e, u))
    src, dst, ts, et, uu = [], [], [], [], []
    for (s, d), items in pairs.items():  # insertion order of pairs, as in the framework (dict order)
        items.sort(key=lambda x: x[0])   # stable sort by time
        cur = None
        for t, e, u in items:
            if e == cur:
                continue
            cur = e
            src.append(s); dst.append(d); ts.append(t); et.append(e); uu.append(u)
    return Window(events[0][2], events[-1][2], np.array(src, dtype=np.int64), np.array(dst, dtype=np.int64),
                  np.array(ts, dtype=np.int64), np.array(et, dtype=np.int64), uu)


class WindowBuilder:
    """Feed time-ordered events (already mapped to dense ids); yields fused windows."""

    def __init__(self, window_ns: int = WINDOW_NS, chunk: int = CHUNK):
        self.window_ns = window_ns
        self.chunk = chunk
        self._buf: list[tuple[int, int, int, int, str]] = []   # current window events
        self._chunk: list[tuple[int, int, int, int, str]] = []
        self._start: int | None = None

    def push(self, src_id: int, dst_id: int, ts_ns: int, etype_id: int, event_uuid: str) -> Iterator[Window]:
        self._chunk.append((src_id, dst_id, ts_ns, etype_id, event_uuid))
        if len(self._chunk) == self.chunk:
            yield from self._flush_chunk(last=False)

    def _flush_chunk(self, last: bool) -> Iterator[Window]:
        if not self._chunk:
            return
        if self._start is None:
            self._start = self._chunk[0][2]
        self._buf.extend(self._chunk)
        chunk_last_t = self._chunk[-1][2]
        self._chunk = []
        if chunk_last_t > self._start + self.window_ns or last:
            w = fuse(self._buf)
            w.start_ns = self._start          # framework naming: window starts where the previous one ended
            w.end_ns = chunk_last_t
            self._buf = []
            self._start = chunk_last_t        # next window measures its 15 minutes from this timestamp
            yield w

    def finish(self) -> Iterator[Window]:
        """Close the stream (end of a day in batch mode, or shutdown)."""
        yield from self._flush_chunk(last=True)
        if self._buf:  # the last chunk was exactly full and did not exceed the window length
            w = fuse(self._buf); w.start_ns = self._start; self._buf = []
            yield w
        self._start = None

    def remap(self, old2new) -> None:
        """Renumber the buffered events' node ids (registry compaction); old2new: old id -> new id."""
        m = old2new
        self._buf = [(m[e[0]], m[e[1]]) + tuple(e[2:]) for e in self._buf]
        self._chunk = [(m[e[0]], m[e[1]]) + tuple(e[2:]) for e in self._chunk]

    def node_ids(self) -> set:
        return {e[0] for e in self._buf} | {e[1] for e in self._buf} | {e[0] for e in self._chunk} | {e[1] for e in self._chunk}

    def state(self) -> dict:
        """Serialisable builder state: the events buffered in the still-open window and current chunk, plus the
        window start timestamp. Persisted by the agent so a restart does not lose up to one window of events."""
        return {"buf": self._buf, "chunk": self._chunk, "start": self._start,
                "window_ns": self.window_ns, "chunk_size": self.chunk}

    def load_state(self, st: dict) -> None:
        if not st:
            return
        self.window_ns = int(st.get("window_ns", self.window_ns))
        self.chunk = int(st.get("chunk_size", self.chunk))
        self._buf = [tuple(e) for e in st.get("buf", [])]
        self._chunk = [tuple(e) for e in st.get("chunk", [])]
        self._start = st.get("start")

    @property
    def pending(self) -> int:
        """Events held in the open window / chunk (not yet emitted in a completed window)."""
        return len(self._buf) + len(self._chunk)


def build_windows(events: Iterable[tuple[int, int, int, int, str]], window_ns: int = WINDOW_NS) -> list[Window]:
    """Batch helper: all windows of a time-ordered event sequence (e.g. one day)."""
    b = WindowBuilder(window_ns)
    out: list[Window] = []
    for ev in events:
        out.extend(b.push(*ev))
    out.extend(b.finish())
    return out


def batches(w: Window, size: int = 1024) -> Iterator[tuple[int, int]]:
    """Consecutive edge slices of a window (the intra-window batching of the detectors)."""
    for i in range(0, w.num_edges, size):
        yield i, min(i + size, w.num_edges)
