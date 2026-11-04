"""Bind an AttackGraph to a target endpoint and inject it into the fused windows of a benign day."""
from __future__ import annotations

import bisect
import random
import re
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

from pdp_engine.schema import EDGE_TYPE_ID, Entity, Registry
from pdp_engine.windows import Window, fuse

from .attacks import AttackGraph

ROLE_RE = {"web": r"nginx|httpd|apache|lighttpd|sshd|smtpd|imapd|postfix|dovecot", "browser": r"firefox|chrome|chromium|thunderbird",
           "shell": r"(^|/)(bash|sh|zsh|dash|tcsh|csh)(\s|$)", "any": r"."}


class LabelIndex:
    """label -> dense ids, built once per registry size (grows lazily)."""

    def __init__(self, reg: Registry):
        self.reg, self.n = reg, 0
        self.by_label: dict[str, list[int]] = defaultdict(list)
        self.sync()

    def sync(self):
        for i in range(self.n, len(self.reg)):
            self.by_label[self.reg[i].label].append(i)
        self.n = len(self.reg)


@dataclass
class Placement:
    day: str
    window_index: int
    start_ns: int
    host: int | None = None
    host_label: str = ""
    new_ids: list[int] = field(default_factory=list)
    malicious_ids: set[int] = field(default_factory=set)
    edges: list[tuple[int, int, int, int, str]] = field(default_factory=list)   # (src, dst, t, etype, uuid)
    bound_context: int = 0


def pick_host(role: str, window: Window, reg: Registry, rng: random.Random, day_windows: list[Window] | None = None) -> int | None:
    """A real process to attach the attack to: one matching the role in the placement window, else one matching the
    role elsewhere in the day, else any process of the placement window (weighted by activity)."""
    pat = re.compile(ROLE_RE.get(role, "."))
    deg = defaultdict(int)
    for a in np.concatenate([window.src, window.dst]).tolist():
        deg[a] += 1
    subs = [i for i in deg if reg[i].ntype == "subject"]
    cand = [i for i in subs if pat.search(reg[i].label)]
    if not cand and role != "any" and day_windows:
        seen = set()
        for w in day_windows:
            for i in w.nodes().tolist():
                if i not in seen and reg[i].ntype == "subject" and pat.search(reg[i].label):
                    seen.add(i)
        cand = list(seen)
    if not cand:
        cand = subs
    if not cand:
        return None
    weights = [deg.get(i, 0) + 1 for i in cand]
    return rng.choices(cand, weights=weights, k=1)[0]


def bind(g: AttackGraph, reg: Registry, index: LabelIndex, window: Window, placement: Placement, rng: random.Random, run_tag: str,
         day_windows: list[Window] | None = None) -> Placement:
    """Resolve placeholders and new entities to dense ids; produce absolute-time edges."""
    index.sync()
    ids: dict[str, int] = {}
    win_nodes = set(window.nodes().tolist())
    for u, role in g.roles.items():
        h = pick_host(role, window, reg, rng, day_windows)
        if h is None:
            raise RuntimeError("no process in placement window")
        ids[u] = h
        if u == "$host":
            placement.host, placement.host_label = h, reg[h].label
    for u, e in g.entities.items():
        if u.startswith(("$benign:", "$ctx:")):
            cand = index.by_label.get(e.label, [])
            if cand:
                inwin = [c for c in cand if c in win_nodes]
                ids[u] = rng.choice(inwin or cand); placement.bound_context += 1
                continue
        nid = reg.add(Entity(f"sim:{run_tag}:{u.lstrip('$')}", e.ntype, e.label, dict(e.display, simulated=True)))
        ids[u] = nid; placement.new_ids.append(nid)
    placement.malicious_ids = {ids[u] for u in g.malicious if u in ids}
    t0 = placement.start_ns
    placement.edges = [(ids[s], ids[d], t0 + t, EDGE_TYPE_ID[op], f"sim:{run_tag}:{k}") for k, (t, s, op, d) in enumerate(sorted(g.events, key=lambda e: e[0]))]
    return placement


def inject(windows: list[Window], edges: list[tuple[int, int, int, int, str]]) -> dict[int, Window]:
    """Return rebuilt windows (index -> Window) with the edges merged in, keeping window boundaries so the clean and
    injected passes stay aligned. Each affected window is re-fused from its events in time order, which is
    exactly what the agent's window builder would produce for the merged stream."""
    starts = [w.start_ns for w in windows]
    per: dict[int, list] = defaultdict(list)
    for s, d, t, e, u in edges:
        i = bisect.bisect_right(starts, t) - 1
        i = min(max(i, 0), len(windows) - 1)
        per[i].append((s, d, t, e, u))
    out = {}
    for i, extra in per.items():
        w = windows[i]
        ev = list(zip(w.src.tolist(), w.dst.tolist(), w.t.tolist(), w.etype.tolist(), w.event_uuid)) + extra
        ev.sort(key=lambda x: x[2])
        nw = fuse(ev)
        nw.start_ns, nw.end_ns = w.start_ns, max(w.end_ns, ev[-1][2])
        out[i] = nw
    return out
