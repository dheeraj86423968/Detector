"""Evasion transforms applied to an AttackGraph before injection.

  padding     mimicry edges (Goyal et al., "Sometimes Simpler is Better" / PIDSMaker mimicry): benign-looking
              OPEN/READ/WRITE structures between attack processes and benign files of the target endpoint,
              which pull the attack nodes' neighbourhoods towards the benign distribution
  camouflage  attack processes and dropped files take the names of frequent benign processes / paths
  spread      the attack is stretched over `spread_s` seconds (slow-and-low), crossing window boundaries
"""
from __future__ import annotations

import random

from pdp_engine.schema import Entity

from .attacks import AttackGraph, Ctx

S = 1_000_000_000

# PIDSMaker mimicry structures
STRUCTURES = [["OPEN", "READ"], ["OPEN", "WRITE"], ["OPEN", "READ", "WRITE"], ["OPEN", "WRITE", "READ"],
              ["OPEN", "READ", "WRITE", "READ", "WRITE"], ["OPEN", "WRITE", "READ", "WRITE", "READ"],
              ["OPEN", "READ", "WRITE", "WRITE", "READ"], ["OPEN", "WRITE", "READ", "WRITE", "WRITE"],
              ["OPEN", "READ", "WRITE", "READ", "WRITE", "WRITE", "WRITE"], ["OPEN", "WRITE", "READ", "READ", "READ", "WRITE", "READ"],
              ["OPEN", "READ", "READ", "READ", "WRITE", "WRITE", "READ"], ["OPEN", "WRITE", "WRITE", "WRITE", "READ", "WRITE", "WRITE"],
              ["OPEN", "READ", "READ", "READ", "READ"], ["OPEN", "WRITE", "WRITE", "WRITE", "WRITE"]]

LEVELS = {  # name -> (padding edges, camouflage probability, spread seconds, thinning fraction)
    "none": (0, 0.0, 0, 0.0), "low": (50, 0.25, 120, 0.0), "medium": (200, 0.5, 900, 0.0), "high": (600, 0.75, 3600, 0.0),
    "extreme": (1500, 1.0, 10800, 0.0),
    "stealth": (0, 1.0, 0, 0.5),     # fully camouflaged, minimal footprint, no padding (max-edge-loss scoring ignores padding)
}


def apply(g: AttackGraph, level: str | dict, rng: random.Random, ctx: Ctx) -> AttackGraph:
    if isinstance(level, str):
        padding, cam, spread, thin_frac = LEVELS[level]
        g.params["evasion"] = level
    else:
        padding, cam, spread = int(level.get("padding", 0)), float(level.get("camouflage", 0.0)), float(level.get("spread_s", 0))
        thin_frac = float(level.get("thin", 0.0))
        g.params["evasion"] = dict(level)
    if thin_frac > 0:
        thin(g, thin_frac, rng)
    if cam > 0:
        camouflage(g, cam, rng, ctx)
    if spread > 0:
        stretch(g, spread, rng)
    if padding > 0:
        pad(g, padding, rng, ctx)
    return g


def thin(g: AttackGraph, frac: float, rng: random.Random) -> None:
    """Minimal-footprint variant: drop a fraction of the optional events (reads of context files, repeated beacons,
    bulk file access), keeping the structural ones (CLONE, EXECUTE, CONNECT, first and last event)."""
    keep_ops = {"CLONE", "EXECUTE", "CONNECT"}
    n = len(g.events)
    out = []
    for i, e in enumerate(g.events):
        if i == 0 or i == n - 1 or e[2] in keep_ops or rng.random() >= frac:
            out.append(e)
    g.events = out
    used = {u for e in out for u in (e[1], e[3])}
    for u in list(g.entities):
        if u not in used:
            g.entities.pop(u); g.malicious.discard(u)
    g.params["thinned_to"] = len(out)


def camouflage(g: AttackGraph, p: float, rng: random.Random, ctx: Ctx) -> None:
    benign = ctx.process_labels
    paths = [x for x in ctx.file_paths if "/" in x]
    for u, e in list(g.entities.items()):
        if u not in g.malicious or rng.random() >= p:
            continue
        if e.ntype == "subject" and benign:
            lab = rng.choice(benign)               # 'subject <exe> <cmd>' of a frequent benign process
            g.entities[u] = Entity(u, "subject", lab, dict(e.display, camouflaged=True))
        elif e.ntype == "file" and paths:
            d = rng.choice(paths).rsplit("/", 1)[0]
            b = rng.choice(paths).rsplit("/", 1)[-1]
            g.entities[u] = Entity.file(u, f"{d}/{b}", camouflaged=True)


def stretch(g: AttackGraph, spread_s: float, rng: random.Random) -> None:
    """Rescale event offsets so the attack lasts about `spread_s` seconds, keeping order and adding jitter."""
    d = g.duration_ns
    if d <= 0:
        return
    k = (spread_s * S) / d
    if k <= 1.0:
        return
    out, last = [], -1
    for t, s, op, o in g.events:
        nt = int(t * k) + rng.randint(0, int(0.02 * spread_s * S))
        nt = max(nt, last + 1)
        out.append((nt, s, op, o)); last = nt
    g.events = out


def pad(g: AttackGraph, n_edges: int, rng: random.Random, ctx: Ctx) -> None:
    """Mimicry: attach benign file-access structures to malicious processes, at times inside the attack span.
    Files come from the endpoint's own benign file set and are bound to existing nodes by label at injection."""
    procs = [u for u in g.malicious if u in g.entities and g.entities[u].ntype == "subject"] or [u for u in g.roles if g.roles[u] != "none"]
    if not procs or not ctx.file_paths:
        return
    span = max(g.duration_ns, 10 * S)
    added = 0
    while added < n_edges:
        p = rng.choice(procs)
        lab = g.entities[p].label if p in g.entities else ""
        path = (ctx.files_like(lab, 1) or [rng.choice(ctx.file_paths)])[0]
        key = f"$benign:{path}"
        if key not in g.entities:
            g.entities[key] = Entity.file(key, path)     # not malicious; bound to the real node with this label if any
        t = rng.randint(0, span)
        for op in rng.choice(STRUCTURES):
            if added >= n_edges:
                break
            t += rng.randint(0, 3 * S)
            g.kernel(t, p, op, key); added += 1
    g.events.sort(key=lambda e: e[0])
    g.params["padding_edges"] = added
