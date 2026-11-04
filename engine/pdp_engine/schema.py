"""Normalised telemetry schema shared by the agent, the engine and the server.

Direction convention (DARPA TC / PIDSMaker): an event is an edge src -> dst in the direction of data
flow. Operations in REVERSED are recorded by the kernel as subject -> object but flow object -> subject
(a process *reading* a file receives data from it), so the normaliser swaps src and dst for them.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# The 10 edge types consumed by the detectors (PIDSMaker's DARPA TC map, 0-based)
EDGE_TYPES = ["CONNECT", "EXECUTE", "OPEN", "READ", "RECVFROM", "RECVMSG", "SENDMSG", "SENDTO", "WRITE", "CLONE"]
EDGE_TYPE_ID = {t: i for i, t in enumerate(EDGE_TYPES)}
NUM_EDGE_TYPES = len(EDGE_TYPES)

NODE_TYPES = ["subject", "file", "netflow"]  # process, file, socket (framework names kept for parity)
NODE_TYPE_ID = {t: i for i, t in enumerate(NODE_TYPES)}
NUM_NODE_TYPES = len(NODE_TYPES)

# kernel-direction operations whose data flows object -> subject
REVERSED = {"EXECUTE", "LSEEK", "MMAP", "OPEN", "ACCEPT", "READ", "RECVFROM", "RECVMSG", "READ_SOCKET_PARAMS", "CHECK_FILE_ATTRIBUTES"}

WINDOW_NS = 15 * 60 * 1_000_000_000


def normalise_op(op: str, strict: bool = False) -> str | None:
    """Map a raw operation name (e.g. 'EVENT_READ', 'read', 'openat') to a detector edge type, or None.
    strict=True accepts only the framework's own names (used for database replay, so that FORK etc. are
    excluded exactly as in the research pipeline)."""
    o = op.upper()
    if o.startswith("EVENT_"):
        o = o[6:]
    if strict:
        return o if o in EDGE_TYPE_ID else None
    aliases = {"OPENAT": "OPEN", "EXECVE": "EXECUTE", "EXECVEAT": "EXECUTE", "FORK": "CLONE", "VFORK": "CLONE",
               "PREAD": "READ", "PREADV": "READ", "READV": "READ", "PWRITE": "WRITE", "PWRITEV": "WRITE", "WRITEV": "WRITE",
               "RECVMMSG": "RECVMSG", "SENDMMSG": "SENDMSG"}
    o = aliases.get(o, o)
    return o if o in EDGE_TYPE_ID else None


# Shared empty display for entities whose display data lives elsewhere (the agent keeps it on disk); never mutated.
NO_DISPLAY: dict = {}


@dataclass(frozen=True, slots=True)   # slots: registries hold millions of entities
class Entity:
    uuid: str
    ntype: str           # subject | file | netflow
    label: str           # featurisation label (framework format): 'subject <exe> <cmdline>', 'file <path>', 'netflow <remote_ip> <remote_port>'
    display: dict = field(default_factory=dict, compare=False, hash=False)  # extras for the GUI (pid, user, ports, hashes)

    @staticmethod
    def process(uuid: str, exe: str | None, cmdline: str | None, **display) -> "Entity":
        return Entity(uuid, "subject", f"subject {exe or 'None'} {cmdline or 'None'}", display)

    @staticmethod
    def file(uuid: str, path: str | None, **display) -> "Entity":
        return Entity(uuid, "file", f"file {path or 'None'}", display)

    @staticmethod
    def socket(uuid: str, remote_ip: str | None, remote_port: str | int | None, **display) -> "Entity":
        return Entity(uuid, "netflow", f"netflow {remote_ip or 'None'} {remote_port if remote_port is not None else 'None'}", display)


@dataclass(frozen=True, slots=True)
class Event:
    ts_ns: int
    src: str             # entity uuid (data-flow source)
    op: str              # one of EDGE_TYPES
    dst: str             # entity uuid (data-flow destination)
    event_uuid: str

    @staticmethod
    def from_kernel(ts_ns: int, subject: str, op: str, obj: str, event_uuid: str | None = None) -> "Event | None":
        """Build a flow-oriented event from a kernel record (subject performs op on object)."""
        e = normalise_op(op)
        if e is None:
            return None
        if event_uuid is None:
            event_uuid = hashlib.sha1(f"{ts_ns}|{subject}|{op}|{obj}".encode()).hexdigest()
        raw = op.upper()
        raw = raw[6:] if raw.startswith("EVENT_") else raw
        if raw in REVERSED or e in REVERSED:
            return Event(ts_ns, obj, e, subject, event_uuid)  # data flows object -> subject
        return Event(ts_ns, subject, e, obj, event_uuid)


class Registry:
    """Entity registry: uuid -> dense integer id, plus type and label.

    Ids are dense positions. Normally they are also the entity's *global* id (its position in the endpoint's
    append-only entity sequence, which the server and the model bundles use). A long-running agent compacts its
    registry (drops entities it no longer needs, see Runtime.compact): positions then differ from global ids, and
    `gids` maps position -> global id (None while they are equal)."""

    def __init__(self):
        self.ids: dict[str, int] = {}
        self.entities: list[Entity] = []
        self.gids: list[int] | None = None
        self._by_gid: dict[int, int] | None = None

    def add(self, e: Entity, gid: int | None = None) -> int:
        i = self.ids.get(e.uuid)
        if i is None:
            i = len(self.entities)
            if self.gids is None and gid is not None and gid != i:
                self._split_gids()
            if self.gids is not None:
                g = i if gid is None else int(gid)
                self.gids.append(g)
                self._by_gid[g] = i
            self.ids[e.uuid] = i
            self.entities.append(e)
        return i

    def _split_gids(self):
        self.gids = list(range(len(self.entities)))
        self._by_gid = {g: g for g in self.gids}

    def gid(self, i: int) -> int:
        return i if self.gids is None else self.gids[i]

    def gid_array(self):
        import numpy as np
        return np.arange(len(self.entities), dtype=np.int64) if self.gids is None else np.asarray(self.gids, dtype=np.int64)

    def local(self, gid: int) -> int | None:
        """Position of the entity with global id `gid`, None if not held."""
        if self.gids is None:
            return gid if 0 <= gid < len(self.entities) else None
        return self._by_gid.get(int(gid))

    def compact(self, keep) -> "list[int]":
        """Keep only positions where keep[i] is true, in order. Returns old position -> new position (-1 dropped)."""
        if self.gids is None:
            self._split_gids()
        old2new, ents, gids, n = [], [], [], 0
        for i, k in enumerate(keep):
            if k:
                old2new.append(n); ents.append(self.entities[i]); gids.append(self.gids[i]); n += 1
            else:
                old2new.append(-1)
        self.entities, self.gids = ents, gids
        self.ids = {e.uuid: i for i, e in enumerate(ents)}
        self._by_gid = {g: i for i, g in enumerate(gids)}
        return old2new

    def __len__(self):
        return len(self.entities)

    def __getitem__(self, i: int) -> Entity:
        return self.entities[i]

    def get(self, uuid: str) -> int | None:
        return self.ids.get(uuid)

    def types(self) -> list[str]:
        return [e.ntype for e in self.entities]

    def labels(self) -> list[str]:
        return [e.label for e in self.entities]

    def extend(self, entities: Iterable[Entity]) -> None:
        for e in entities:
            self.add(e)

    def iter_items(self) -> Iterator[tuple[int, Entity]]:
        return enumerate(self.entities)
