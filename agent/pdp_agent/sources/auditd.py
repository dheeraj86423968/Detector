"""Linux kernel telemetry via auditd -> normalised provenance events.

Audit records of one kernel event share a serial (msg=audit(ts:serial)); the parser groups the
SYSCALL, PATH, CWD, EXECVE and SOCKADDR records and maps the syscall to detector edge types in
information-flow direction (see pdp_engine.schema): reads/opens/receives/executes flow object -> process,
writes/sends/connects flow process -> object, clones parent -> child.

Entities: one process node per (boot, pid, exec generation) with label 'subject <exe> <argv>';
one file node per absolute path; one socket node per remote address:port.

Required audit rules (installed by `rules()`):
  -a always,exit -F arch=b64 -S execve,execveat,clone,clone3,fork,vfork,open,openat,openat2,creat,connect,accept,accept4,sendto,recvfrom,sendmsg,recvmsg
"""
from __future__ import annotations

import binascii
import os
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Iterator

from pdp_engine.schema import Entity, Event

SYSCALLS_X86_64 = {59: "execve", 322: "execveat", 56: "clone", 435: "clone3", 57: "fork", 58: "vfork",
                   2: "open", 257: "openat", 437: "openat2", 85: "creat", 42: "connect", 43: "accept",
                   288: "accept4", 44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg"}
SYSCALLS_AARCH64 = {221: "execve", 281: "execveat", 220: "clone", 435: "clone3", 56: "openat", 437: "openat2",
                    203: "connect", 202: "accept", 242: "accept4", 206: "sendto", 207: "recvfrom", 211: "sendmsg", 212: "recvmsg"}
O_ACCMODE, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC = 0o3, 0o1, 0o2, 0o100, 0o1000

_REC = re.compile(r"^type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):\s?(.*)$")
_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

RULES = ("-a always,exit -F arch=b64 -S execve,execveat,clone,clone3,fork,vfork,open,openat,openat2,creat,"
         "connect,accept,accept4,sendto,recvfrom,sendmsg,recvmsg -k pdp",)


def unhex(v: str) -> str:
    if v.startswith('"'):
        return v[1:-1]
    try:
        return binascii.unhexlify(v).decode(errors="replace").replace("\x00", " ").strip()
    except (binascii.Error, ValueError):
        return v


def sockaddr(hexstr: str) -> tuple[str, str] | None:
    try:
        raw = binascii.unhexlify(hexstr)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 8:
        return None
    family = struct.unpack("<H", raw[:2])[0]
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, raw[4:8]), str(struct.unpack(">H", raw[2:4])[0])
    if family == socket.AF_INET6 and len(raw) >= 24:
        return socket.inet_ntop(socket.AF_INET6, raw[8:24]), str(struct.unpack(">H", raw[2:4])[0])
    return None


def parse_line(line: str) -> tuple[str, int, int, dict] | None:
    """-> (record type, ts_ns, serial, fields) or None."""
    m = _REC.match(line.strip())
    if not m:
        return None
    rtype, sec, ms, serial, rest = m.groups()
    ts_ns = int(sec) * 1_000_000_000 + int(ms) * 1_000_000
    return rtype, ts_ns, int(serial), {k: v for k, v in _KV.findall(rest)}


@dataclass
class ProcessTable:
    """pid -> current process entity (uuid changes at every exec)."""
    boot_id: str
    gen: dict[int, int] = field(default_factory=dict)
    current: dict[int, Entity] = field(default_factory=dict)

    def get(self, pid: int, exe: str | None = None, argv: str | None = None, new_image: bool = False) -> Entity:
        if new_image or pid not in self.current:
            g = self.gen.get(pid, 0) + (1 if new_image else 0)
            self.gen[pid] = g
            prev = self.current.get(pid)
            exe = exe or (prev.display.get("exe_path") if prev else None)
            argv = argv or (prev.display.get("argv") if prev else None)
            self.current[pid] = Entity.process(f"proc:{self.boot_id}:{pid}:{g}", exe, argv, pid=pid, exe_path=exe, argv=argv)
        return self.current[pid]

    def forget(self, pid: int):
        """The process exited: a later process that reuses the pid must get a new identity (generation), not the
        exited one's uuid."""
        if self.current.pop(pid, None) is not None:
            self.gen[pid] = self.gen.get(pid, 0) + 1


class AuditNormaliser:
    """Stateful: feed audit lines (in order), get (entities, events)."""

    def __init__(self, boot_id: str | None = None, arch: str = "x86_64"):
        self.boot_id = boot_id or _boot_id()
        self.syscalls = SYSCALLS_AARCH64 if arch == "aarch64" else SYSCALLS_X86_64
        self.procs = ProcessTable(self.boot_id)
        self._cur_serial: int | None = None
        self._cur: list[tuple[str, int, dict]] = []

    def feed(self, line: str) -> Iterator[tuple[list[Entity], Event]]:
        p = parse_line(line)
        if p is None:
            return
        rtype, ts, serial, kv = p
        if self._cur_serial is not None and serial != self._cur_serial:
            yield from self._flush()
        self._cur_serial = serial
        self._cur.append((rtype, ts, kv))
        if rtype == "EOE":
            yield from self._flush()

    def flush(self) -> Iterator[tuple[list[Entity], Event]]:
        yield from self._flush()

    def _flush(self):
        recs, serial = self._cur, self._cur_serial
        self._cur, self._cur_serial = [], None
        if recs:
            yield from self._event(recs, serial)

    def _event(self, recs: list[tuple[str, int, dict]], serial: int):
        sc = next((kv for t, _, kv in recs if t == "SYSCALL"), None)
        if sc is None:
            return
        ts = recs[0][1]
        try:
            name = self.syscalls.get(int(sc.get("syscall", "-1")))
            pid = int(sc["pid"])
        except (KeyError, ValueError):
            return
        if name is None or sc.get("success") == "no":
            return
        exe = unhex(sc.get("exe", '""'))
        uid = f"{self.boot_id}:{serial}"
        out: list[tuple[Entity, str, Entity, str]] = []

        if name in ("execve", "execveat"):
            argv = [unhex(v) for t, _, kv in recs if t == "EXECVE" for k, v in sorted(kv.items(), key=lambda x: int(x[0][1:]) if x[0][1:].isdigit() else -1) if re.match(r"a\d+$", k)]
            parent = self.procs.get(pid, exe)
            child = self.procs.get(pid, exe, " ".join(argv)[:1024] or exe, new_image=True)
            out.append((Entity.file(f"file:{exe}", exe), "EXECUTE", child, f"{uid}:0"))
            out.append((parent, "CLONE", child, f"{uid}:1"))
        elif name in ("clone", "clone3", "fork", "vfork"):
            try:
                child_pid = int(sc.get("exit", "-1"))
            except ValueError:
                return
            if child_pid > 0:
                p = self.procs.get(pid, exe)
                c = self.procs.get(child_pid, p.display.get("exe_path"), p.display.get("argv"), new_image=True)
                out.append((p, "CLONE", c, f"{uid}:0"))
        elif name in ("open", "openat", "openat2", "creat"):
            paths = [kv for t, _, kv in recs if t == "PATH" and kv.get("nametype") in ("NORMAL", "CREATE")]
            if not paths:
                return
            path = unhex(paths[-1].get("name", '""'))
            cwd = next((unhex(kv.get("cwd", '""')) for t, _, kv in recs if t == "CWD"), "")
            if path and not path.startswith("/") and cwd:
                path = os.path.normpath(os.path.join(cwd, path))
            try:
                flags = int(sc.get("a1" if name in ("open", "creat") else "a2", "0"), 16)
            except ValueError:
                flags = 0
            if name == "creat":
                flags = O_WRONLY | O_CREAT | O_TRUNC
            f, p = Entity.file(f"file:{path}", path), self.procs.get(pid, exe)
            out.append((f, "OPEN", p, f"{uid}:0"))
            acc = flags & O_ACCMODE
            if acc in (0, O_RDWR):
                out.append((f, "READ", p, f"{uid}:1"))
            if acc in (O_WRONLY, O_RDWR):
                out.append((p, "WRITE", f, f"{uid}:2"))
        else:  # sockets
            sa = next((kv.get("saddr") for t, _, kv in recs if t == "SOCKADDR"), None)
            addr = sockaddr(sa) if sa else None
            if addr is None:
                return
            p = self.procs.get(pid, exe)
            n = Entity.socket(f"net:{addr[0]}:{addr[1]}", addr[0], addr[1])
            if name == "connect":
                out.append((p, "CONNECT", n, f"{uid}:0"))
            elif name == "sendto":
                out.append((p, "SENDTO", n, f"{uid}:0"))
            elif name == "sendmsg":
                out.append((p, "SENDMSG", n, f"{uid}:0"))
            elif name == "recvfrom":
                out.append((n, "RECVFROM", p, f"{uid}:0"))
            elif name == "recvmsg":
                out.append((n, "RECVMSG", p, f"{uid}:0"))
            else:  # accept: incoming connection, data flows socket -> process
                out.append((n, "RECVFROM", p, f"{uid}:0"))
        for src, op, dst, euid in out:
            yield [src, dst], Event(ts, src.uuid, op, dst.uuid, euid)


def _boot_id() -> str:
    try:
        return open("/proc/sys/kernel/random/boot_id").read().strip()
    except OSError:
        return "unknown"


def follow(path: str, stop, poll: float = 0.5) -> Iterator[str]:
    """Tail a log file across rotations (audit.log is renamed and recreated)."""
    f, ino = None, None
    while not stop():
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(poll); continue
        if f is None or st.st_ino != ino:
            if f:
                for line in f:  # drain the rotated file
                    yield line
                f.close()
            f, ino = open(path, "r", errors="replace"), st.st_ino
        line = f.readline()
        if line:
            yield line
        else:
            time.sleep(poll)
    if f:
        f.close()
