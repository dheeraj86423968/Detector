"""Live Linux telemetry via strace (ptrace) -> normalised provenance events.

This is the portable live collector: it needs only `strace` and CAP_SYS_PTRACE, so it runs where the kernel
audit netlink is unavailable (containers, WSL2) and where eBPF tooling is not installed. A production eBPF
collector (libbpf CO-RE) is the intended drop-in for high-volume hosts; it emits the exact same Entity/Event
stream, so nothing downstream changes.

strace is run with `-ff -o <dir>/t` so every traced process gets its own file `t.<pid>` (the filename is the
pid, unambiguous), each line `"<epoch.us> syscall(args) = ret"`. The syscall set mirrors the auditd collector
(execve/open/connect/clone family, no read/write): file access edges are inferred from the open mode, exactly
as in the research pipeline, which keeps edge volume and semantics identical across collectors.

Entities: one process node per (run, pid, exec generation) 'subject <exe> <argv>'; one file node per absolute
path 'file <path>'; one socket node per 'netflow <remote_ip> <remote_port>'.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
import uuid as uuidlib
from typing import Callable, Iterator

from pdp_engine.schema import Entity, Event

from .common import ProvenanceMapper

TRACE_SYSCALLS = ("execve,execveat,open,openat,openat2,creat,connect,accept,accept4,"
                  "sendto,recvfrom,sendmsg,recvmsg,clone,clone3,fork,vfork")

_LINE = re.compile(r"^(\d+)\.(\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+|0x[0-9a-f]+)(?:<([^>]*)>)?(?:\s+\w+.*)?$")
_UNFIN = re.compile(r"^(\d+)\.(\d+)\s+(\w+)\((.*)<unfinished \.\.\.>$")
_RESUM = re.compile(r"^(\d+)\.(\d+)\s+<\.\.\. (\w+) resumed>(.*)\)\s+=\s+(-?\d+|0x[0-9a-f]+)(?:<([^>]*)>)?.*$")
_FDPATH = re.compile(r"^(?:\d+|AT_FDCWD)<([^>]*)>")         # first arg of openat: AT_FDCWD</cwd> or dirfd</path>
_PATHARG = re.compile(r'"((?:[^"\\]|\\.)*)"')
_INET = re.compile(r'sin_port=htons\((\d+)\).*?inet_addr\("([^"]+)"\)')
_INET6 = re.compile(r'sin6_port=htons\((\d+)\).*?inet6_addr\("([^"]+)"\)|sin6_port=htons\((\d+)\).*?inet_pton\([^,]+,\s*"([^"]+)"')


class StraceNormaliser:
    """Feed strace lines tagged with their pid (from the per-pid file); get (entities, event) tuples.
    The syscall -> edge mapping is shared with the eBPF collector (sources/common.py)."""

    def __init__(self, run_id: str | None = None):
        self.run_id = run_id or uuidlib.uuid4().hex[:12]
        self.map = ProvenanceMapper(self.run_id)
        self.procs = self.map.procs
        self._pending: dict[int, str] = {}   # pid -> unfinished line prefix
        self._thread_of: dict[int, int] = {}  # thread id -> process (thread-group) id: strace -ff writes threads to t.<tid>

    def feed(self, pid: int, line: str) -> Iterator[tuple[list[Entity], Event]]:
        line = line.rstrip("\n")
        mu = _UNFIN.match(line)
        if mu:
            self._pending[pid] = f"{mu.group(1)}.{mu.group(2)} {mu.group(3)}({mu.group(4)}"
            return
        mr = _RESUM.match(line)
        if mr:
            pre = self._pending.pop(pid, None)
            if pre is None:
                return
            line = f"{pre}{mr.group(4)}) = {mr.group(5)}" + (f"<{mr.group(6)}>" if mr.group(6) else "")
        m = _LINE.match(line)
        if not m:
            return
        sec, us, name, args, ret, retpath = m.groups()
        ts = int(sec) * 1_000_000_000 + int(us) * 1000
        try:
            retv = int(ret, 16) if ret.startswith("0x") else int(ret)
        except ValueError:
            return
        yield from self._event(self._thread_of.get(pid, pid), ts, name, args, retv, retpath)

    def _event(self, pid: int, ts: int, name: str, args: str, ret: int, retpath: str | None):
        M = self.map
        if name in ("execve", "execveat"):
            if ret != 0:
                return
            yield from M.exec(pid, ts, _first_str(args), _argv(args))
        elif name in ("clone", "clone3", "fork", "vfork"):
            if ret <= 0:
                return
            if "CLONE_THREAD" in args:     # a new thread of the same process, not a new process
                self._thread_of[ret] = pid
                return
            yield from M.fork(pid, ret, ts)
        elif name in ("open", "openat", "openat2", "creat"):
            if ret < 0:
                return
            path = retpath if retpath else _resolve_path(args)
            if not path:
                return
            readable = "O_WRONLY" not in args and name != "creat"
            writable = ("O_WRONLY" in args) or ("O_RDWR" in args) or name == "creat"
            yield from M.open(pid, ts, path, readable, writable)
        else:   # sockets
            addr = _sockaddr(args)
            if addr is None:
                return
            op = {"connect": "CONNECT", "sendto": "SENDTO", "sendmsg": "SENDMSG",
                  "recvfrom": "RECVFROM", "recvmsg": "RECVMSG", "accept": "RECVFROM", "accept4": "RECVFROM"}.get(name)
            if op is None:
                return
            yield from M.socket(pid, ts, op, addr[0], addr[1])


_TS = re.compile(r"^(\d+)\.(\d+)")


def _line_ts(line: str) -> int:
    m = _TS.match(line)
    return int(m.group(1)) * 1_000_000_000 + int(m.group(2)) * 1000 if m else 0


def _first_str(args: str) -> str:
    m = _PATHARG.search(args)
    return m.group(1).replace('\\"', '"') if m else ""


def _argv(args: str) -> list[str]:
    i = args.find("[")
    if i < 0:
        return []
    depth, j = 0, i
    for j in range(i, len(args)):
        if args[j] == "[":
            depth += 1
        elif args[j] == "]":
            depth -= 1
            if depth == 0:
                break
    return [s.replace('\\"', '"') for s in _PATHARG.findall(args[i:j + 1])]


def _resolve_path(args: str) -> str:
    """openat(AT_FDCWD</cwd>, "name", flags): resolve a relative name against the annotated cwd."""
    parts = args.split(", ", 1)
    base = ""
    mb = _FDPATH.match(parts[0]) if parts else None
    if mb:
        base = mb.group(1)
    name = _first_str(parts[1] if len(parts) > 1 else args)
    if not name:
        return ""
    if not name.startswith("/") and base:
        return os.path.normpath(os.path.join(base, name))
    return name


def _sockaddr(args: str):
    if "AF_INET6" in args:
        m = _INET6.search(args)
        if m:
            port = m.group(1) or m.group(3)
            ip = m.group(2) or m.group(4)
            if ip:
                return ip, str(port)
        return None
    if "AF_INET" in args:
        m = _INET.search(args)
        if m:
            return m.group(2), str(m.group(1))
    return None


class StraceLive:
    """Live source. Two modes:
       * workload: spawn `command` under strace and trace it and its children until it exits (then idle).
       * attach:   watch an existing trace directory that strace (started elsewhere) writes into.
    Yields lists of (entities, Event) like the other collectors."""
    chronological = True   # wall-clock timestamps: a calendar day is complete once it has ended

    def __init__(self, command: list[str] | None = None, trace_dir: str | None = None, run_id: str | None = None,
                 batch: int = 1000, cwd: str | None = None, keep_traces: bool = False):
        self.command = command
        self.batch = batch
        self.cwd = cwd
        self.keep_traces = keep_traces
        self.run_id = run_id or uuidlib.uuid4().hex[:12]
        self.trace_dir = trace_dir or os.path.join("/tmp", f"pdp-strace-{self.run_id}")
        self.norm = StraceNormaliser(self.run_id)
        self.proc: subprocess.Popen | None = None
        self._offsets: dict[str, int] = {}

    def _start_strace(self):
        os.makedirs(self.trace_dir, exist_ok=True)
        prefix = os.path.join(self.trace_dir, "t")
        cmd = ["strace", "-ff", "-ttt", "-y", "-qq", "-s", "256", "-e", f"trace={TRACE_SYSCALLS}", "-o", prefix, *self.command]
        self.proc = subprocess.Popen(cmd, cwd=self.cwd, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _drain(self) -> list:
        """Read new complete lines from every per-pid trace file, merge them across files by timestamp and normalise
        them in that order (a child's first syscall must not be processed before the parent's clone)."""
        lines: list[tuple[int, int, int, str]] = []
        try:
            files = os.listdir(self.trace_dir)
        except FileNotFoundError:
            return []
        for fn in files:
            if not fn.startswith("t."):
                continue
            try:
                pid = int(fn.rsplit(".", 1)[1])
            except ValueError:
                continue
            path = os.path.join(self.trace_dir, fn)
            off = self._offsets.get(fn, 0)
            try:
                with open(path, "r", errors="replace") as f:
                    f.seek(off)
                    data = f.read()
            except OSError:
                continue
            nl = data.rfind("\n")
            if nl < 0:
                continue
            self._offsets[fn] = off + nl + 1
            for k, line in enumerate(data[:nl].splitlines()):
                lines.append((_line_ts(line), pid, k, line))
        lines.sort(key=lambda x: (x[0], x[1], x[2]))
        out = []
        for _, pid, _, line in lines:
            out.extend(self.norm.feed(pid, line))
        return out

    def batches(self, stop: Callable[[], bool]) -> Iterator[list]:
        if self.command:
            self._start_strace()
        buf = []
        while not stop():
            buf.extend(self._drain())
            if len(buf) >= self.batch:
                yield buf[:self.batch]; buf = buf[self.batch:]
                continue
            if buf:
                yield buf; buf = []
            running = self.proc is not None and self.proc.poll() is None
            if self.command and not running:
                time.sleep(0.5)
                buf.extend(self._drain())    # final flush after the workload exits
                if buf:
                    yield buf; buf = []
                if not self.keep_traces:
                    self._cleanup()
                break
            yield []
            time.sleep(0.5)

    def _cleanup(self):
        try:
            for f in os.listdir(self.trace_dir):
                os.remove(os.path.join(self.trace_dir, f))
            os.rmdir(self.trace_dir)
        except OSError:
            pass
