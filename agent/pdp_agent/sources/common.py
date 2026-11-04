"""Shared syscall -> provenance mapping for the live Linux collectors (strace and eBPF).

Both collectors decode their own wire format (strace text, eBPF ring-buffer records) into the few calls below, so
the edge semantics are defined once and are identical across collectors:

  exec(pid, exe, argv)      EXECUTE  file(exe) -> new process image;  CLONE previous image -> new image
  fork(ppid, child)         CLONE    parent -> child (threads are not processes and are not reported)
  open(pid, path, flags)    OPEN file -> process; READ file -> process unless O_WRONLY; WRITE process -> file if
                            O_WRONLY / O_RDWR (file reads/writes are inferred from the open mode, as in the research
                            pipeline, not traced per read/write call)
  socket(pid, op, ip, port) CONNECT / SENDTO / SENDMSG process -> socket;  RECVFROM / RECVMSG socket -> process
  exit(pid)                 forget the pid (a reused pid becomes a new process)

Entities: one process node per (run, pid, exec generation) 'subject <exe> <argv>'; one file node per path
'file <path>'; one socket node per 'netflow <remote_ip> <remote_port>'.
"""
from __future__ import annotations

from typing import Iterator

from pdp_engine.schema import Entity, Event

from .auditd import ProcessTable

O_ACCMODE, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC = 0o3, 0o1, 0o2, 0o100, 0o1000
SOCKET_OPS = {"CONNECT", "SENDTO", "SENDMSG", "RECVFROM", "RECVMSG"}
INBOUND = {"RECVFROM", "RECVMSG"}


class ProvenanceMapper:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.procs = ProcessTable(run_id)
        self._seq = 0

    def _eid(self) -> str:
        # zero-padded so that lexicographic order of event ids equals emission order (the server sorts a day's events
        # by (ts_ns, event_uuid); equal timestamps then keep the collector's order)
        self._seq += 1
        return f"{self.run_id}:{self._seq:010d}"

    def _emit(self, ts: int, out) -> Iterator[tuple[list[Entity], Event]]:
        for src, op, dst in out:
            yield [src, dst], Event(ts, src.uuid, op, dst.uuid, self._eid())

    def exec(self, pid: int, ts: int, exe: str, argv: list[str]):
        parent = self.procs.get(pid, exe)
        child = self.procs.get(pid, exe, " ".join(argv)[:1024] or exe, new_image=True)
        return self._emit(ts, [(Entity.file(f"file:{exe}", exe), "EXECUTE", child), (parent, "CLONE", child)])

    def fork(self, ppid: int, child_pid: int, ts: int):
        p = self.procs.get(ppid, None)
        c = self.procs.get(child_pid, p.display.get("exe_path"), p.display.get("argv"), new_image=True)
        return self._emit(ts, [(p, "CLONE", c)])

    def open(self, pid: int, ts: int, path: str, readable: bool, writable: bool):
        f, p = Entity.file(f"file:{path}", path), self.procs.get(pid, None)
        out = [(f, "OPEN", p)]
        if readable:
            out.append((f, "READ", p))
        if writable:
            out.append((p, "WRITE", f))
        return self._emit(ts, out)

    def open_flags(self, pid: int, ts: int, path: str, flags: int):
        acc = flags & O_ACCMODE
        return self.open(pid, ts, path, acc != O_WRONLY, acc in (O_WRONLY, O_RDWR))

    def socket(self, pid: int, ts: int, op: str, ip: str, port: str | int):
        if op not in SOCKET_OPS:
            return iter(())
        p = self.procs.get(pid, None)
        n = Entity.socket(f"net:{ip}:{port}", ip, str(port))
        return self._emit(ts, [(n, op, p)] if op in INBOUND else [(p, op, n)])

    def exit(self, pid: int) -> None:
        self.procs.forget(pid)
