"""Production live collector: eBPF -> normalised provenance events.

This is the high-volume Linux endpoint collector. It traces the same syscall set as the strace and auditd
collectors and maps it through the same code (sources/common.py), so the event stream - node labels, edge types,
directions - is identical across collectors and everything downstream is unchanged:

  exec                  sched_process_exec (successful execs only): filename + argv read from the new image
  open / openat / openat2 / creat
                        path + flags at entry, reported only on success; reads/writes are inferred from the open mode
  connect, sendto, sendmsg (destination address), recvfrom, recvmsg, accept, accept4 (peer address)
                        IPv4 and IPv6; a socket op without an address (connected TCP send/recv) is not an edge,
                        exactly as in the strace collector
  process fork          raw tracepoint sched_process_fork; new threads are not processes and are filtered in-kernel.
                        It fires before the child can run, so a child's syscalls are never seen before its fork.
  process exit          sched_process_exit with group_dead: the pid is forgotten (a reused pid is a new process)
  dup / dup2 / dup3 / fcntl(F_DUPFD*)
                        not edges: they carry an fd's path to its duplicate, for fd-relative opens (grep -r, find)

Records go through one BPF ring buffer, so they are consumed in the order they were produced on all CPUs (a
per-CPU perf buffer would reorder a parent's fork and the child's exec). Timestamps are the kernel's monotonic
clock converted to wall-clock nanoseconds.

File paths are made absolute (cwd or dirfd) and symlink-free in user space, resolving inside the process's own root,
which matches the strace collector's `-y` output (tools/crosscheck.py compares the collectors on the same
workloads). The agent's own process is excluded in-kernel.

Two engines load the same kernel program (same hooks, filters and record layout), selected by the source config
`{"kind": "ebpf", "engine": "core" | "bcc"}` (default "core", or $PDP_EBPF_ENGINE):

  core (default)  libbpf CO-RE. The program (agent/bpf/pdp_ebpf.bpf.c) is compiled once at image build time against
                  vmlinux.h and embedded in a static loader, `pdp-ebpf` ($PDP_EBPF_LOADER, /opt/pdp/bin/pdp-ebpf),
                  which libbpf relocates against the running kernel's BTF. The agent spawns it and reads raw records
                  from its stdout; the loader and the agent are both excluded in-kernel. Needs a kernel >= 5.8 with
                  BTF (/sys/kernel/btf/vmlinux, CONFIG_DEBUG_INFO_BTF - every current distro kernel). No kernel
                  headers, no compiler, no tracefs (all hooks are raw tracepoints). Starts in tens of milliseconds.
  bcc (fallback)  the original in-process bcc program (BPF_PROGRAM below), compiled at start against the running
                  kernel's headers: needs python3-bpfcc, /lib/modules + /usr/src (linux-headers-$(uname -r)) and
                  tracefs. Not shipped in the agent image; kept for hosts without BTF and for differential checks
                  (`python -m pdp_agent.tools.crosscheck --compare bcc,core`).

Both need CAP_BPF + CAP_PERFMON (+ CAP_SYS_ADMIN for bcc; or a privileged container) and the host pid namespace so
pids and /proc agree. `decode` and the record parser are pure Python and unit-tested without a kernel
(tests/unit/test_ebpf.py).
"""
from __future__ import annotations

import collections
import os
import posixpath
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid as uuidlib
from dataclasses import dataclass
from typing import Callable, Iterator

from pdp_engine.schema import Entity, Event

from .common import ProvenanceMapper

# record kinds emitted by the kernel program (keep in sync with BPF_PROGRAM and agent/bpf/pdp_ebpf.h)
EXEC, EXEC_ARGV, OPEN, CONNECT, SEND, RECV, ACCEPT, FORK, EXIT, DUP = range(10)
STATS = 255           # CO-RE loader only: ret = records lost in-kernel (ring buffer full) so far, flags = over its spool limit
EXEC_ARG = EXEC   # old name
AT_FDCWD = -100
STRLEN = 512          # bytes per record string (kernel side)
ARG_CHUNKS = 2        # argv bytes captured = STRLEN * ARG_CHUNKS
ARG_MAX = 256         # per-argument truncation, as the strace collector's -s 256

# struct event_t (agent/bpf/pdp_ebpf.h, and BPF_PROGRAM below): ts kind pid tid aux ret flags dirfd family port addr str
REC = struct.Struct("<QIIIIqQiHH16s%ds" % STRLEN)
assert REC.size == 576
STREAM_MAGIC, STREAM_VERSION = b"PDPEBPF\0", 1
STREAM_HEADER = struct.Struct("<8sII")      # magic, version, record size

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

#define K_EXEC_ARG 0
#define K_EXEC_ARGV 1
#define K_OPEN     2
#define K_CONNECT  3
#define K_SEND     4
#define K_RECV     5
#define K_ACCEPT   6
#define K_FORK     7
#define K_EXIT     8
#define K_DUP      9

#define STRLEN   512
#define ARGCHUNKS 2
#define AF_INET_  2
#define AF_INET6_ 10
#define SELF_PID  __SELF_PID__
/*__SYSCALLS__*/

struct event_t {
    u64 ts;
    u32 kind;
    u32 pid;          /* thread-group id (the process) */
    u32 tid;
    u32 aux;          /* FORK: child pid; EXEC_ARGV: chunk index; SEND/RECV: 1 = *msg variant */
    s64 ret;
    u64 flags;
    s32 dirfd;
    u16 family;
    u16 port;         /* network byte order */
    u8  addr[16];
    char str[STRLEN];
};

struct sa4 { u16 family; u16 port; u32 addr; };
struct sa6 { u16 family; u16 port; u32 flowinfo; u8 addr[16]; };

BPF_RINGBUF_OUTPUT(events, __RING_PAGES__);

#define SKIP_SELF() if ((bpf_get_current_pid_tgid() >> 32) == SELF_PID) return 0;
#define TID() ((u32)bpf_get_current_pid_tgid())

static __always_inline void hdr(struct event_t *e, u32 kind) {
    u64 pt = bpf_get_current_pid_tgid();
    e->ts = bpf_ktime_get_ns(); e->kind = kind; e->pid = pt >> 32; e->tid = (u32)pt;
    e->aux = 0; e->ret = 0; e->flags = 0; e->dirfd = 0; e->family = 0; e->port = 0;
    __builtin_memset(e->addr, 0, sizeof(e->addr));
    e->str[0] = 0;
}

/* returns 1 if the sockaddr is AF_INET / AF_INET6 and was copied into e */
static __always_inline int read_sockaddr(struct event_t *e, const void *uaddr) {
    u16 fam = 0;
    if (!uaddr) return 0;
    bpf_probe_read_user(&fam, sizeof(fam), uaddr);
    if (fam == AF_INET_) {
        struct sa4 a = {};
        bpf_probe_read_user(&a, sizeof(a), uaddr);
        e->family = fam; e->port = a.port; __builtin_memcpy(e->addr, &a.addr, 4);
        return 1;
    }
    if (fam == AF_INET6_) {
        struct sa6 a = {};
        bpf_probe_read_user(&a, sizeof(a), uaddr);
        e->family = fam; e->port = a.port; __builtin_memcpy(e->addr, a.addr, 16);
        return 1;
    }
    return 0;
}

/* ---- exec: sched_process_exec fires once per *successful* exec, in the new image. The filename comes from the
   tracepoint; argv is read from the new mm's argument area (NUL-separated), in two STRLEN chunks.
   (The per-syscall sys_enter_execve tracepoint does not fire for BPF on every kernel — e.g. 7.0 — so it is not used.) */
TRACEPOINT_PROBE(sched, sched_process_exec) {
    SKIP_SELF();
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;
    hdr(e, K_EXEC_ARG);
    TP_DATA_LOC_READ_STR(e->str, filename, STRLEN);
    events.ringbuf_submit(e, 0);
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = 0;
    bpf_probe_read_kernel(&mm, sizeof(mm), &t->mm);
    if (!mm) return 0;
    unsigned long as = 0, ae = 0;
    bpf_probe_read_kernel(&as, sizeof(as), &mm->arg_start);
    bpf_probe_read_kernel(&ae, sizeof(ae), &mm->arg_end);
    #pragma unroll
    for (int i = 0; i < ARGCHUNKS; i++) {
        unsigned long off = (unsigned long)i * STRLEN;
        if (as + off >= ae) break;
        unsigned long len = ae - as - off;
        if (len > STRLEN) len = STRLEN;
        struct event_t *a = events.ringbuf_reserve(sizeof(struct event_t));
        if (!a) return 0;
        hdr(a, K_EXEC_ARGV); a->aux = i; a->ret = (s64)len;
        bpf_probe_read_user(a->str, ((len - 1) & (STRLEN - 1)) + 1, (void *)(as + off));   /* 1..STRLEN, verifier-bounded */
        events.ringbuf_submit(a, 0);
    }
    return 0;
}

/* ---- syscalls: one raw sys_enter handler dispatching on the syscall number, one raw sys_exit handler completing
   the calls that were remembered at entry. (The per-syscall sys_enter_<name> tracepoints are not used: on some kernels
   - observed on 7.0 - they fire for only a fraction of the calls when a BPF program is attached; raw_syscalls fire
   for every call.) Syscall numbers and argument registers are substituted per architecture by user space. */
struct pend_t { const void *ptr; u64 flags; s32 dirfd; u32 kind; u32 variant; };
BPF_HASH(inflight, u32, struct pend_t, 32768);

static __always_inline int remember(u32 kind, u32 variant, const void *ptr, u64 flags, s32 dirfd) {
    if (!ptr) return 0;
    u32 tid = TID();
    struct pend_t p = {};
    p.ptr = ptr; p.flags = flags; p.dirfd = dirfd; p.kind = kind; p.variant = variant;
    inflight.update(&tid, &p);
    return 0;
}
static __always_inline int sock_now(u32 kind, u32 variant, const void *uaddr) {
    if (!uaddr) return 0;
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;
    hdr(e, kind); e->aux = variant;
    if (read_sockaddr(e, uaddr)) events.ringbuf_submit(e, 0);
    else events.ringbuf_discard(e, 0);
    return 0;
}

RAW_TRACEPOINT_PROBE(sys_enter) {
    long nr = (long)ctx->args[1];
    if (nr != SYS_openat && nr != SYS_open && nr != SYS_creat && nr != SYS_openat2 && nr != SYS_connect &&
        nr != SYS_sendto && nr != SYS_sendmsg && nr != SYS_recvfrom && nr != SYS_recvmsg && nr != SYS_accept &&
        nr != SYS_accept4 && nr != SYS_dup && nr != SYS_dup2 && nr != SYS_dup3 && nr != SYS_fcntl)
        return 0;
    SKIP_SELF();
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    unsigned long a0 = 0, a1 = 0, a2 = 0, a4 = 0;
    bpf_probe_read_kernel(&a0, sizeof(a0), &REG_ARG0);
    bpf_probe_read_kernel(&a1, sizeof(a1), &REG_ARG1);
    bpf_probe_read_kernel(&a2, sizeof(a2), &REG_ARG2);
    bpf_probe_read_kernel(&a4, sizeof(a4), &REG_ARG4);
    if (nr == SYS_openat)  return remember(K_OPEN, 0, (const void *)a1, a2, (s32)a0);
    if (nr == SYS_open)    return remember(K_OPEN, 0, (const void *)a0, a1, -100);
    if (nr == SYS_creat)   return remember(K_OPEN, 0, (const void *)a0, 01 | 0100 | 01000, -100);
    if (nr == SYS_openat2) {
        u64 f = 0;
        bpf_probe_read_user(&f, sizeof(f), (const void *)a2);    /* struct open_how { __u64 flags; ... } */
        return remember(K_OPEN, 0, (const void *)a1, f, (s32)a0);
    }
    if (nr == SYS_connect) return sock_now(K_CONNECT, 0, (const void *)a1);
    if (nr == SYS_sendto)  return sock_now(K_SEND, 0, (const void *)a4);
    if (nr == SYS_sendmsg) {
        const void *name = 0;
        bpf_probe_read_user(&name, sizeof(name), (const void *)a1);  /* struct user_msghdr { void *msg_name; ... } */
        return sock_now(K_SEND, 1, name);
    }
    /* fd duplication: the new fd refers to the same file (fd-relative opens through a dup'ed directory fd) */
    if (nr == SYS_dup || nr == SYS_dup2 || nr == SYS_dup3) return remember(K_DUP, 0, (const void *)1, a0, 0);
    if (nr == SYS_fcntl) {
        if (a1 == 0 || a1 == 1030) return remember(K_DUP, 0, (const void *)1, a0, 0);   /* F_DUPFD, F_DUPFD_CLOEXEC */
        return 0;
    }
    if (nr == SYS_recvfrom) return remember(K_RECV, 0, (const void *)a4, 0, 0);
    if (nr == SYS_recvmsg)  return remember(K_RECV, 1, (const void *)a1, 0, 0);
    return remember(K_ACCEPT, 0, (const void *)a1, 0, 0);              /* accept / accept4 */
}

RAW_TRACEPOINT_PROBE(sys_exit) {
    u32 tid = TID();
    struct pend_t *p = inflight.lookup(&tid);
    if (!p) return 0;
    long ret = (long)ctx->args[1];
    if (ret >= 0) {
        if (p->kind == K_DUP) {
            struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
            if (e) { hdr(e, K_DUP); e->aux = (u32)p->flags; e->ret = ret; events.ringbuf_submit(e, 0); }
        } else if (p->kind == K_OPEN) {
            struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
            if (e) {
                hdr(e, K_OPEN); e->ret = ret; e->flags = p->flags; e->dirfd = p->dirfd;
                bpf_probe_read_user_str(e->str, STRLEN, p->ptr);
                events.ringbuf_submit(e, 0);
            }
        } else {
            const void *uaddr = p->ptr;
            if (p->variant == 1) {          /* recvmsg: the msghdr's msg_name, filled in by the kernel */
                uaddr = 0;
                bpf_probe_read_user(&uaddr, sizeof(uaddr), p->ptr);
            }
            if (uaddr) {
                struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
                if (e) {
                    hdr(e, p->kind); e->aux = p->variant; e->ret = ret;
                    if (read_sockaddr(e, uaddr)) events.ringbuf_submit(e, 0);
                    else events.ringbuf_discard(e, 0);
                }
            }
        }
    }
    inflight.delete(&tid);
    return 0;
}

/* ---- process lifecycle ---- */
RAW_TRACEPOINT_PROBE(sched_process_fork) {
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
    u32 ptgid = 0, ctgid = 0;
    bpf_probe_read_kernel(&ptgid, sizeof(ptgid), &parent->tgid);
    bpf_probe_read_kernel(&ctgid, sizeof(ctgid), &child->tgid);
    if (ctgid == ptgid || ptgid == SELF_PID) return 0;   /* a new thread, or a child of the agent itself */
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;
    hdr(e, K_FORK); e->pid = ptgid; e->aux = ctgid;
    events.ringbuf_submit(e, 0);
    return 0;
}
TRACEPOINT_PROBE(sched, sched_process_exit) {
    if (!args->group_dead) return 0;
    SKIP_SELF();
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) return 0;
    hdr(e, K_EXIT);
    events.ringbuf_submit(e, 0);
    return 0;
}
"""


# syscall numbers and the pt_regs fields holding syscall arguments 0, 1, 2 and 4, per architecture
_ARCH = {
    "x86_64": ({"open": 2, "openat": 257, "openat2": 437, "creat": 85, "connect": 42, "sendto": 44, "sendmsg": 46,
                "recvfrom": 45, "recvmsg": 47, "accept": 43, "accept4": 288, "dup": 32, "dup2": 33, "dup3": 292, "fcntl": 72},
               ("regs->di", "regs->si", "regs->dx", "regs->r8")),
    "aarch64": ({"open": -1, "openat": 56, "openat2": 437, "creat": -1, "connect": 203, "sendto": 206, "sendmsg": 211,
                 "recvfrom": 207, "recvmsg": 212, "accept": 202, "accept4": 242, "dup": 23, "dup2": -1, "dup3": 24, "fcntl": 25},
                ("regs->regs[0]", "regs->regs[1]", "regs->regs[2]", "regs->regs[4]")),
}


def program(self_pid: int, ring_pages: int = 1024, arch: str | None = None) -> str:
    """The kernel program text for this architecture."""
    import platform
    arch = arch or platform.machine()
    if arch not in _ARCH:
        raise RuntimeError(f"eBPF collector: unsupported architecture {arch}")
    nrs, regs = _ARCH[arch]
    defs = "".join(f"#define SYS_{k} {v}\n" for k, v in nrs.items())
    defs += "".join(f"#define REG_ARG{i} {r}\n" for i, r in zip((0, 1, 2, 4), regs))
    return BPF_PROGRAM.replace("__SELF_PID__", str(self_pid)).replace("__RING_PAGES__", str(ring_pages)).replace("/*__SYSCALLS__*/", defs)


@dataclass
class Rec:
    """One decoded kernel record (the user-space mirror of struct event_t)."""
    kind: int
    pid: int
    ts_ns: int = 0
    tid: int = 0
    aux: int = 0            # FORK: child pid; EXEC_ARGV: chunk index; SEND/RECV: 1 = *msg variant; DUP: old fd
    ret: int = 0
    flags: int = 0
    dirfd: int = AT_FDCWD
    family: int = 0
    port: int = 0           # host byte order
    addr: bytes = b""
    s: str = ""
    raw: bytes = b""        # EXEC_ARGV: the raw argv bytes (NUL-separated), length = ret


def sock_ip(family: int, addr: bytes) -> str | None:
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, addr[:4])
    if family == socket.AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, addr[:16])
    return None


class EbpfNormaliser:
    """Kernel records -> (entities, Event), through the shared mapping. Stateful (exec arguments in flight, process
    generations, cwd cache); feed records in ring-buffer order."""

    def __init__(self, run_id: str | None = None, proc: str = "/proc", host_root: str | None = "/"):
        self.run_id = run_id or uuidlib.uuid4().hex[:12]
        self.map = ProvenanceMapper(self.run_id)
        self.procs = self.map.procs
        self.proc = proc
        self._exec: dict[int, tuple[int, str, list[bytes]]] = {}   # pid -> (ts, filename, argv chunks) awaiting chunks
        self._cwd: dict[int, str] = {}
        self._dirs: dict[tuple[int, int], str] = {}   # (pid, fd) -> path of the file/directory the process opened
        self.host_root = host_root                    # fallback root for symlink resolution after a process exited
        self._recent: dict[int, list[str]] = {}       # pid -> last few opened paths (dirfd fallback)

    # ---- /proc helpers (best effort: short-lived processes may be gone already) ----
    def _link(self, pid: int, what: str) -> str | None:
        try:
            return os.readlink(f"{self.proc}/{pid}/{what}")
        except OSError:
            return None

    def resolve(self, pid: int, path: str, dirfd: int, fd: int | None = None) -> str:
        """Absolute, symlink-free path of an opened file - what the kernel's d_path (and the strace collector's
        `-y`) reports - so both collectors give the file the same label.
        Relative names are joined to the cwd (AT_FDCWD) or to the directory the dirfd refers to (from this
        normaliser's record of what the process opened - correct at the time of the open, and it also covers
        short-lived processes such as `grep -r` and `tar` - else from /proc for fds opened before the agent started); symlinks are then resolved inside the process's root (/proc/<pid>/root, falling
        back to `host_root` once the process is gone)."""
        if not path.startswith("/"):
            if dirfd == AT_FDCWD:
                base = self._link(pid, "cwd")
                if base:
                    self._cwd[pid] = base
                else:
                    base = self._cwd.get(pid)
            else:
                # the stream's own record of what this fd was opened as comes first: /proc/<pid>/fd is read at decode
                # time, when a busy or short-lived process may already have closed and reused the fd (wrong label)
                base = self._dirs.get((pid, dirfd)) or self._link(pid, f"fd/{dirfd}") or self._recent_dir(pid)
            if not (base and base.startswith("/")):
                return path
            path = os.path.join(base, path)
        out = self._canon(pid, os.path.normpath(path))
        if fd is not None and fd >= 0:
            # every successful open is recorded (directories are often opened without O_DIRECTORY, e.g. by tar); a later
            # open returning the same fd overwrites it, and a process's entries are dropped when it exits
            if len(self._dirs) > 200_000:
                self._dirs.clear()
            self._dirs[(pid, fd)] = out
            rec = self._recent.setdefault(pid, [])
            rec.append(out)
            del rec[:-8]
        return out

    def _recent_dir(self, pid: int) -> str | None:
        """Fallback for a dirfd the process obtained without open() (dup/F_DUPFD, as fts-based walkers such as
        `grep -r` do) after the process exited: its most recently opened directory."""
        root = f"{self.proc}/{pid}/root" if os.path.isdir(f"{self.proc}/{pid}/root") else (self.host_root or "").rstrip("/")
        for p in reversed(self._recent.get(pid, [])):
            if os.path.isdir(root + p):
                return p
        return None

    DIR_CACHE_TTL = 10.0     # s; a symlink changed in a parent directory is picked up within this time

    def _canon(self, pid: int, path: str) -> str:
        """Resolve symlinks component by component as if chrooted at the process's root (absolute link targets are
        re-rooted there, not at the agent's own root).

        Hot path (every open): the resolved parent directory is cached per filesystem view - keyed by the identity
        of the process's root directory, so all processes of one container or of the host share entries - and only
        the last component is checked each time."""
        proot = f"{self.proc}/{pid}/root"
        try:
            st = os.stat(proot)
        except OSError:
            st = None
        if st is not None:
            out = self._canon_cached(proot, (st.st_dev, st.st_ino), path)
            if out is not None:
                return out
        return self._canon_at(self.host_root, path) if self.host_root is not None else path

    def _canon_cached(self, proot: str, rkey: tuple, path: str) -> str | None:
        d, base = os.path.split(path)
        now = time.monotonic()
        cache = self.__dict__.setdefault("_dir_cache", {})
        hit = cache.get((rkey, d))
        if hit is not None and now - hit[1] < self.DIR_CACHE_TTL:
            rd = hit[0]
        else:
            rd = self._canon_at(proot, d)
            if not os.path.isdir(proot):     # the process exited during the walk: its view is gone
                return None
            if len(cache) > 50_000:
                cache.clear()
            cache[(rkey, d)] = (rd, now)
        if not base:
            return rd
        cur = rd.rstrip("/") + "/" + base
        try:
            target = os.readlink(proot + cur)
        except OSError:                      # not a link (or gone): keep the name
            return cur
        return self._canon_at(proot, target if target.startswith("/") else rd.rstrip("/") + "/" + target)

    @staticmethod
    def _canon_at(root: str, path: str) -> str:
        root = root.rstrip("/")
        parts, done, hops = [p for p in path.split("/") if p], [], 0
        while parts:
            name = parts.pop(0)
            if name == "..":
                if done:
                    done.pop()
                continue
            cur = "/" + "/".join(done + [name])
            try:
                target = os.readlink(root + cur)
            except OSError:          # not a link (or gone): keep the name
                done.append(name)
                continue
            hops += 1
            if hops > 40:            # loop
                return path
            if target.startswith("/"):
                done = []
            parts = [p for p in target.split("/") if p and p != "."] + parts
        return "/" + "/".join(done)

    # ---- decoding ----
    def decode(self, r: Rec) -> Iterator[tuple[list[Entity], Event]]:
        ts = r.ts_ns or time.time_ns()
        M = self.map
        k = r.kind
        if k == EXEC:
            # the exec record is followed by its argv chunks; flush any previous exec of this pid still waiting
            yield from self._flush_exec(r.pid)
            self._exec[r.pid] = (ts, self.exec_path(r.pid, r.s), [])
        elif k == EXEC_ARGV:
            x = self._exec.get(r.pid)
            if x is not None and len(x[2]) == r.aux:
                x[2].append(r.raw if r.raw else r.s.encode())
                if r.ret < STRLEN or len(x[2]) == ARG_CHUNKS:   # last chunk
                    yield from self._flush_exec(r.pid)
        else:
            yield from self._flush_exec(r.pid)
        if k == FORK:
            if r.pid in self._cwd:
                self._cwd[r.aux] = self._cwd[r.pid]
            yield from M.fork(r.pid, r.aux, ts)
        elif k == EXIT:
            M.exit(r.pid)
            self._exec.pop(r.pid, None)
            for k in [k for k in self._dirs if k[0] == r.pid]:
                del self._dirs[k]
            self._recent.pop(r.pid, None)
            self._cwd.pop(r.pid, None)
        elif k == DUP:                     # new fd (ret) refers to what fd aux referred to
            src = self._dirs.get((r.pid, r.aux)) or self._link(r.pid, f"fd/{r.ret}")
            if src and src.startswith("/"):
                self._dirs[(r.pid, r.ret)] = src
        elif k == OPEN:
            if not r.s:
                return
            yield from M.open_flags(r.pid, ts, self.resolve(r.pid, r.s, r.dirfd, r.ret), r.flags)
        elif k in (CONNECT, SEND, RECV, ACCEPT):
            ip = sock_ip(r.family, r.addr)
            if ip is None:
                return
            op = {CONNECT: "CONNECT", SEND: "SENDMSG" if r.aux == 1 else "SENDTO",
                  RECV: "RECVMSG" if r.aux == 1 else "RECVFROM", ACCEPT: "RECVFROM"}[k]
            yield from M.socket(r.pid, ts, op, ip, r.port)

    def exec_path(self, pid: int, path: str) -> str:
        """The program an exec ran, as an absolute path (0.6). execve() takes the name as the caller wrote it:
        `execve("ls")` from /tmp runs /tmp/ls, and `/usr/bin/../../tmp/x` is /tmp/x - recorded verbatim, the first
        looked like the system's `ls` to layer 1 (a bare name matches a known program by name) and neither met the
        taint of the file the download wrote. Relative names are joined to the cwd and resolved
        like opened files; absolute paths are only normalised ('.', '..', '//'), not symlink-resolved, so program
        identities recorded before 0.6 stay the same (/usr/bin/python3 stays /usr/bin/python3)."""
        if not path:
            return path
        if path.startswith(("/dev/fd/", "/proc/self/fd/")):        # fexecve / memfd: the image has no name of its own
            img = self._link(pid, "exe")                           # e.g. '/memfd:payload (deleted)' - a program never seen
            return img if img else path
        if not path.startswith("/"):                               # the record carries no dirfd: relative to the cwd
            return self.resolve(pid, path, AT_FDCWD)
        if "/." in path or "//" in path:
            return posixpath.normpath(path) if not path.startswith("//") else "/" + posixpath.normpath(path).lstrip("/")
        return path

    def _flush_exec(self, pid: int):
        x = self._exec.pop(pid, None)
        if x is None:
            return
        ts, exe, chunks = x
        blob = b"".join(chunks)
        argv = [a.decode(errors="replace")[:ARG_MAX] for a in blob.split(b"\0")]
        while argv and argv[-1] == "":
            argv.pop()
        yield from self.map.exec(pid, ts, exe, argv)

    decode_event = decode   # backwards-compatible name


def parse_records(buf, mono_to_wall: int = 0) -> tuple[list[Rec], int, tuple[int, int] | None]:
    """Raw struct event_t records (as the CO-RE loader streams them) -> (Recs, bytes consumed, (lost in the kernel,
    dropped over the loader's spool limit) or None). A trailing partial record is left for the next call; STATS
    records update the counts instead of yielding.
    Field for field what BccTracer._on_event builds from bcc's ctypes view of the same struct."""
    n = len(buf) // REC.size
    out: list[Rec] = []
    lost = None
    for ts, kind, pid, tid, aux, ret, flags, dirfd, family, port, addr, sb in REC.iter_unpack(memoryview(buf)[:n * REC.size]):
        if kind == STATS:
            lost = (ret, flags)
            continue
        nul = sb.find(b"\0")
        out.append(Rec(kind=kind, pid=pid, ts_ns=ts + mono_to_wall, tid=tid, aux=aux, ret=ret, flags=flags, dirfd=dirfd,
                       family=family, port=socket.ntohs(port), addr=addr,
                       s=(sb if nul < 0 else sb[:nul]).decode(errors="replace"),
                       raw=sb[:max(0, min(ret, STRLEN))] if kind == EXEC_ARGV else b""))
    return out, n * REC.size, lost


def find_loader() -> str:
    """Path of the CO-RE loader binary: $PDP_EBPF_LOADER, the image's /opt/pdp/bin/pdp-ebpf, `pdp-ebpf` on PATH, or a
    development build in agent/bpf/."""
    here = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "bpf", "pdp-ebpf")
    for c in (os.environ.get("PDP_EBPF_LOADER"), "/opt/pdp/bin/pdp-ebpf", shutil.which("pdp-ebpf"), here):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise RuntimeError("eBPF collector (engine core): loader pdp-ebpf not found (set PDP_EBPF_LOADER, or build "
                       "agent/bpf with make; engine 'bcc' is the header-based fallback)")


class CoreTracer:
    """libbpf CO-RE engine: spawns the static loader (agent/bpf/pdp_ebpf.c), which loads the precompiled program,
    relocates it against the kernel's BTF, attaches it and streams raw ring-buffer records to a pipe. Same records,
    same order, same `poll` interface as BccTracer; the loader and `self_pid` (the agent) are excluded in-kernel."""
    engine = "core"

    def __init__(self, ring_pages: int = 1024, self_pid: int | None = None, loader: str | None = None,
                 start_timeout: float = 30.0, btf: str | None = None):
        if ring_pages & (ring_pages - 1):
            raise ValueError("ring_pages must be a power of two")
        if btf is None and not os.path.exists(KERNEL_BTF):
            raise RuntimeError(f"this kernel ({os.uname().release}) has no BTF ({KERNEL_BTF}) and no BTF file for it was found; "
                               "the server can provide one (BTF directory, see docs/DEPLOYMENT.md) or set PDP_BTF")
        self.loader = loader or find_loader()
        self.stats = {"lost": 0, "behind": 0}
        self._err: collections.deque = collections.deque(maxlen=40)
        t0 = time.monotonic()
        self.btf = btf
        self.p = subprocess.Popen([self.loader, "--ring-pages", str(ring_pages), "--exclude", str(self_pid or os.getpid())]
                                  + (["--btf", btf] if btf else []),
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        threading.Thread(target=self._drain_stderr, daemon=True, name="pdp-ebpf-stderr").start()
        self._fd = self.p.stdout.fileno()
        self._buf = bytearray()
        head = self._read_exact(STREAM_HEADER.size, start_timeout)
        magic, version, size = STREAM_HEADER.unpack(head)
        if magic != STREAM_MAGIC or version != STREAM_VERSION or size != REC.size:
            self.close()
            raise RuntimeError(f"eBPF loader {self.loader}: unexpected stream header {head!r} (version {version}, "
                               f"record size {size}; expected {STREAM_VERSION} / {REC.size})")
        self.startup_s = time.monotonic() - t0        # spawn -> every program loaded, relocated and attached
        self._mono_to_wall = time.time_ns() - time.monotonic_ns()   # bpf_ktime_get_ns is CLOCK_MONOTONIC

    def _drain_stderr(self):
        for line in iter(self.p.stderr.readline, b""):
            line = line.decode(errors="replace").rstrip()
            self._err.append(line)
            print(line if line.startswith("pdp-ebpf") else f"pdp-ebpf: {line}", file=sys.stderr, flush=True)

    def _dead(self, what: str) -> RuntimeError:
        try:
            rc = self.p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            rc = None
        time.sleep(0.05)                               # let the stderr thread pick up the last lines
        return RuntimeError(f"eBPF loader {what} (exit {rc}): " + " | ".join(self._err))

    def _read_exact(self, n: int, timeout: float) -> bytes:
        end = time.monotonic() + timeout
        while len(self._buf) < n:
            left = end - time.monotonic()
            if left <= 0:
                self.close()
                raise RuntimeError(f"eBPF loader did not start within {timeout:.0f}s: " + " | ".join(self._err))
            r, _, _ = select.select([self._fd], [], [], left)
            if r:
                chunk = os.read(self._fd, 1 << 16)
                if not chunk:
                    raise self._dead("failed to start")
                self._buf += chunk
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def poll(self, timeout_ms: int = 200) -> list[Rec]:
        r, _, _ = select.select([self._fd], [], [], timeout_ms / 1000)
        got = 0
        while r and got < (64 << 20):                  # what is ready now (bounded, like one ring-buffer poll)
            chunk = os.read(self._fd, 1 << 20)
            if not chunk:
                raise self._dead("exited")
            self._buf += chunk
            got += len(chunk)
            r, _, _ = select.select([self._fd], [], [], 0)
        recs, used, lost = parse_records(self._buf, self._mono_to_wall)
        del self._buf[:used]
        if lost is not None and lost != (self.stats["lost"], self.stats["behind"]):   # from the loader, at most every 10 s
            self.stats["lost"], self.stats["behind"] = lost
            print(f"pdp-ebpf: {lost[0]} records lost in the kernel so far (the loader did not drain the ring buffer in time: "
                  f"a saturated host; source.ring_pages raises the buffer), {lost[1]} dropped because the agent fell behind",
                  file=sys.stderr, flush=True)
        return recs

    def close(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.p.kill()
        for f in (self.p.stdout, self.p.stderr):
            try:
                f.close()
            except OSError:
                pass


class BccTracer:
    """bcc engine (fallback): compiles BPF_PROGRAM in-process against the running kernel's headers and hands out
    decoded records (Rec) in ring-buffer order. Compiling takes a few seconds and needs python3-bpfcc + headers."""
    engine = "bcc"

    def __init__(self, ring_pages: int = 1024, self_pid: int | None = None):
        from bcc import BPF   # imported here so the module loads without bcc (unit tests, other collectors)
        if ring_pages & (ring_pages - 1):
            raise ValueError("ring_pages must be a power of two")
        t0 = time.monotonic()
        text = program(self_pid or os.getpid(), ring_pages)
        self.b = BPF(text=text, cflags=["-w"])   # -w: the host kernel headers emit many harmless clang warnings
        self.stats = {"lost": 0}                 # not counted by this engine
        self._out: list[Rec] = []
        self._mono_to_wall = time.time_ns() - time.monotonic_ns()   # bpf_ktime_get_ns is CLOCK_MONOTONIC
        self.b["events"].open_ring_buffer(self._on_event)
        self.startup_s = time.monotonic() - t0

    def _on_event(self, ctx, data, size):
        e = self.b["events"].event(data)
        self._out.append(Rec(kind=e.kind, pid=e.pid, ts_ns=e.ts + self._mono_to_wall, tid=e.tid, aux=e.aux, ret=e.ret,
                             flags=e.flags, dirfd=e.dirfd, family=e.family, port=socket.ntohs(e.port), addr=bytes(e.addr),
                             s=e.str.decode(errors="replace") if isinstance(e.str, bytes) else str(e.str),
                             raw=self._raw_str(e, int(e.ret)) if e.kind == EXEC_ARGV else b""))

    @staticmethod
    def _raw_str(e, n: int) -> bytes:
        """The first n bytes of the record's str field, NULs included (ctypes stops a char[] at the first NUL)."""
        import ctypes
        return ctypes.string_at(ctypes.addressof(e) + type(e).str.offset, max(0, min(n, STRLEN)))

    def poll(self, timeout_ms: int = 200) -> list[Rec]:
        self.b.ring_buffer_poll(timeout_ms)
        out, self._out = self._out, []
        return out

    def close(self):
        self.b.cleanup()


ENGINES = {"core": CoreTracer, "bcc": BccTracer}


KERNEL_BTF = "/sys/kernel/btf/vmlinux"


def find_btf(data_dir: str | None = None) -> str | None:
    """None when the kernel has its own BTF; otherwise a BTF file for the running kernel: $PDP_BTF, or
    <data_dir>/btf/<release>.btf (downloaded from the server, which the operator stocks e.g. from BTFHub)."""
    if os.path.exists(KERNEL_BTF):
        return None
    env = os.environ.get("PDP_BTF")
    if env and os.path.isfile(env):
        return env
    if data_dir:
        f = os.path.join(data_dir, "btf", os.uname().release + ".btf")
        if os.path.isfile(f):
            return f
    return None


def EbpfTracer(ring_pages: int = 1024, self_pid: int | None = None, engine: str | None = None, btf: str | None = None):
    """The kernel tracer for `engine`: "core" (libbpf CO-RE, the default, or $PDP_EBPF_ENGINE) or "bcc" (the
    header-compiled fallback). Long-lived: the sandbox reuses one tracer for many workload sessions."""
    engine = engine or os.environ.get("PDP_EBPF_ENGINE") or "core"
    if engine not in ENGINES:
        raise ValueError(f"eBPF collector: unknown engine {engine!r} (core, bcc)")
    if engine == "core":
        return CoreTracer(ring_pages, self_pid, btf=btf)
    return ENGINES[engine](ring_pages, self_pid)


class EbpfLive:
    """eBPF source. Two modes:
       * system-wide (default): every process on the host except the agent itself (production endpoints).
       * workload:  `command` is spawned and only it and its descendants are reported, until it exits (sandbox,
                    collector cross-checks).
    Yields lists of (entities, Event) like the other collectors."""
    chronological = True   # wall-clock timestamps: a calendar day is complete once it has ended

    def __init__(self, batch: int = 2000, command: list[str] | None = None, tracer: CoreTracer | BccTracer | None = None,
                 run_id: str | None = None, cwd: str | None = None, ring_pages: int = 1024, proc: str = "/proc",
                 engine: str | None = None, btf: Callable[[], str | None] | None = None, retry_s: float = 600,
                 canary_s: float = 0, canary_dir: str | None = None):
        self.batch, self.command, self.cwd, self.ring_pages, self.engine = batch, command, cwd, ring_pages, engine
        self._tracer = tracer
        self.btf, self.retry_s = btf, retry_s       # btf: called before each start attempt (may download one)
        self.error: str | None = None               # why the collector is not running (reported in health)
        self.norm = EbpfNormaliser(run_id, proc=proc)
        self.proc: subprocess.Popen | None = None
        self.stats = {"records": 0, "events": 0}
        # 0.6 canary (system-wide mode only): every `canary_s` a short-lived child of the agent opens a file whose
        # name carries a fresh nonce; the collector must deliver that open. The child's records are consumed here (never
        # part of the provenance graph). Proves end to end that the probes are attached and the loader streams.
        self.canary_s, self.canary_dir = float(canary_s or 0), canary_dir
        self._canary = {"sent": 0, "seen": 0, "missed": 0, "last_seen": 0.0, "error": None}
        self._canary_pending: dict[str, tuple[float, subprocess.Popen, str]] = {}   # nonce -> (sent at, child, path)
        self._canary_pids: dict[int, float] = {}        # child pid -> when to forget it (its exit record normally first)
        self._canary_next = time.time() + 30
        self.CANARY_DEADLINE_S = 300.0                   # a canary not delivered by then counts as missed

    # ------------------------------------------------------------------ canary (0.6)
    def canary_status(self) -> dict | None:
        if not self.canary_s or self.command:
            return None
        c = self._canary
        out = {"sent": c["sent"], "seen": c["seen"], "missed": c["missed"], "pending": len(self._canary_pending),
               "last_seen_age_s": round(time.time() - c["last_seen"], 1) if c["last_seen"] else None}
        if c["error"]:
            out["error"] = c["error"]
        return out

    def _canary_tick(self) -> None:
        now = time.time()
        for nonce, (t0, child, path) in list(self._canary_pending.items()):
            if child.poll() is not None and child.returncode not in (0, None) and not self._canary["error"]:
                self._canary["error"] = f"canary child exited with {child.returncode}"
            if now - t0 > self.CANARY_DEADLINE_S:
                del self._canary_pending[nonce]
                self._canary["missed"] += 1
                self._canary_cleanup(child, path)
        for pid, until in list(self._canary_pids.items()):
            if now > until:
                del self._canary_pids[pid]
        if now < self._canary_next or self.command:
            return
        if not self._canary["sent"] and self.canary_dir:        # leftovers of an earlier run
            try:
                for f in os.listdir(self.canary_dir):
                    if f.startswith(".pdp-canary-"):
                        os.unlink(os.path.join(self.canary_dir, f))
            except OSError:
                pass
        self._canary_next = now + self.canary_s
        nonce = uuidlib.uuid4().hex
        d = self.canary_dir or "/tmp"
        path = os.path.join(d, f".pdp-canary-{nonce}")
        try:
            with open(path, "w") as f:                  # written by the agent itself: excluded in-kernel, not seen
                f.write("pdp collector canary\n")
            sh = "/bin/sh" if os.path.exists("/bin/sh") else None
            argv = [sh, "-c", 'exec 3< "$1"', "pdp-canary", path] if sh else [sys.executable, "-S", "-c", "import sys; open(sys.argv[1]).close()", path]
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        except OSError as e:
            self._canary["error"] = f"cannot start the canary: {e}"[:200]
            try:
                os.unlink(path)
            except OSError:
                pass
            return
        self._canary_pids[child.pid] = now + self.CANARY_DEADLINE_S + 60
        self._canary_pending[nonce] = (now, child, path)
        self._canary["sent"] += 1

    @staticmethod
    def _canary_cleanup(child, path) -> None:
        try:
            child.poll()
            os.unlink(path)
        except OSError:
            pass

    def _canary_record(self, r: Rec) -> None:
        """A record of a canary child: an open of a pending canary file marks it seen; all are consumed."""
        if r.kind == EXIT:
            self._canary_pids.pop(r.pid, None)
            return
        if r.kind != OPEN or not r.s:
            return
        name = os.path.basename(r.s)
        if not name.startswith(".pdp-canary-"):
            return
        x = self._canary_pending.pop(name[len(".pdp-canary-"):], None)
        if x is not None:
            self._canary["seen"] += 1
            self._canary["missed"] = 0
            self._canary["last_seen"] = time.time()
            self._canary["error"] = None
            self._canary_cleanup(x[1], x[2])

    @property
    def tracer(self) -> CoreTracer | BccTracer:
        if self._tracer is None:
            self._tracer = EbpfTracer(self.ring_pages, engine=self.engine, btf=self.btf() if self.btf else None)
        return self._tracer

    def _start(self, stop: Callable[[], bool]) -> Iterator[list]:
        """System-wide mode: a collector that cannot start (no BTF, missing privileges) must not crash-loop the agent;
        idle ticks keep it reporting (heartbeats carry the reason, commands and updates still arrive) and the
        collector is retried every `retry_s`."""
        while not stop():
            try:
                self.tracer
                if self.error:
                    print(f"eBPF collector started after: {self.error}", file=sys.stderr, flush=True)
                self.error = None
                return
            except Exception as e:  # noqa
                if self.command:
                    raise
                self.error = str(e)[:600]
                print(f"eBPF collector unavailable (retry in {self.retry_s:.0f}s): {self.error}", file=sys.stderr, flush=True)
            until = time.time() + self.retry_s
            while time.time() < until and not stop():
                yield []
                time.sleep(1)

    def _decode(self, recs: list[Rec], track: set[int] | None) -> list:
        out = []
        canary = self._canary_pids
        for r in recs:
            if canary and (r.pid in canary or (r.kind == OPEN and ".pdp-canary-" in r.s)):
                self._canary_record(r)
                continue
            if track is not None:
                if r.kind == FORK:
                    if r.pid not in track:
                        continue
                    track.add(r.aux)
                elif r.pid not in track:
                    continue
            self.stats["records"] += 1
            out.extend(self.norm.decode(r))
        self.stats["events"] += len(out)
        return out

    def batches(self, stop: Callable[[], bool]) -> Iterator[list]:
        yield from self._start(stop)
        if stop():
            return
        tr = self.tracer
        track: set[int] | None = None
        if self.command:
            self.proc = subprocess.Popen(self.command, cwd=self.cwd, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            track = {self.proc.pid}
        buf, last = [], time.time()
        while not stop():
            if self.canary_s and track is None:
                self._canary_tick()
            buf.extend(self._decode(tr.poll(200), track))
            done = self.proc is not None and self.proc.poll() is not None
            if done:
                for _ in range(3):                 # records still in flight when the workload exited
                    buf.extend(self._decode(tr.poll(50), track))
            if len(buf) >= self.batch or (buf and (done or time.time() - last > 2)):
                yield buf; buf = []; last = time.time()
            elif not done:
                yield []
            if done:
                break
        if buf:
            yield buf
