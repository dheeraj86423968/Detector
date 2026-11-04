"""Production live collector: eBPF (bcc) -> normalised provenance events.

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
which matches the strace collector's `-y` output (tools/crosscheck.py compares the two collectors on the same
workloads). The agent's own process is excluded in-kernel.

Requirements: kernel >= 5.8 (ring buffer) with BPF; bcc (python3-bpfcc) and the running kernel's headers (bcc
compiles the program at start: mount /lib/modules and /usr/src read-only into the agent container, or install
linux-headers-$(uname -r)); CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN (or a privileged container) and the host pid
namespace so pids and /proc agree. `decode` is pure Python and unit-tested without a kernel (tests/unit/test_ebpf.py).
"""
from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid as uuidlib
from dataclasses import dataclass
from typing import Callable, Iterator

from pdp_engine.schema import Entity, Event

from .common import ProvenanceMapper

# record kinds emitted by the kernel program (keep in sync with BPF_PROGRAM)
EXEC, EXEC_ARGV, OPEN, CONNECT, SEND, RECV, ACCEPT, FORK, EXIT, DUP = range(10)
EXEC_ARG = EXEC   # old name
AT_FDCWD = -100
STRLEN = 512          # bytes per record string (kernel side)
ARG_CHUNKS = 2        # argv bytes captured = STRLEN * ARG_CHUNKS
ARG_MAX = 256         # per-argument truncation, as the strace collector's -s 256

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
        Relative names are joined to the cwd (AT_FDCWD) or to the directory the dirfd refers to (from /proc, or from
        this normaliser's record of what the process opened, so fd-relative opens of short-lived processes such as
        `grep -r` and `tar` still resolve); symlinks are then resolved inside the process's root (/proc/<pid>/root, falling
        back to `host_root` once the process is gone)."""
        if not path.startswith("/"):
            if dirfd == AT_FDCWD:
                base = self._link(pid, "cwd")
                if base:
                    self._cwd[pid] = base
                else:
                    base = self._cwd.get(pid)
            else:
                base = self._link(pid, f"fd/{dirfd}") or self._dirs.get((pid, dirfd)) or self._recent_dir(pid)
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

    def _canon(self, pid: int, path: str) -> str:
        """Resolve symlinks component by component as if chrooted at the process's root (absolute link targets are
        re-rooted there, not at the agent's own root)."""
        proot = f"{self.proc}/{pid}/root"
        if os.path.isdir(proot):
            out = self._canon_at(proot, path)
            if os.path.isdir(proot):       # still alive: the walk saw the process's own filesystem view
                return out
        return self._canon_at(self.host_root, path) if self.host_root is not None else path

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
            self._exec[r.pid] = (ts, r.s, [])
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


class EbpfTracer:
    """Loads the kernel program once and hands out decoded records (Rec) in ring-buffer order. Long-lived: the
    sandbox reuses one tracer for many workload sessions (compiling the program takes a few seconds)."""

    def __init__(self, ring_pages: int = 1024, self_pid: int | None = None):
        from bcc import BPF   # imported here so the module loads without bcc (unit tests, other collectors)
        if ring_pages & (ring_pages - 1):
            raise ValueError("ring_pages must be a power of two")
        text = program(self_pid or os.getpid(), ring_pages)
        self.b = BPF(text=text, cflags=["-w"])   # -w: the host kernel headers emit many harmless clang warnings
        self._out: list[Rec] = []
        self._mono_to_wall = time.time_ns() - time.monotonic_ns()   # bpf_ktime_get_ns is CLOCK_MONOTONIC
        self.b["events"].open_ring_buffer(self._on_event)

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


class EbpfLive:
    """eBPF source. Two modes:
       * system-wide (default): every process on the host except the agent itself (production endpoints).
       * workload:  `command` is spawned and only it and its descendants are reported, until it exits (sandbox,
                    collector cross-checks).
    Yields lists of (entities, Event) like the other collectors."""
    chronological = True   # wall-clock timestamps: a calendar day is complete once it has ended

    def __init__(self, batch: int = 2000, command: list[str] | None = None, tracer: EbpfTracer | None = None,
                 run_id: str | None = None, cwd: str | None = None, ring_pages: int = 1024, proc: str = "/proc"):
        self.batch, self.command, self.cwd, self.ring_pages = batch, command, cwd, ring_pages
        self._tracer = tracer
        self.norm = EbpfNormaliser(run_id, proc=proc)
        self.proc: subprocess.Popen | None = None
        self.stats = {"records": 0, "events": 0}

    @property
    def tracer(self) -> EbpfTracer:
        if self._tracer is None:
            self._tracer = EbpfTracer(self.ring_pages)
        return self._tracer

    def _decode(self, recs: list[Rec], track: set[int] | None) -> list:
        out = []
        for r in recs:
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
        tr = self.tracer
        track: set[int] | None = None
        if self.command:
            self.proc = subprocess.Popen(self.command, cwd=self.cwd, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            track = {self.proc.pid}
        buf, last = [], time.time()
        while not stop():
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
