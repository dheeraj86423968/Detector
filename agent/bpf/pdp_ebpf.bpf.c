// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* PDP eBPF collector, kernel side (libbpf CO-RE). Compiled once at image build time against vmlinux.h; libbpf
 * relocates every kernel struct access against the running kernel's BTF (/sys/kernel/btf/vmlinux) at load, so
 * endpoints need neither kernel headers nor a compiler.
 *
 * Same hooks, filters and record stream as the bcc program it replaces (sources/ebpf.py: BPF_PROGRAM), with one
 * packaging difference: every hook is a *raw* tracepoint, so nothing needs tracefs (libbpf attaches raw tracepoints
 * by name; classic tracepoints need their id from tracefs).
 *   raw_tp/sched_process_exec   successful execs: filename (bprm->filename, what the classic tracepoint copies) + argv
 *   raw_tp/sys_enter, sys_exit  open/openat/openat2/creat, connect, send*, recv*, accept*, dup*, fcntl(F_DUPFD*);
 *                               at exit also data on connected INET/INET6 sockets (K_SOCKIO): read, readv, preadv2,
 *                               write, writev, pwritev2, recvfrom/recvmsg/recvmmsg/sendto/sendmsg/sendmmsg without an
 *                               address, sendfile, splice. The socket and its peer come from the fd, in-kernel
 *                               (task->files->fdt->fd[fd] -> S_IFSOCK inode -> socket -> sk), so inherited, dup'ed and
 *                               passed fds need no user-space tracking. At most one record per (process image, edge,
 *                               peer) per re-emit interval (sockio_ns, LRU map iolast).
 *   raw_tp/io_uring_submit_req  io_uring READ/WRITE/SEND/RECV(MSG) on a socket fd (optional: attached if present)
 *   raw_tp/sched_process_fork   new processes (new threads filtered here)
 *   raw_tp/sched_process_exit   group exits
 * The per-syscall sys_enter_<name> tracepoints are deliberately not used: on kernel 7.0 they fire for only ~10% of
 * the calls when a BPF program is attached; raw sys_enter/sys_exit and sched_process_exec fire for every call.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "pdp_ebpf.h"

#define AF_INET_  2
#define AF_INET6_ 10
#define NO_SYSCALL (-1000L)   /* a syscall this architecture does not have */

#if defined(__TARGET_ARCH_x86)
#define SYS_open 2
#define SYS_openat 257
#define SYS_openat2 437
#define SYS_creat 85
#define SYS_connect 42
#define SYS_sendto 44
#define SYS_sendmsg 46
#define SYS_recvfrom 45
#define SYS_recvmsg 47
#define SYS_accept 43
#define SYS_accept4 288
#define SYS_dup 32
#define SYS_dup2 33
#define SYS_dup3 292
#define SYS_fcntl 72
#define SYS_read 0
#define SYS_write 1
#define SYS_readv 19
#define SYS_writev 20
#define SYS_preadv2 327
#define SYS_pwritev2 328
#define SYS_recvmmsg 299
#define SYS_sendmmsg 307
#define SYS_sendfile 40
#define SYS_splice 275
#define SYS_NR(regs) BPF_CORE_READ((regs), orig_ax)
#define SYS_ARG6(regs) BPF_CORE_READ((regs), r9)
#elif defined(__TARGET_ARCH_arm64)
#define SYS_open NO_SYSCALL
#define SYS_openat 56
#define SYS_openat2 437
#define SYS_creat NO_SYSCALL
#define SYS_connect 203
#define SYS_sendto 206
#define SYS_sendmsg 211
#define SYS_recvfrom 207
#define SYS_recvmsg 212
#define SYS_accept 202
#define SYS_accept4 242
#define SYS_dup 23
#define SYS_dup2 NO_SYSCALL
#define SYS_dup3 24
#define SYS_fcntl 25
#define SYS_read 63
#define SYS_write 64
#define SYS_readv 65
#define SYS_writev 66
#define SYS_preadv2 286
#define SYS_pwritev2 287
#define SYS_recvmmsg 243
#define SYS_sendmmsg 269
#define SYS_sendfile 71
#define SYS_splice 76
#define SYS_NR(regs) BPF_CORE_READ((regs), syscallno)
#define SYS_ARG6(regs) BPF_CORE_READ((regs), regs[5])
#else
#error "pdp_ebpf: unsupported target architecture (define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64)"
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* set by the loader before load (read-only data: the verifier sees constants) */
const volatile __u32 excl[MAX_EXCL] = {};
/* K_SOCKIO re-emit interval in ns (loader --sockio-interval-ms); 0 = socket data transfers are not traced */
const volatile __u64 sockio_ns = SOCKIO_MS * 1000000ULL;
/* records that could not be reserved because the ring buffer was full (read by the loader through the mmaped .bss) */
__u64 lost = 0;
/* records dropped because a program run was interrupted on its CPU by another run (scratch buffer busy) */
__u64 nested = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 4096);       /* resized by the loader (--ring-pages) */
} events SEC(".maps");

struct pend_t { __u64 ptr; __u64 flags; __s32 dirfd; __u32 kind; __u32 variant; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, struct pend_t);
} inflight SEC(".maps");

/* K_SOCKIO volume control: last record per (process, exec generation, edge, peer). The key is the provenance edge
   itself (process image -> op -> netflow node), so re-emitting within the interval could only repeat an edge the
   stream already has; bytes and calls of the suppressed transfers are summed into the next record of the key. */
struct io_key { __u32 tgid; __u32 op; __u64 gen; __u16 family; __u16 port; __u32 pad; __u8 addr[16]; };
struct io_val { __u64 ts; __u64 bytes; __u64 calls; };
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct io_key);
    __type(value, struct io_val);
} iolast SEC(".maps");
struct peer_t { __u16 family; __u16 port; __u8 addr[16]; };

struct sa4 { __u16 family; __u16 port; __u32 addr; };
struct sa6 { __u16 family; __u16 port; __u32 flowinfo; __u8 addr[16]; };

/* kernels >= 6.16 pass group_dead to sched_process_exit; probed through BTF (CO-RE flavour, independent of the
   vmlinux.h the program was built against) */
struct trace_event_raw_sched_process_exit___gd { bool group_dead; } __attribute__((preserve_access_index));

static __always_inline int excluded(__u32 tgid) {
    #pragma unroll
    for (int i = 0; i < MAX_EXCL; i++)
        if (excl[i] && excl[i] == tgid) return 1;
    return 0;
}
#define SKIP_SELF() if (excluded(bpf_get_current_pid_tgid() >> 32)) return 0;
#define TID() ((__u32)bpf_get_current_pid_tgid())

/* Records are built in a per-CPU scratch buffer and copied into the ring with only the bytes they use: the 64-byte
   header plus the string's bytes. Most records are 64-150 bytes instead of sizeof(struct event_t) = 576, so the ring
   holds 4-8x more of them through a burst. The loader pads them back to full size (the stream format is unchanged).
   Program runs can be interrupted on their CPU by another run (preemptible syscall tracepoints, measured on 7.0):
   each nesting level gets its own buffer (NEST per CPU); a record is dropped (counted in `nested`) only beyond that. */
#define NEST 4
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NEST);
    __type(key, __u32);
    __type(value, struct event_t);
} scratch SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} busy SEC(".maps");
#define HDR_BYTES ((__u64)__builtin_offsetof(struct event_t, str))

static __always_inline void hdr(struct event_t *e, __u32 kind);
static __always_inline struct event_t *begin(__u32 kind) {
    __u32 z = 0;
    __u32 *depth = bpf_map_lookup_elem(&busy, &z);       /* this CPU's nesting depth = the next free buffer */
    if (!depth) return 0;
    __u32 k = *depth;
    if (k >= NEST) { __sync_fetch_and_add(&nested, 1); return 0; }
    *depth = k + 1;
    struct event_t *e = bpf_map_lookup_elem(&scratch, &k);
    if (!e) { *depth = k; return 0; }
    hdr(e, kind);
    return e;
}
static __always_inline void release(void) {
    __u32 z = 0;
    __u32 *depth = bpf_map_lookup_elem(&busy, &z);
    if (depth && *depth) *depth -= 1;
}
/* copy the header and `strbytes` bytes of the string into the ring (a failed string read counts 0) */
static __always_inline void emit(struct event_t *e, long strbytes) {
    __u64 n = strbytes > 0 ? (__u64)strbytes : 0;
    if (n > STRLEN) n = STRLEN;
    if (bpf_ringbuf_output(&events, e, HDR_BYTES + n, 0)) __sync_fetch_and_add(&lost, 1);
    release();
}

static __always_inline void hdr(struct event_t *e, __u32 kind) {
    __u64 pt = bpf_get_current_pid_tgid();
    e->ts = bpf_ktime_get_ns(); e->kind = kind; e->pid = pt >> 32; e->tid = (__u32)pt;
    e->aux = 0; e->ret = 0; e->flags = 0; e->dirfd = 0; e->family = 0; e->port = 0;
    __builtin_memset(e->addr, 0, sizeof(e->addr));
    e->str[0] = 0;
}

/* returns 1 if the sockaddr is AF_INET / AF_INET6 and was copied into e */
static __always_inline int read_sockaddr(struct event_t *e, const void *uaddr) {
    __u16 fam = 0;
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

/* ---- data on connected sockets (K_SOCKIO) ---- */
#define S_IFMT_   00170000
#define S_IFSOCK_ 0140000

/* the socket behind fd in the current task's fd table, or 0 if fd is not a socket. Non-sockets (the bulk of
   read/write calls: files, pipes, ttys) are rejected after 7 reads: files, fdt, max_fds, fd[], fd[fd], f_inode, i_mode */
static __always_inline struct sock *fd_sock(int fd) {
    if (fd < 0) return 0;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct fdtable *fdt = BPF_CORE_READ(t, files, fdt);
    if (!fdt) return 0;
    if ((unsigned int)fd >= BPF_CORE_READ(fdt, max_fds)) return 0;
    struct file **arr = BPF_CORE_READ(fdt, fd);
    struct file *f = 0;
    bpf_probe_read_kernel(&f, sizeof(f), &arr[fd]);
    if (!f) return 0;
    if ((BPF_CORE_READ(f, f_inode, i_mode) & S_IFMT_) != S_IFSOCK_) return 0;
    struct socket *so = BPF_CORE_READ(f, private_data);
    if (!so) return 0;
    return BPF_CORE_READ(so, sk);
}

/* the peer of an INET/INET6 socket (port 0 = not connected); 0 for other families (unix, netlink, packet ...) */
static __always_inline int sock_peer(struct sock *sk, struct peer_t *p) {
    if (!sk) return 0;
    __u16 fam = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (fam == AF_INET_) {
        __u32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(p->addr, &d, 4);
    } else if (fam == AF_INET6_) {
        if (!bpf_core_field_exists(sk->__sk_common.skc_v6_daddr)) return 0;     /* CONFIG_IPV6=n */
        BPF_CORE_READ_INTO(&p->addr, sk, __sk_common.skc_v6_daddr);
    } else {
        return 0;
    }
    p->family = fam;
    p->port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    return 1;
}

/* a user sockaddr (the first message's msg_name of *mmsg on an unconnected socket) into p */
static __always_inline int user_peer(struct peer_t *p, const void *uaddr) {
    __u16 fam = 0;
    if (!uaddr) return 0;
    bpf_probe_read_user(&fam, sizeof(fam), uaddr);
    if (fam == AF_INET_) {
        struct sa4 a = {};
        bpf_probe_read_user(&a, sizeof(a), uaddr);
        p->port = a.port; __builtin_memcpy(p->addr, &a.addr, 4);
    } else if (fam == AF_INET6_) {
        struct sa6 a = {};
        bpf_probe_read_user(&a, sizeof(a), uaddr);
        p->port = a.port; __builtin_memcpy(p->addr, a.addr, 16);
    } else {
        return 0;
    }
    p->family = fam;
    return p->port != 0;
}

/* one K_SOCKIO record unless the same (process image, edge, peer) was reported less than sockio_ns ago */
static __always_inline void sockio_out(__u32 op, __u64 variant, __s32 fd, struct peer_t *p, __u64 amount) {
    struct io_key k;
    __builtin_memset(&k, 0, sizeof(k));
    k.tgid = bpf_get_current_pid_tgid() >> 32;
    k.op = op;
    k.family = p->family; k.port = p->port;
    __builtin_memcpy(k.addr, p->addr, 16);
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    k.gen = BPF_CORE_READ(t, self_exec_id);      /* bumped by every exec: a new image is a new process node */
    __u64 now = bpf_ktime_get_ns(), calls = 1;
    struct io_val *v = bpf_map_lookup_elem(&iolast, &k);
    if (v) {
        if ((__s64)(now - v->ts) < (__s64)sockio_ns) {
            __sync_fetch_and_add(&v->bytes, amount);
            __sync_fetch_and_add(&v->calls, 1);
            return;
        }
        amount += v->bytes; calls += v->calls;
        v->ts = now; v->bytes = 0; v->calls = 0;
    } else {
        struct io_val nv = {};
        nv.ts = now;
        bpf_map_update_elem(&iolast, &k, &nv, BPF_ANY);
    }
    struct event_t *e = begin(K_SOCKIO);
    if (!e) return;
    e->aux = op; e->ret = (__s64)amount; e->flags = variant | (calls << 32); e->dirfd = fd;
    e->family = p->family; e->port = p->port;
    __builtin_memcpy(e->addr, p->addr, 16);
    emit(e, 0);
}

/* sk (behind fd) is a socket: report the transfer if it is INET/INET6 with a peer. opv = op << 32 | variant. mmsg: the
   user mmsghdr array (unconnected sockets: the first message's address is the peer). A BPF subprogram (one copy for
   every call site); the non-socket rejection in fd_sock stays inlined in the hot path. */
static __noinline void sockio_sk(__u64 opv, int fd, struct sock *sk, __u64 amount, const void *mmsg) {
    __u32 op = opv >> 32;
    __u64 variant = opv & 0xffffffffull;
    struct peer_t p = {};
    if (!sock_peer(sk, &p)) return;
    if (!p.port) {                                     /* not connected */
        if (!mmsg) return;                             /* recv without an address on an unconnected socket: no peer */
        const void *name = 0;
        bpf_probe_read_user(&name, sizeof(name), mmsg);             /* mmsghdr.msg_hdr.msg_name */
        if (variant == SV_RECVMMSG) {
            __u32 nl = 0;
            bpf_probe_read_user(&nl, sizeof(nl), (const char *)mmsg + 8);   /* msg_namelen, set by the kernel */
            if (!nl) return;
        }
        if (!user_peer(&p, name)) return;
    }
    sockio_out(op, variant, fd, &p, amount);
}

static __always_inline void sockio_fd(__u32 op, __u64 variant, int fd, __u64 amount, const void *mmsg) {
    struct sock *sk = fd_sock(fd);
    if (sk) sockio_sk(((__u64)op << 32) | variant, fd, sk, amount, mmsg);
}

/* syscall exit with ret > 0: data moved on a socket fd. Runs for every successful syscall exit, so the syscall number
   test comes first and only the traced calls read anything else. */
static __always_inline int sockio_exit(struct pt_regs *regs, long ret) {
    if (!sockio_ns) return 0;
    long nr = (long)SYS_NR(regs);
    __u32 op; __u64 v; const void *mmsg = 0;
    if (nr == SYS_read)                                 { op = IO_READ;     v = SV_READ; }
    else if (nr == SYS_write)                           { op = IO_WRITE;    v = SV_WRITE; }
    else if (nr == SYS_readv || nr == SYS_preadv2)      { op = IO_READ;     v = SV_READV; }
    else if (nr == SYS_writev || nr == SYS_pwritev2)    { op = IO_WRITE;    v = SV_WRITEV; }
    else if (nr == SYS_recvfrom)                        { op = IO_RECVFROM; v = SV_RECVFROM; }
    else if (nr == SYS_recvmsg)                         { op = IO_RECVMSG;  v = SV_RECVMSG; }
    else if (nr == SYS_sendfile)                        { op = IO_WRITE;    v = SV_SENDFILE; }
    else if (nr == SYS_splice)                          { op = IO_WRITE;    v = SV_SPLICE; }
    else if (nr == SYS_sendto) {
        if (PT_REGS_PARM5_CORE_SYSCALL(regs)) return 0;              /* with a destination: reported at entry */
        op = IO_SENDTO; v = SV_SENDTO;
    } else if (nr == SYS_sendmsg) {
        const void *name = 0;
        bpf_probe_read_user(&name, sizeof(name), (const void *)PT_REGS_PARM2_CORE_SYSCALL(regs));
        if (name) return 0;                                          /* with a destination: reported at entry */
        op = IO_SENDMSG; v = SV_SENDMSG;
    } else if (nr == SYS_recvmmsg) {
        op = IO_RECVMSG; v = SV_RECVMMSG; mmsg = (const void *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    } else if (nr == SYS_sendmmsg) {
        op = IO_SENDMSG; v = SV_SENDMMSG; mmsg = (const void *)PT_REGS_PARM2_CORE_SYSCALL(regs);
    } else {
        return 0;
    }
    SKIP_SELF();
    if (v == SV_SPLICE) {                       /* splice(fd_in, off_in, fd_out, ...): either end can be the socket */
        sockio_fd(IO_WRITE, v, (int)PT_REGS_PARM3_CORE_SYSCALL(regs), ret, 0);
        sockio_fd(IO_READ, v, (int)PT_REGS_PARM1_CORE_SYSCALL(regs), ret, 0);
        return 0;
    }
    sockio_fd(op, v, (int)PT_REGS_PARM1_CORE_SYSCALL(regs), ret, mmsg);
    return 0;
}

/* ---- exec: fires once per successful exec, in the new image (args: task, old_pid, bprm) ---- */
SEC("raw_tp/sched_process_exec")
int pdp_exec(struct bpf_raw_tracepoint_args *ctx) {
    SKIP_SELF();
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
    struct event_t *e = begin(K_EXEC_ARG);
    if (!e) return 0;
    emit(e, bpf_probe_read_kernel_str(e->str, STRLEN, BPF_CORE_READ(bprm, filename)));
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(t, mm);
    if (!mm) return 0;
    unsigned long as = BPF_CORE_READ(mm, arg_start), ae = BPF_CORE_READ(mm, arg_end);
    #pragma unroll
    for (int i = 0; i < ARGCHUNKS; i++) {
        unsigned long off = (unsigned long)i * STRLEN;
        if (as + off >= ae) break;
        unsigned long len = ae - as - off;
        if (len > STRLEN) len = STRLEN;
        struct event_t *a = begin(K_EXEC_ARGV);
        if (!a) return 0;
        a->aux = i; a->ret = (__s64)len;
        bpf_probe_read_user(a->str, ((len - 1) & (STRLEN - 1)) + 1, (void *)(as + off));   /* 1..STRLEN, verifier-bounded */
        emit(a, (long)len);
    }
    return 0;
}

/* ---- syscalls: one raw sys_enter handler dispatching on the syscall number, one raw sys_exit handler completing
   the calls that were remembered at entry ---- */
static __always_inline int remember(__u32 kind, __u32 variant, __u64 ptr, __u64 flags, __s32 dirfd) {
    if (!ptr) return 0;
    __u32 tid = TID();
    struct pend_t p = {};
    p.ptr = ptr; p.flags = flags; p.dirfd = dirfd; p.kind = kind; p.variant = variant;
    bpf_map_update_elem(&inflight, &tid, &p, BPF_ANY);
    return 0;
}
static __always_inline int sock_now(__u32 kind, __u32 variant, const void *uaddr) {
    if (!uaddr) return 0;
    struct event_t *e = begin(kind);
    if (!e) return 0;
    e->aux = variant;
    if (read_sockaddr(e, uaddr)) emit(e, 0);
    else release();
    return 0;
}

SEC("raw_tp/sys_enter")
int pdp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    long nr = (long)ctx->args[1];
    if (nr != SYS_openat && nr != SYS_open && nr != SYS_creat && nr != SYS_openat2 && nr != SYS_connect &&
        nr != SYS_sendto && nr != SYS_sendmsg && nr != SYS_recvfrom && nr != SYS_recvmsg && nr != SYS_accept &&
        nr != SYS_accept4 && nr != SYS_dup && nr != SYS_dup2 && nr != SYS_dup3 && nr != SYS_fcntl)
        return 0;
    SKIP_SELF();
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    unsigned long a0 = PT_REGS_PARM1_CORE_SYSCALL(regs);
    unsigned long a1 = PT_REGS_PARM2_CORE_SYSCALL(regs);
    unsigned long a2 = PT_REGS_PARM3_CORE_SYSCALL(regs);
    unsigned long a4 = PT_REGS_PARM5_CORE_SYSCALL(regs);
    if (nr == SYS_openat)  return remember(K_OPEN, 0, a1, a2, (__s32)a0);
    if (nr == SYS_open)    return remember(K_OPEN, 0, a0, a1, -100);
    if (nr == SYS_creat)   return remember(K_OPEN, 0, a0, 01 | 0100 | 01000, -100);
    if (nr == SYS_openat2) {
        __u64 f = 0;
        bpf_probe_read_user(&f, sizeof(f), (const void *)a2);    /* struct open_how { __u64 flags; ... } */
        return remember(K_OPEN, 0, a1, f, (__s32)a0);
    }
    if (nr == SYS_connect) return sock_now(K_CONNECT, 0, (const void *)a1);
    if (nr == SYS_sendto)  return sock_now(K_SEND, 0, (const void *)a4);
    if (nr == SYS_sendmsg) {
        const void *name = 0;
        bpf_probe_read_user(&name, sizeof(name), (const void *)a1);  /* struct user_msghdr { void *msg_name; ... } */
        return sock_now(K_SEND, 1, name);
    }
    /* fd duplication: the new fd refers to the same file (fd-relative opens through a dup'ed directory fd) */
    if (nr == SYS_dup || nr == SYS_dup2 || nr == SYS_dup3) return remember(K_DUP, 0, 1, a0, 0);
    if (nr == SYS_fcntl) {
        if (a1 == 0 || a1 == 1030) return remember(K_DUP, 0, 1, a0, 0);   /* F_DUPFD, F_DUPFD_CLOEXEC */
        return 0;
    }
    /* recv*: the address is read at exit and only if the kernel returned one (*addrlen / msg_namelen > 0; a TCP socket
       returns none and leaves the caller's buffer as it was); otherwise the socket's own peer is used (K_SOCKIO) */
    if (nr == SYS_recvfrom) return remember(K_RECV, 0, a4, SYS_ARG6(regs), 0);
    if (nr == SYS_recvmsg)  return remember(K_RECV, 1, a1, 0, 0);
    return remember(K_ACCEPT, 0, a1, 0, 0);                         /* accept / accept4 */
}

SEC("raw_tp/sys_exit")
int pdp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    __u32 tid = TID();
    long ret = (long)ctx->args[1];
    struct pend_t *p = bpf_map_lookup_elem(&inflight, &tid);
    if (!p)
        goto sockio;                    /* the common case: nothing remembered at entry */
    int addressed = 1;                  /* 0: a recv* that returned no address: the socket's own peer is used */
    if (ret >= 0) {
        if (p->kind == K_DUP) {
            struct event_t *e = begin(K_DUP);
            if (e) { e->aux = (__u32)p->flags; e->ret = ret; emit(e, 0); }
        } else if (p->kind == K_OPEN) {
            struct event_t *e = begin(K_OPEN);
            if (e) {
                e->ret = ret; e->flags = p->flags; e->dirfd = p->dirfd;
                emit(e, bpf_probe_read_user_str(e->str, STRLEN, (const void *)p->ptr));
            }
        } else {
            const void *uaddr = (const void *)p->ptr;
            __u32 alen = 1;
            if (p->kind == K_RECV) {
                if (p->variant == 1) {      /* recvmsg: the msghdr's msg_name / msg_namelen, filled in by the kernel */
                    uaddr = 0;
                    bpf_probe_read_user(&uaddr, sizeof(uaddr), (const void *)p->ptr);
                    bpf_probe_read_user(&alen, sizeof(alen), (const char *)p->ptr + 8);
                } else if (p->flags) {      /* recvfrom: *addrlen */
                    bpf_probe_read_user(&alen, sizeof(alen), (const void *)p->flags);
                }
                addressed = 0;
            }
            if (uaddr && alen) {
                struct event_t *e = begin(p->kind);
                if (e) {
                    e->aux = p->variant; e->ret = ret;
                    if (read_sockaddr(e, uaddr)) { emit(e, 0); addressed = 1; }
                    else release();
                }
            }
        }
    }
    bpf_map_delete_elem(&inflight, &tid);
    if (addressed) return 0;
sockio:
    if (ret > 0) sockio_exit((struct pt_regs *)ctx->args[0], ret);
    return 0;
}

/* ---- process lifecycle ---- */
SEC("raw_tp/sched_process_fork")
int pdp_fork(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
    __u32 ptgid = BPF_CORE_READ(parent, tgid), ctgid = BPF_CORE_READ(child, tgid);
    if (ctgid == ptgid || excluded(ptgid)) return 0;     /* a new thread, or a child of the agent / loader */
    struct event_t *e = begin(K_FORK);
    if (!e) return 0;
    e->pid = ptgid; e->aux = ctgid;
    emit(e, 0);
    return 0;
}

SEC("raw_tp/sched_process_exit")
int pdp_exit(struct bpf_raw_tracepoint_args *ctx) {
    int group_dead;
    if (bpf_core_field_exists(struct trace_event_raw_sched_process_exit___gd, group_dead)) {
        group_dead = (int)(__u8)ctx->args[1];                    /* trace_sched_process_exit(tsk, group_dead) */
    } else {                                                     /* older kernels: signal->live already decremented */
        struct task_struct *t = (struct task_struct *)ctx->args[0];
        group_dead = BPF_CORE_READ(t, signal, live.counter) == 0;
    }
    if (!group_dead) return 0;
    SKIP_SELF();
    struct event_t *e = begin(K_EXIT);
    if (!e) return 0;
    emit(e, 0);
    return 0;
}

/* ---- io_uring: requests bypass the syscalls above (IORING_OP_READ/WRITE/SEND/RECV... are issued by the kernel, from
   the submitting task, an SQPOLL thread or an io-wq worker - all threads of the owning process sharing its fd table).
   The submission tracepoint fires for every request in the submitter's context (the SQPOLL thread with SQPOLL), with
   the fd still in req->cqe.fd. The result is not known yet (ret = 0: an attempt, not a confirmed transfer). Not
   covered: registered ("fixed") files (IOSQE_FIXED_FILE: an index into the ring's file table, not an fd) and
   IORING_OP_CONNECT / ACCEPT / OPENAT (no CONNECT / OPEN edges for those). Optional: the loader attaches it only if
   the kernel has the tracepoint (5.19+; older kernels name it io_uring_submit_sqe with other arguments). ---- */
SEC("raw_tp/io_uring_submit_req")
int pdp_uring(struct bpf_raw_tracepoint_args *ctx) {
    if (!sockio_ns) return 0;
    struct io_kiocb *req = (struct io_kiocb *)ctx->args[0];
    if (!bpf_core_field_exists(req->cqe.fd) || !bpf_core_field_exists(req->flags)) return 0;
    __u8 opc = BPF_CORE_READ(req, opcode);
    __u32 op;
    switch (opc) {
    case 1: case 4: case 22: case 49: case 60:  op = IO_READ; break;      /* READV, READ_FIXED, READ, READ_MULTISHOT, READV_FIXED */
    case 2: case 5: case 23: case 61:           op = IO_WRITE; break;     /* WRITEV, WRITE_FIXED, WRITE, WRITEV_FIXED */
    case 26: case 47:                           op = IO_SENDTO; break;    /* SEND, SEND_ZC */
    case 27: case 58:                           op = IO_RECVFROM; break;  /* RECV, RECV_ZC */
    case 9: case 48:                            op = IO_SENDMSG; break;   /* SENDMSG, SENDMSG_ZC */
    case 10:                                    op = IO_RECVMSG; break;   /* RECVMSG */
    default: return 0;
    }
    __u8 fl = 0;
    bpf_core_read(&fl, 1, &req->flags);         /* low byte (little endian): REQ_F_FIXED_FILE is bit 0 */
    if (fl & 1) return 0;
    SKIP_SELF();
    int fd = BPF_CORE_READ(req, cqe.fd);
    sockio_fd(op, SV_URING | ((__u64)opc << 8), fd, 0, 0);
    return 0;
}
