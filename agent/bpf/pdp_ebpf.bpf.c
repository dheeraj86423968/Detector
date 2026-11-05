// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* PDP eBPF collector, kernel side (libbpf CO-RE). Compiled once at image build time against vmlinux.h; libbpf
 * relocates every kernel struct access against the running kernel's BTF (/sys/kernel/btf/vmlinux) at load, so
 * endpoints need neither kernel headers nor a compiler.
 *
 * Same hooks, filters and record stream as the bcc program it replaces (sources/ebpf.py: BPF_PROGRAM), with one
 * packaging difference: every hook is a *raw* tracepoint, so nothing needs tracefs (libbpf attaches raw tracepoints
 * by name; classic tracepoints need their id from tracefs).
 *   raw_tp/sched_process_exec   successful execs: filename (bprm->filename, what the classic tracepoint copies) + argv
 *   raw_tp/sys_enter, sys_exit  open/openat/openat2/creat, connect, send*, recv*, accept*, dup*, fcntl(F_DUPFD*)
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
#else
#error "pdp_ebpf: unsupported target architecture (define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64)"
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* set by the loader before load (read-only data: the verifier sees constants) */
const volatile __u32 excl[MAX_EXCL] = {};
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
    if (nr == SYS_recvfrom) return remember(K_RECV, 0, a4, 0, 0);
    if (nr == SYS_recvmsg)  return remember(K_RECV, 1, a1, 0, 0);
    return remember(K_ACCEPT, 0, a1, 0, 0);                         /* accept / accept4 */
}

SEC("raw_tp/sys_exit")
int pdp_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    __u32 tid = TID();
    struct pend_t *p = bpf_map_lookup_elem(&inflight, &tid);
    if (!p) return 0;
    long ret = (long)ctx->args[1];
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
            if (p->variant == 1) {          /* recvmsg: the msghdr's msg_name, filled in by the kernel */
                uaddr = 0;
                bpf_probe_read_user(&uaddr, sizeof(uaddr), (const void *)p->ptr);
            }
            if (uaddr) {
                struct event_t *e = begin(p->kind);
                if (e) {
                    e->aux = p->variant; e->ret = ret;
                    if (read_sockaddr(e, uaddr)) emit(e, 0);
                    else release();
                }
            }
        }
    }
    bpf_map_delete_elem(&inflight, &tid);
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
