// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* pdp-ebpf: user-space loader of the PDP eBPF collector (libbpf CO-RE, skeleton embedded, statically linked).
 *
 *   pdp-ebpf [--ring-pages N] [--exclude PID]... [--stats-interval S] [--check]
 *
 * Loads and attaches the kernel program (pdp_ebpf.bpf.c), relocated against the running kernel's BTF, then streams
 * the raw ring-buffer records (struct event_t, pdp_ebpf.h) to stdout in ring-buffer order. Stream: a 16-byte header
 * (magic "PDPEBPF\0", u32 version, u32 record size), written once every program is attached, then fixed-size records.
 * A K_STATS record (aux = records lost in-kernel so far) is written when that count changes.
 * The loader's own process and every --exclude pid (the agent) are excluded in-kernel. It exits when stdout closes,
 * on SIGTERM/SIGINT, or when its parent (the agent) exits. --check loads and attaches, prints "ok" to stderr and exits.
 * Diagnostics go to stderr. */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include "pdp_ebpf.h"
#include "pdp_ebpf.skel.h"

#define OUTBUF (256 * 1024)

static volatile sig_atomic_t stop;
static char outbuf[OUTBUF];
static size_t outlen;
static int out_broken;

static void on_signal(int sig) { (void)sig; stop = 1; }

static int libbpf_log(enum libbpf_print_level level, const char *fmt, va_list args) {
    if (level == LIBBPF_DEBUG && !getenv("PDP_EBPF_DEBUG")) return 0;
    return vfprintf(stderr, fmt, args);
}

static int write_all(const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t w = write(STDOUT_FILENO, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;                       /* EPIPE: the reader is gone */
        }
        p += w; n -= (size_t)w;
    }
    return 0;
}

static void flush_out(void) {
    if (outlen && !out_broken && write_all(outbuf, outlen)) { out_broken = 1; stop = 1; }
    outlen = 0;
}

static int on_record(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (outlen + size > OUTBUF) flush_out();
    if (size > OUTBUF) return 0;
    memcpy(outbuf + outlen, data, size);
    outlen += size;
    return 0;
}

static void emit_stats(__u64 lost) {
    struct event_t e;
    struct timespec ts;
    memset(&e, 0, sizeof(e));
    clock_gettime(CLOCK_MONOTONIC, &ts);
    e.ts = (__u64)ts.tv_sec * 1000000000ull + (__u64)ts.tv_nsec;
    e.kind = K_STATS;
    e.pid = (__u32)getpid();
    e.aux = (__u32)(lost > 0xffffffffull ? 0xffffffffull : lost);
    e.ret = (__s64)lost;
    on_record(NULL, &e, sizeof(e));
}

static void usage(const char *p) {
    fprintf(stderr, "usage: %s [--ring-pages N] [--exclude PID]... [--stats-interval S] [--check]\n", p);
}

int main(int argc, char **argv) {
    unsigned ring_pages = 1024, stats_interval = 10;
    __u32 excl[MAX_EXCL] = {0};
    int nexcl = 0, check = 0, err;
    static const struct option opts[] = {
        {"ring-pages", required_argument, 0, 'r'}, {"exclude", required_argument, 0, 'x'},
        {"stats-interval", required_argument, 0, 's'}, {"check", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};
    excl[nexcl++] = (__u32)getpid();
    for (int c; (c = getopt_long(argc, argv, "r:x:s:ch", opts, NULL)) != -1;) {
        switch (c) {
        case 'r': ring_pages = (unsigned)strtoul(optarg, NULL, 10); break;
        case 'x':
            if (nexcl == MAX_EXCL) { fprintf(stderr, "pdp-ebpf: at most %d excluded pids\n", MAX_EXCL - 1); return 2; }
            excl[nexcl++] = (__u32)strtoul(optarg, NULL, 10);
            break;
        case 's': stats_interval = (unsigned)strtoul(optarg, NULL, 10); break;
        case 'c': check = 1; break;
        default: usage(argv[0]); return c == 'h' ? 0 : 2;
        }
    }
    if (!ring_pages || (ring_pages & (ring_pages - 1))) { fprintf(stderr, "pdp-ebpf: --ring-pages must be a power of two\n"); return 2; }

    /* never outlive the agent: its death is noticed within one poll interval (getppid changes) or on the next write
       (EPIPE). PR_SET_PDEATHSIG is not used: it fires when the spawning *thread* exits, not the agent process. */
    pid_t parent = getppid();
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL); sigaction(SIGHUP, &sa, NULL);
    libbpf_set_print(libbpf_log);
    /* kernels < 5.11 charge BPF memory to RLIMIT_MEMLOCK (newer ones use memcg; libbpf 1.x handles both) */
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);

    struct pdp_ebpf_bpf *skel = pdp_ebpf_bpf__open();
    if (!skel) { fprintf(stderr, "pdp-ebpf: open failed: %s\n", strerror(errno)); return 1; }
    for (int i = 0; i < MAX_EXCL; i++) skel->rodata->excl[i] = excl[i];
    bpf_map__set_max_entries(skel->maps.events, ring_pages * (unsigned)getpagesize());
    if ((err = pdp_ebpf_bpf__load(skel))) {
        fprintf(stderr, "pdp-ebpf: load failed (%d: %s); the kernel needs BPF, BTF (/sys/kernel/btf/vmlinux) and "
                "the ring buffer (>= 5.8), and the process CAP_BPF+CAP_PERFMON (or CAP_SYS_ADMIN)\n", err, strerror(-err));
        pdp_ebpf_bpf__destroy(skel); return 1;
    }
    if ((err = pdp_ebpf_bpf__attach(skel))) {
        fprintf(stderr, "pdp-ebpf: attach failed (%d: %s)\n", err, strerror(-err));
        pdp_ebpf_bpf__destroy(skel); return 1;
    }
    if (check) { fprintf(stderr, "ok\n"); pdp_ebpf_bpf__destroy(skel); return 0; }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_record, NULL, NULL);
    if (!rb) { fprintf(stderr, "pdp-ebpf: ring buffer: %s\n", strerror(errno)); pdp_ebpf_bpf__destroy(skel); return 1; }
#ifdef F_SETPIPE_SZ
    fcntl(STDOUT_FILENO, F_SETPIPE_SZ, 1 << 20);   /* best effort: absorb bursts while the agent decodes */
#endif
    struct { char magic[8]; __u32 version, recsize; } head;
    memcpy(head.magic, PDP_EBPF_MAGIC, 8);
    head.version = PDP_EBPF_VERSION; head.recsize = sizeof(struct event_t);
    if (write_all(&head, sizeof(head))) stop = 1;

    __u64 reported = 0;
    time_t last = time(NULL);
    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "pdp-ebpf: poll: %s\n", strerror(-err)); break; }
        time_t now = time(NULL);
        if (stats_interval && now - last >= (time_t)stats_interval) {
            last = now;
            __u64 lost = __atomic_load_n(&skel->bss->lost, __ATOMIC_RELAXED);
            if (lost != reported) { emit_stats(lost); reported = lost; }
        }
        if (getppid() != parent) stop = 1;
        flush_out();
    }
    ring_buffer__consume(rb);
    flush_out();
    __u64 lost = skel->bss->lost;
    if (lost) fprintf(stderr, "pdp-ebpf: %llu records lost in-kernel (ring buffer full)\n", (unsigned long long)lost);
    ring_buffer__free(rb);
    pdp_ebpf_bpf__destroy(skel);
    return 0;
}
