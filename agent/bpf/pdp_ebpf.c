// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/* pdp-ebpf: user-space loader of the PDP eBPF collector (libbpf CO-RE, skeleton embedded, statically linked).
 *
 *   pdp-ebpf [--ring-pages N] [--spool-mb M] [--exclude PID]... [--stats-interval S] [--btf FILE] [--nice N] [--check]
 *
 * Loads and attaches the kernel program (pdp_ebpf.bpf.c), relocated against the running kernel's BTF, then streams
 * the raw ring-buffer records (struct event_t, pdp_ebpf.h) to stdout in ring-buffer order. Stream: a 16-byte header
 * (magic "PDPEBPF\0", u32 version, u32 record size), written once every program is attached, then fixed-size records.
 * A K_STATS record (ret = records the kernel dropped, flags = records over the spool limit, aux = both) is written
 * when those counts change. The kernel writes compact records (header + the string's bytes); they are padded here.
 * The kernel ring buffer is drained at full speed into an in-memory spool (1 MB chunks, at most --spool-mb, default
 * 512) that a writer thread feeds to stdout, so a burst (a build opening 100k files) no longer overflows the ring
 * buffer while the agent decodes: memory is used only while the agent catches up. Records the spool cannot hold are
 * counted separately (the agent fell behind). The loader runs at nice -10 (--nice) so it drains the ring on busy hosts.
 * The loader's own process and every --exclude pid (the agent) are excluded in-kernel. It exits when stdout closes,
 * on SIGTERM/SIGINT, or when its parent (the agent) exits. --check loads and attaches, prints "ok" to stderr and exits.
 * Diagnostics go to stderr. */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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

#define CHUNK (1 << 20)

static volatile sig_atomic_t stop;
static int out_broken;

struct chunk { struct chunk *next; size_t len; char data[CHUNK]; };
static struct chunk *qhead, *qtail, *cur;          /* queue (writer thread) and the chunk being filled (main) */
static struct timespec cur_started;
static size_t qbytes, qmax = 512ull << 20;
static __u64 spool_dropped;
static int writer_done;
static pthread_mutex_t qm = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qc = PTHREAD_COND_INITIALIZER;

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

/* hand the chunk being filled to the writer thread */
static void flush_out(void) {
    if (!cur || !cur->len) return;
    pthread_mutex_lock(&qm);
    if (qtail) qtail->next = cur; else qhead = cur;
    qtail = cur;
    qbytes += CHUNK;
    pthread_cond_signal(&qc);
    pthread_mutex_unlock(&qm);
    cur = NULL;
}

static void *writer(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&qm);
        while (!qhead && !writer_done) pthread_cond_wait(&qc, &qm);
        struct chunk *c = qhead;
        if (c) { qhead = c->next; if (!qhead) qtail = NULL; }
        pthread_mutex_unlock(&qm);
        if (!c) return NULL;                  /* done and drained */
        if (!out_broken && write_all(c->data, c->len)) { out_broken = 1; stop = 1; }
        free(c);
        pthread_mutex_lock(&qm);
        qbytes -= CHUNK;
        pthread_mutex_unlock(&qm);
    }
}

/* a partly filled chunk goes to the writer when the writer is idle (low latency when quiet) or after 200 ms; during
   a burst chunks are handed over full, so the spool limit counts real data */
static void maybe_flush(void) {
    if (!cur || !cur->len) return;
    pthread_mutex_lock(&qm);
    int idle = qhead == NULL;
    pthread_mutex_unlock(&qm);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long ms = (now.tv_sec - cur_started.tv_sec) * 1000 + (now.tv_nsec - cur_started.tv_nsec) / 1000000;
    if (idle || ms >= 200) flush_out();
}

static int on_record(void *ctx, void *data, size_t size) {
    (void)ctx;
    struct event_t full;
    if (size < sizeof(full)) {          /* compact record (header + the string's bytes): pad to the stream's fixed size */
        memset(&full, 0, sizeof(full));
        memcpy(&full, data, size);
        data = &full; size = sizeof(full);
    }
    if (size > CHUNK) return 0;
    if (cur && cur->len + size > CHUNK) flush_out();
    if (!cur) {
        pthread_mutex_lock(&qm);
        int full = qbytes + CHUNK > qmax;
        pthread_mutex_unlock(&qm);
        if (full || !(cur = malloc(sizeof(*cur)))) { spool_dropped++; cur = NULL; return 0; }
        cur->next = NULL; cur->len = 0;
        clock_gettime(CLOCK_MONOTONIC, &cur_started);
    }
    memcpy(cur->data + cur->len, data, size);
    cur->len += size;
    return 0;
}

/* STATS record: ret = records the kernel dropped (ring buffer full: the loader did not get the CPU in time), flags =
   records dropped over the spool limit (the agent fell behind); aux = their sum, clamped (older agents read ret) */
static void emit_stats(__u64 lost, __u64 behind) {
    struct event_t e;
    struct timespec ts;
    memset(&e, 0, sizeof(e));
    clock_gettime(CLOCK_MONOTONIC, &ts);
    e.ts = (__u64)ts.tv_sec * 1000000000ull + (__u64)ts.tv_nsec;
    e.kind = K_STATS;
    e.pid = (__u32)getpid();
    e.aux = (__u32)(lost + behind > 0xffffffffull ? 0xffffffffull : lost + behind);
    e.ret = (__s64)lost;
    e.flags = behind;
    on_record(NULL, &e, sizeof(e));
}

static void usage(const char *p) {
    fprintf(stderr, "usage: %s [--ring-pages N] [--spool-mb M] [--exclude PID]... [--stats-interval S] [--btf FILE] [--nice N] [--check]\n", p);
}

int main(int argc, char **argv) {
    unsigned ring_pages = 1024, stats_interval = 10;
    /* the loader only moves records from the kernel ring into its spool; on a busy host it must get the CPU before
       the ring fills, or the kernel drops records (measured: 2 saturated CPUs, a file-open burst: 4129 lost at
       nice 0, none at -10). Best effort: needs CAP_SYS_NICE (the agent container is privileged). */
    int nice_level = -10;
    __u32 excl[MAX_EXCL] = {0};
    int nexcl = 0, check = 0, err;
    const char *btf = NULL;      /* kernels without /sys/kernel/btf/vmlinux: the kernel's BTF from a file (e.g. BTFHub) */
    static const struct option opts[] = {
        {"ring-pages", required_argument, 0, 'r'}, {"exclude", required_argument, 0, 'x'}, {"spool-mb", required_argument, 0, 'm'},
        {"stats-interval", required_argument, 0, 's'}, {"check", no_argument, 0, 'c'}, {"btf", required_argument, 0, 'b'},
        {"nice", required_argument, 0, 'n'}, {"help", no_argument, 0, 'h'}, {0, 0, 0, 0}};
    excl[nexcl++] = (__u32)getpid();
    for (int c; (c = getopt_long(argc, argv, "r:x:s:m:b:n:ch", opts, NULL)) != -1;) {
        switch (c) {
        case 'r': ring_pages = (unsigned)strtoul(optarg, NULL, 10); break;
        case 'm': qmax = (size_t)strtoull(optarg, NULL, 10) << 20; if (qmax < 2 * CHUNK) qmax = 2 * CHUNK; break;
        case 'x':
            if (nexcl == MAX_EXCL) { fprintf(stderr, "pdp-ebpf: at most %d excluded pids\n", MAX_EXCL - 1); return 2; }
            excl[nexcl++] = (__u32)strtoul(optarg, NULL, 10);
            break;
        case 's': stats_interval = (unsigned)strtoul(optarg, NULL, 10); break;
        case 'n': nice_level = (int)strtol(optarg, NULL, 10); break;
        case 'c': check = 1; break;
        case 'b': btf = optarg; break;
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
    if (setpriority(PRIO_PROCESS, 0, nice_level))       /* before the writer thread starts: it inherits it */
        fprintf(stderr, "pdp-ebpf: could not raise the priority to nice %d (%s); records may be lost on a busy host\n", nice_level, strerror(errno));
    /* kernels < 5.11 charge BPF memory to RLIMIT_MEMLOCK (newer ones use memcg; libbpf 1.x handles both) */
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);

    LIBBPF_OPTS(bpf_object_open_opts, oopts, .btf_custom_path = btf);
    struct pdp_ebpf_bpf *skel = pdp_ebpf_bpf__open_opts(&oopts);
    if (!skel) { fprintf(stderr, "pdp-ebpf: open failed: %s\n", strerror(errno)); return 1; }
    for (int i = 0; i < MAX_EXCL; i++) skel->rodata->excl[i] = excl[i];
    bpf_map__set_max_entries(skel->maps.events, ring_pages * (unsigned)getpagesize());
    if ((err = pdp_ebpf_bpf__load(skel))) {
        fprintf(stderr, "pdp-ebpf: load failed (%d: %s); the kernel needs BPF, BTF (/sys/kernel/btf/vmlinux or --btf FILE) and "
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
    fcntl(STDOUT_FILENO, F_SETPIPE_SZ, 1 << 20);   /* best effort: fewer wake-ups for the agent */
#endif
    struct { char magic[8]; __u32 version, recsize; } head;
    memcpy(head.magic, PDP_EBPF_MAGIC, 8);
    head.version = PDP_EBPF_VERSION; head.recsize = sizeof(struct event_t);
    if (write_all(&head, sizeof(head))) stop = 1;
    pthread_t wt;
    if (pthread_create(&wt, NULL, writer, NULL)) { fprintf(stderr, "pdp-ebpf: writer thread: %s\n", strerror(errno)); return 1; }

    __u64 reported = 0;
    time_t last = time(NULL);
    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "pdp-ebpf: poll: %s\n", strerror(-err)); break; }
        time_t now = time(NULL);
        if (stats_interval && now - last >= (time_t)stats_interval) {
            last = now;
            __u64 lost = __atomic_load_n(&skel->bss->lost, __ATOMIC_RELAXED) + __atomic_load_n(&skel->bss->nested, __ATOMIC_RELAXED);
            if (lost + spool_dropped != reported) { emit_stats(lost, spool_dropped); reported = lost + spool_dropped; }
        }
        if (getppid() != parent) stop = 1;
        maybe_flush();
    }
    ring_buffer__consume(rb);
    flush_out();
    pthread_mutex_lock(&qm); writer_done = 1; pthread_cond_signal(&qc); pthread_mutex_unlock(&qm);
    pthread_join(wt, NULL);
    __u64 lost = skel->bss->lost, nested = skel->bss->nested;
    if (lost || nested || spool_dropped)
        fprintf(stderr, "pdp-ebpf: %llu records lost in-kernel (ring buffer full), %llu (interrupted program runs), %llu over the spool limit\n",
                (unsigned long long)lost, (unsigned long long)nested, (unsigned long long)spool_dropped);
    ring_buffer__free(rb);
    pdp_ebpf_bpf__destroy(skel);
    return 0;
}
