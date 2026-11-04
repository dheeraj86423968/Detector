/* Record layout shared by the kernel program (pdp_ebpf.bpf.c), the loader (pdp_ebpf.c) and the Python decoder
 * (agent/pdp_agent/sources/ebpf.py: REC_FORMAT). It is the bcc collector's struct event_t, byte for byte, so both
 * engines feed the same `Rec`/`EbpfNormaliser.decode`. Keep the three in sync. */
#ifndef PDP_EBPF_H
#define PDP_EBPF_H

#define K_EXEC_ARG  0
#define K_EXEC_ARGV 1
#define K_OPEN      2
#define K_CONNECT   3
#define K_SEND      4
#define K_RECV      5
#define K_ACCEPT    6
#define K_FORK      7
#define K_EXIT      8
#define K_DUP       9
#define K_STATS     255   /* loader -> user space only: aux = records lost in-kernel (ring buffer full) since start */

#define STRLEN    512
#define ARGCHUNKS 2
#define MAX_EXCL  4       /* tgids excluded in-kernel (the loader itself and the agent) */

struct event_t {
    __u64 ts;            /* bpf_ktime_get_ns (CLOCK_MONOTONIC) */
    __u32 kind;
    __u32 pid;           /* thread-group id (the process) */
    __u32 tid;
    __u32 aux;           /* FORK: child pid; EXEC_ARGV: chunk index; SEND/RECV: 1 = *msg variant; DUP: old fd */
    __s64 ret;
    __u64 flags;
    __s32 dirfd;
    __u16 family;
    __u16 port;          /* network byte order */
    __u8  addr[16];
    char  str[STRLEN];
};                       /* 576 bytes, no padding */

/* stream header written by the loader once every program is attached: magic, version, sizeof(struct event_t) */
#define PDP_EBPF_MAGIC "PDPEBPF\0"
#define PDP_EBPF_VERSION 1

#endif
