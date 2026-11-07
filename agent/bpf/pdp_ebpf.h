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
#define K_SOCKIO    10    /* data transferred on a connected INET/INET6 socket (read/write/send/recv without address) */
#define K_STATS     255   /* loader -> user space only: aux = records lost in-kernel (ring buffer full) since start */

/* K_SOCKIO: aux = the edge the call maps to (IO_*), flags = variant (SV_*) | io_uring opcode << 8 | calls << 32 */
#define IO_READ     0     /* read, readv, preadv2, splice from a socket, io_uring READ*         netflow -> process */
#define IO_WRITE    1     /* write, writev, pwritev2, sendfile / splice to a socket, io_uring WRITE*  process -> netflow */
#define IO_RECVFROM 2     /* recvfrom without an address returned, io_uring RECV                  netflow -> process */
#define IO_RECVMSG  3     /* recvmsg without an address returned, recvmmsg, io_uring RECVMSG      netflow -> process */
#define IO_SENDTO   4     /* sendto without a destination, io_uring SEND                          process -> netflow */
#define IO_SENDMSG  5     /* sendmsg without a destination, sendmmsg, io_uring SENDMSG            process -> netflow */
#define SV_READ 0
#define SV_READV 1
#define SV_WRITE 2
#define SV_WRITEV 3
#define SV_RECVFROM 4
#define SV_RECVMSG 5
#define SV_RECVMMSG 6
#define SV_SENDTO 7
#define SV_SENDMSG 8
#define SV_SENDMMSG 9
#define SV_SENDFILE 10
#define SV_SPLICE 11
#define SV_URING 12       /* io_uring submission (opcode in bits 8-15; ret = 0: the result is not known at submit) */
#define SOCKIO_MS 2000    /* default re-emit interval per (process image, op, peer) */

#define STRLEN    512
#define ARGCHUNKS 2
#define MAX_EXCL  4       /* tgids excluded in-kernel (the loader itself and the agent) */

struct event_t {
    __u64 ts;            /* bpf_ktime_get_ns (CLOCK_MONOTONIC) */
    __u32 kind;
    __u32 pid;           /* thread-group id (the process) */
    __u32 tid;
    __u32 aux;           /* FORK: child pid; EXEC_ARGV: chunk index; SEND/RECV: 1 = *msg variant; DUP: old fd; SOCKIO: IO_* */
    __s64 ret;           /* SOCKIO: bytes (messages for *mmsg) since the previous record of the same key, this call included */
    __u64 flags;
    __s32 dirfd;         /* SOCKIO: the fd */
    __u16 family;
    __u16 port;          /* network byte order */
    __u8  addr[16];
    char  str[STRLEN];
};                       /* 576 bytes, no padding */

/* stream header written by the loader once every program is attached: magic, version, sizeof(struct event_t) */
#define PDP_EBPF_MAGIC "PDPEBPF\0"
#define PDP_EBPF_VERSION 1

#endif
