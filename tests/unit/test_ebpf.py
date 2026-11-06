"""Unit tests for the eBPF collector's record -> event mapping (no kernel/bcc needed), and for the kernel program
text generation and the CO-RE loader stream parser. Run: PYTHONPATH=engine:agent python tests/unit/test_ebpf.py
"""
import socket
import sys

from pdp_agent.sources.ebpf import (ACCEPT, CONNECT, DUP, EXEC, EXEC_ARGV, EXIT, FORK, OPEN, RECV, SEND, STRLEN,
                                    EbpfNormaliser, Rec, program)
from pdp_agent.sources.strace_src import StraceNormaliser

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


n = EbpfNormaliser("boot", proc="/nonexistent")   # no /proc lookups in tests


def feed(*recs):
    out = []
    for r in recs:
        out.extend((ev.op, ents[0].ntype, ents[1].ntype, ents[0].label, ents[1].label, ev.ts_ns) for ents, ev in n.decode(r))
    return out


def argv(*a):
    blob = b"\0".join(x.encode() for x in a) + b"\0"
    return Rec(EXEC_ARGV, 100, ts_ns=1001, aux=0, ret=len(blob), raw=blob)


# exec: filename record + argv chunk -> EXECUTE + CLONE, label = exe + argv
e = feed(Rec(EXEC, 100, ts_ns=1000, s="/usr/bin/curl"), argv("curl", "-s", "http://x"))
check(any(o == "EXECUTE" and s == "file" and d == "subject" and dl == "subject /usr/bin/curl curl -s http://x" for o, s, d, sl, dl, _ in e),
      "exec -> EXECUTE file->process with label 'exe argv'")
check(any(o == "CLONE" for o, *_ in e) and all(t == 1000 for *_, t in e), "exec also emits CLONE; timestamp of the exec record")
# 0.6: exec paths are absolute - relative names joined to the cwd, '..' removed, fexecve / memfd named by the image
import os as _os, tempfile as _tf
_pd = _tf.mkdtemp(); _work = _tf.mkdtemp()
_os.makedirs(f"{_pd}/321"); _os.symlink(_work, f"{_pd}/321/cwd"); _os.symlink("/", f"{_pd}/321/root")
_os.symlink("/memfd:payload (deleted)", f"{_pd}/321/exe")
n6 = EbpfNormaliser("boot", proc=_pd)
check(n6.exec_path(321, "ls") == _os.path.realpath(_work) + "/ls", f"relative exec name resolved against the cwd ({n6.exec_path(321, 'ls')})")
check(n6.exec_path(321, "/usr/bin/../../tmp/x") == "/tmp/x" and n6.exec_path(321, "//usr//bin/./id") == "/usr/bin/id",
      "'..', '.', '//' in an exec path are normalised")
check(n6.exec_path(321, "/usr/bin/python3") == "/usr/bin/python3", "absolute exec paths are kept as recorded (identities from before 0.6 stay)")
check(n6.exec_path(321, "/dev/fd/3") == "/memfd:payload (deleted)", "fexecve of a memfd is named by its image, not /dev/fd/N")
e6 = [(ev.op, ents[1].label) for r in (Rec(EXEC, 321, ts_ns=10, s="./run.sh"), Rec(EXIT, 321, ts_ns=11)) for ents, ev in n6.decode(r)]
check(any(op == "EXECUTE" and lab.startswith("subject " + _os.path.realpath(_work) + "/run.sh") for op, lab in e6),
      f"decode: the EXECUTE event carries the resolved program ({e6[:1]})")
# an exec whose argv chunk never arrives is flushed by the next record of that pid
e = feed(Rec(EXEC, 100, ts_ns=2000, s="/bin/true"), Rec(OPEN, 100, ts_ns=2001, s="/etc/hosts", flags=0, ret=3))
check([o for o, *_ in e][:2] == ["EXECUTE", "CLONE"] and "OPEN" in [o for o, *_ in e], "exec without argv chunk flushed by the next record")
# long argv split over two chunks
blob = (b"a" * 300 + b"\0" + b"b" * 400 + b"\0")
e = feed(Rec(EXEC, 100, ts_ns=3000, s="/bin/x"), Rec(EXEC_ARGV, 100, aux=0, ret=STRLEN, raw=blob[:STRLEN]),
         Rec(EXEC_ARGV, 100, aux=1, ret=len(blob) - STRLEN, raw=blob[STRLEN:]))
lab = next(dl for o, s, d, sl, dl, _ in e if o == "EXECUTE")
check(lab == "subject /bin/x " + "a" * 256 + " " + "b" * 256, "argv over two chunks, each argument truncated to 256 like strace -s 256")

# open: read-only, write, read-write, O_CREAT alone is not a write (same rule as strace/auditd)
check([o for o, *_ in feed(Rec(OPEN, 100, s="/etc/passwd", flags=0, ret=3))] == ["OPEN", "READ"], "O_RDONLY -> OPEN + READ")
check([o for o, *_ in feed(Rec(OPEN, 100, s="/tmp/o", flags=0o1 | 0o100 | 0o1000, ret=3))] == ["OPEN", "WRITE"], "O_WRONLY|O_CREAT|O_TRUNC -> OPEN + WRITE")
check([o for o, *_ in feed(Rec(OPEN, 100, s="/tmp/o", flags=0o2, ret=3))] == ["OPEN", "READ", "WRITE"], "O_RDWR -> OPEN + READ + WRITE")
check([o for o, *_ in feed(Rec(OPEN, 100, s="/tmp/o", flags=0o100, ret=3))] == ["OPEN", "READ"], "O_RDONLY|O_CREAT -> no WRITE")
e = feed(Rec(OPEN, 100, s="/a/./b/../c", flags=0, ret=3))
check(e[0][3] == "file /a/c", "absolute paths are normalised")
e = feed(Rec(OPEN, 100, s="rel.txt", flags=0, ret=3))
check(e[0][3] == "file rel.txt", "relative path without a resolvable cwd is kept as given")

# fd-relative open through a dup'ed directory fd (grep -r / fts): open dir -> fd 3, dup 3 -> 4, openat(4, "a.c")
feed(Rec(OPEN, 300, s="/srv/data", flags=0o200000, ret=3), Rec(DUP, 300, aux=3, ret=4))
e = feed(Rec(OPEN, 300, s="a.c", flags=0, dirfd=4, ret=5))
check(e[0][3] == "file /srv/data/a.c", f"open relative to a dup'ed directory fd resolves ({e[0][3]})")

# sockets: IPv4, IPv6, msg variants, inbound direction
a4 = socket.inet_aton("9.9.9.9") + b"\0" * 12
e = feed(Rec(CONNECT, 100, family=socket.AF_INET, port=443, addr=a4))
check(len(e) == 1 and e[0][0] == "CONNECT" and e[0][2] == "netflow" and e[0][4] == "netflow 9.9.9.9 443", "connect IPv4 -> CONNECT process->netflow")
a6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
e = feed(Rec(SEND, 100, family=socket.AF_INET6, port=53, addr=a6, aux=1))
check(e[0][0] == "SENDMSG" and e[0][4] == "netflow 2001:db8::1 53", "sendmsg IPv6 -> SENDMSG")
e = feed(Rec(RECV, 100, family=socket.AF_INET, port=53, addr=a4, aux=0))
check(e[0][0] == "RECVFROM" and e[0][1] == "netflow" and e[0][2] == "subject", "recvfrom -> RECVFROM socket->process")
e = feed(Rec(ACCEPT, 100, family=socket.AF_INET, port=5555, addr=a4))
check(e[0][0] == "RECVFROM" and e[0][1] == "netflow", "accept -> RECVFROM socket->process")
check(feed(Rec(CONNECT, 100, family=socket.AF_UNIX)) == [], "non-inet socket ignored")

# fork / exit: child inherits the parent's label; a reused pid after exit is a new process
e = feed(Rec(FORK, 100, aux=200))
check(len(e) == 1 and e[0][0] == "CLONE" and e[0][1] == e[0][2] == "subject", "fork -> CLONE parent->child")
u1 = n.procs.current[200].uuid
feed(Rec(EXIT, 200))
feed(Rec(OPEN, 200, s="/etc/hosts", flags=0, ret=3))
check(n.procs.current[200].uuid != u1, "exit: a reused pid gets a new process identity")

# event ids are zero-padded so that their order equals emission order
ids = [ev.event_uuid for r in (Rec(OPEN, 100, s="/x", flags=2, ret=3),) for _, ev in n.decode(r)]
check(ids == sorted(ids) and all(len(i.split(":")[1]) == 10 for i in ids), "event ids sortable in emission order")

# identical semantics to the strace collector for the same syscalls
st = StraceNormaliser("r")
sl = [(10, '1.000000 execve("/usr/bin/curl", ["curl", "-s", "http://x"], 0x1 /* 7 vars */) = 0'),
      (10, '1.000100 openat(AT_FDCWD</root>, "/etc/passwd", O_RDONLY) = 3</etc/passwd>'),
      (10, '1.000200 openat(AT_FDCWD</root>, "/tmp/o", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4</tmp/o>'),
      (10, '1.000300 connect(3<socket>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("9.9.9.9")}, 16) = 0'),
      (10, '1.000400 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND) = 11'),
      (11, '1.000500 openat(AT_FDCWD</root>, "/etc/hosts", O_RDONLY) = 5</etc/hosts>')]
s_ev = [(e.op, ents[0].label, ents[1].label) for pid, l in sl for ents, e in st.feed(pid, l)]
b = EbpfNormaliser("r", proc="/nonexistent")
recs = [Rec(EXEC, 10, s="/usr/bin/curl"), Rec(EXEC_ARGV, 10, aux=0, ret=17, raw=b"curl\0-s\0http://x\0"),
        Rec(OPEN, 10, s="/etc/passwd", flags=0, ret=3), Rec(OPEN, 10, s="/tmp/o", flags=0o1101, ret=4),
        Rec(CONNECT, 10, family=socket.AF_INET, port=443, addr=a4), Rec(OPEN, 10, s="/etc/hosts", flags=0, ret=5)]
b_ev = [(e.op, ents[0].label, ents[1].label) for r in recs for ents, e in b.decode(r)]
check(s_ev == b_ev, f"eBPF and strace produce identical (op, src label, dst label) streams ({len(b_ev)} events; thread syscalls attributed to the process)")

# kernel program text for both architectures
for arch in ("x86_64", "aarch64"):
    t = program(1234, 1024, arch)
    check("#define SYS_openat" in t and "#define REG_ARG4" in t and "__SELF_PID__" not in t and "/*__SYSCALLS__*/" not in t,
          f"kernel program generated for {arch}")

# ---- CO-RE engine: the loader's raw record stream -> Rec, identical to what the bcc engine builds ----
import os
import re
import struct

from pdp_agent.sources.ebpf import _ARCH, REC, STATS, STREAM_HEADER, STREAM_MAGIC, parse_records, sock_ip

check(REC.size == 576 and STREAM_HEADER.size == 16, "record = 576 bytes (struct event_t), stream header = 16 bytes")


def raw(kind, pid, ts=0, tid=0, aux=0, ret=0, flags=0, dirfd=0, family=0, port=0, addr=b"", s=b""):
    return REC.pack(ts, kind, pid, tid, aux, ret, flags, dirfd, family, port, addr.ljust(16, b"\0"), s.ljust(STRLEN, b"\0"))


blob = b"curl\0-s\0http://x\0"
stream = (raw(EXEC, 10, ts=5, tid=11, s=b"/usr/bin/curl") + raw(EXEC_ARGV, 10, ts=6, aux=0, ret=len(blob), s=blob)
          + raw(OPEN, 10, ret=3, flags=0o1101, dirfd=-100, s=b"/tmp/o")
          + raw(CONNECT, 10, family=socket.AF_INET, port=socket.htons(443), addr=socket.inet_aton("9.9.9.9"))
          + raw(STATS, 1, ret=7) + raw(FORK, 10, aux=12)[:100])                  # a partial record at the end
recs, used, lost = parse_records(stream, mono_to_wall=1000)
lost = lost[0] if isinstance(lost, tuple) else lost
check(used == 5 * 576 and lost == 7 and [r.kind for r in recs] == [EXEC, EXEC_ARGV, OPEN, CONNECT],
      "parse_records: complete records only, STATS consumed as the lost count, partial tail left")
check(recs[0].s == "/usr/bin/curl" and recs[0].ts_ns == 1005 and recs[0].tid == 11, "exec record: filename, monotonic->wall ts")
check(recs[1].raw == blob and recs[1].s == "curl", "argv chunk: raw keeps the NUL-separated bytes (length = ret)")
check(recs[2].dirfd == -100 and recs[2].flags == 0o1101 and recs[2].ret == 3, "open record: signed dirfd, flags, fd")
check(recs[3].port == 443 and sock_ip(recs[3].family, recs[3].addr) == "9.9.9.9", "socket record: port to host order, address")
hand = [Rec(EXEC, 10, s="/usr/bin/curl"), Rec(EXEC_ARGV, 10, aux=0, ret=len(blob), raw=blob),
        Rec(OPEN, 10, s="/tmp/o", flags=0o1101, ret=3), Rec(CONNECT, 10, family=socket.AF_INET, port=443, addr=a4)]
n1, n2 = EbpfNormaliser("r", proc="/nonexistent"), EbpfNormaliser("r", proc="/nonexistent")
e1 = [(e.op, en[0].ntype, en[1].ntype, en[0].label, en[1].label) for r in recs for en, e in n1.decode(r)]
e2 = [(e.op, en[0].ntype, en[1].ntype, en[0].label, en[1].label) for r in hand for en, e in n2.decode(r)]
check(e1 == e2 and len(e1) == 5, f"parsed CO-RE records decode to the same events as hand-built Recs ({len(e1)} events)")

# the C sources stay in sync with the Python side (record kinds, syscall numbers, header magic)
bpf_dir = os.path.join(os.path.dirname(__file__), "..", "..", "agent", "bpf")
hdr = open(os.path.join(bpf_dir, "pdp_ebpf.h")).read()
kinds = {k: int(v) for k, v in re.findall(r"#define K_(\w+)\s+(\d+)", hdr)}
check(kinds == {"EXEC_ARG": EXEC, "EXEC_ARGV": EXEC_ARGV, "OPEN": OPEN, "CONNECT": CONNECT, "SEND": SEND, "RECV": RECV,
                "ACCEPT": ACCEPT, "FORK": FORK, "EXIT": EXIT, "DUP": DUP, "STATS": STATS}, "record kinds match pdp_ebpf.h")
check(f"#define STRLEN    {STRLEN}" in hdr and '"PDPEBPF\\0"' in hdr and STREAM_MAGIC == b"PDPEBPF\0", "STRLEN and stream magic match")
src = open(os.path.join(bpf_dir, "pdp_ebpf.bpf.c")).read()
for arch, tag in (("x86_64", "__TARGET_ARCH_x86"), ("aarch64", "__TARGET_ARCH_arm64")):
    block = src.split(tag, 1)[1].split("#el", 1)[0]
    nrs = {k: (-1 if v == "NO_SYSCALL" else int(v)) for k, v in re.findall(r"#define SYS_(\w+) (\w+)", block)}
    check(nrs == _ARCH[arch][0], f"CO-RE syscall numbers for {arch} match the bcc program's")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
