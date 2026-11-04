"""Unit tests for the strace live collector's parser (no strace/ptrace needed).
Run: PYTHONPATH=engine:agent python tests/unit/test_strace.py
"""
import sys

from pdp_agent.sources.strace_src import StraceNormaliser, _argv, _resolve_path, _sockaddr

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


# argv / path / sockaddr helpers
check(_argv('"/usr/bin/cp", ["cp", "/a", "/b"], 0x64') == ["cp", "/a", "/b"], "argv parsed from execve")
check(_resolve_path('AT_FDCWD</home/u>, "rel.txt", O_RDONLY') == "/home/u/rel.txt", "relative path resolved against cwd")
check(_sockaddr('3<socket>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16') == ("1.2.3.4", "443"), "AF_INET sockaddr parsed")
check(_sockaddr('{sa_family=AF_UNIX, sun_path="/run/x"}, 110') is None, "AF_UNIX ignored")

# full event stream, including an unfinished/resumed blocking syscall
n = StraceNormaliser("run")
lines = [
    (10, '1000.000000 execve("/bin/sh", ["sh", "-c", "x"], 0x1 /* 7 vars */) = 0'),
    (10, '1000.001000 openat(AT_FDCWD</root>, "/etc/passwd", O_RDONLY) = 3</etc/passwd>'),
    (10, '1000.002000 openat(AT_FDCWD</root>, "out", O_WRONLY|O_CREAT, 0644) = 4</root/out>'),
    (10, '1000.003000 clone(child_stack=NULL, flags=SIGCHLD) = 11'),
    (11, '1000.004000 execve("/usr/bin/curl", ["curl", "x"], 0x1 /* 7 vars */) = 0'),
    (11, '1000.005000 connect(3<socket>, <unfinished ...>'),
    (11, '1000.006000 <... connect resumed>{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("9.9.9.9")}, 16) = 0'),
]
ops = []
for pid, ln in lines:
    for ents, ev in n.feed(pid, ln):
        ops.append((ev.op, ents[0].ntype, ents[1].ntype))

opset = [o for o, _, _ in ops]
check("EXECUTE" in opset and "CLONE" in opset, "execve yields EXECUTE and CLONE")
check(opset.count("OPEN") == 2 and "READ" in opset and "WRITE" in opset, "read-only and write opens give READ / WRITE")
check("CONNECT" in opset, "unfinished/resumed connect is stitched and yields CONNECT")
# data-flow direction: READ is file->subject, WRITE is subject->file, CONNECT is subject->netflow
read = next(o for o in ops if o[0] == "READ"); write = next(o for o in ops if o[0] == "WRITE"); conn = next(o for o in ops if o[0] == "CONNECT")
check(read[1] == "file" and read[2] == "subject", "READ flows file -> process")
check(write[1] == "subject" and write[2] == "file", "WRITE flows process -> file")
check(conn[1] == "subject" and conn[2] == "netflow", "CONNECT flows process -> socket")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
