"""A scripted workload touching every syscall class the eBPF collector maps, for collector checks
(tools/crosscheck.py scenario `syscalls`, and the CO-RE acceptance run in docs/DEPLOYMENT.md §1):

  exec (short and > 512-byte argv), file read / write / read-write, open through a symlink, fork (a child that
  writes and exits without exec), fd-relative opens (openat on a directory fd, on a dup()ed and an F_DUPFD_CLOEXEC
  copy of it, and fts walkers: find, grep -r), TCP connect + accept on 127.0.0.1, UDP sendto/recvfrom and
  sendmsg/recvmsg on 127.0.0.1, IPv6 loopback, connects to non-local TEST-NET addresses (RFC 5737 / RFC 3849:
  never routed, short timeout; at most a TCP SYN leaves the host, no payload).

  python -m pdp_agent.tools.syscall_workload --root DIR [--port 39100]

Ports are fixed (client sockets bind explicit ports too), so labels are reproducible across runs.
"""
from __future__ import annotations

import argparse
import fcntl
import os
import socket
import subprocess
import threading


def _connect_out(family: int, ip: str, port: int):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(0.15)
    try:
        s.connect((ip, port))
    except OSError:
        pass
    finally:
        s.close()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--port", type=int, default=39100)
    a = ap.parse_args(argv)
    root, P = os.path.abspath(a.root), a.port
    os.makedirs(f"{root}/tree/sub", exist_ok=True)

    # files: write, read, read-write, through a symlink
    with open(f"{root}/in.txt", "w") as f:
        f.write("needle\n")
    with open(f"{root}/in.txt") as f:
        f.read()
    with open(f"{root}/rw.bin", "w+b") as f:
        f.write(b"x")
    for name in ("a.txt", "b.txt", "c.txt", "sub/d.txt"):
        with open(f"{root}/tree/{name}", "w") as f:
            f.write("needle\n")
    if not os.path.islink(f"{root}/link.txt"):
        os.symlink(f"{root}/in.txt", f"{root}/link.txt")
    with open(f"{root}/link.txt") as f:          # reported as the link's target
        f.read()

    # exec: a short command, and one whose argv spans both 512-byte argv chunks
    subprocess.run(["/bin/cat", f"{root}/in.txt"], stdout=subprocess.DEVNULL, check=False)
    subprocess.run(["/bin/echo", "A" * 300, "B" * 300], stdout=subprocess.DEVNULL, check=False)
    subprocess.run(["/bin/sh", "-c", f"cd {root} && cat in.txt > copy.txt"], check=False)   # relative paths, cwd

    # fork without exec: the child writes a file and exits
    pid = os.fork()
    if pid == 0:
        try:
            with open(f"{root}/child.txt", "w") as f:
                f.write("child\n")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)

    # fd-relative opens: openat(dirfd), through dup() and fcntl(F_DUPFD_CLOEXEC) copies of the directory fd
    dfd = os.open(f"{root}/tree", os.O_RDONLY | os.O_DIRECTORY)
    os.close(os.open("a.txt", os.O_RDONLY, dir_fd=dfd))
    d2 = os.dup(dfd)
    os.close(os.open("b.txt", os.O_RDONLY, dir_fd=d2))
    d3 = fcntl.fcntl(dfd, fcntl.F_DUPFD_CLOEXEC, 50)
    os.close(os.open("sub/d.txt", os.O_WRONLY | os.O_APPEND, dir_fd=d3))
    for fd in (dfd, d2, d3):
        os.close(fd)
    subprocess.run(["find", f"{root}/tree", "-name", "*.txt", "-newer", f"{root}/in.txt"], stdout=subprocess.DEVNULL, check=False)
    subprocess.run(["grep", "-r", "needle", f"{root}/tree"], stdout=subprocess.DEVNULL, check=False)

    # TCP on loopback: connect (fixed client port) + accept
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", P)); srv.listen(1)
    acc = threading.Thread(target=lambda: srv.accept()[0].close())
    acc.start()
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    c.bind(("127.0.0.1", P + 1)); c.connect(("127.0.0.1", P)); c.sendall(b"hi"); c.close()
    acc.join(); srv.close()

    # UDP on loopback: sendto / recvfrom, sendmsg / recvmsg
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); rx.bind(("127.0.0.1", P + 2))
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); tx.bind(("127.0.0.1", P + 3))
    tx.sendto(b"1", ("127.0.0.1", P + 2)); rx.recvfrom(16)
    tx.sendmsg([b"2"], [], 0, ("127.0.0.1", P + 2)); rx.recvmsg(16)
    tx.close(); rx.close()

    # IPv6 loopback (connect to a closed port: the attempt is the edge)
    if socket.has_ipv6:
        _connect_out(socket.AF_INET6, "::1", P + 4)

    # non-local destinations: TEST-NET-3 and the IPv6 documentation prefix (unroutable; the connect attempt is the edge)
    _connect_out(socket.AF_INET, "203.0.113.7", 4444)
    _connect_out(socket.AF_INET6, "2001:db8::7", 443)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.connect(("198.51.100.9", 53)); u.close()          # UDP connect: an edge, no packet sent


if __name__ == "__main__":
    main()
