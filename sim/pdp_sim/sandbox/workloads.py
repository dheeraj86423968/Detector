"""Sandbox actors: real programs whose system calls are captured live by the strace collector.

Each scenario performs genuine syscalls (fork/exec, file open/read/write, socket connect) in a throwaway
working directory, so the provenance graph the collector records is real kernel telemetry, not a replay or a
synthetic graph. Nothing here is malicious: the "attack" scenarios reproduce the *provenance shape* of DARPA
TC behaviours (drop-and-execute, backdoor shell, staged exfiltration, living-off-the-land recon) using
harmless commands, a private scratch directory, and connections to TEST-NET addresses (RFC 5737, never
routed) with a short timeout, so no data leaves the host.

Run one scenario:  python -m pdp_sim.sandbox.workloads <scenario> [--root DIR] [--scale N]
"""
from __future__ import annotations

import os
import random
import socket
import subprocess
import sys
import time

EXTERNAL = ["203.0.113.7", "203.0.113.42", "198.51.100.9"]   # RFC 5737 TEST-NET, unroutable


def _connect(ip: str, port: int, timeout: float = 0.15):
    """A real connect() syscall to an unroutable address (captured by the collector; no egress)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
    except OSError:
        pass
    finally:
        s.close()


def _run(cmd: list[str], cwd: str):
    """fork+exec a real child (its own strace file) and wait."""
    try:
        subprocess.run(cmd, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def _write(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


# ----------------------------------------------------------------------------- benign baseline workloads
def benign_build(root: str, scale: int, rng: random.Random):
    """A build: read many source files with real tools, write artefacts."""
    src = os.path.join(root, "src"); os.makedirs(src, exist_ok=True)
    for i in range(scale * 4):
        _write(os.path.join(src, f"m{i}.c"), b"int f%d(){return %d;}\n" % (i, i) * 8)
    for i in range(scale * 4):
        _run(["cat", os.path.join(src, f"m{i}.c")], root)
        _run(["cp", os.path.join(src, f"m{i}.c"), os.path.join(src, f"m{i}.o")], root)
    _run(["ls", "-l", src], root)
    _run(["grep", "-r", "return", src], root)


def benign_web(root: str, scale: int, rng: random.Random):
    """A web server: accept-like loop reading content files and talking to known upstreams."""
    www = os.path.join(root, "www"); os.makedirs(www, exist_ok=True)
    for i in range(scale * 3):
        _write(os.path.join(www, f"page{i}.html"), b"<html>ok</html>")
    for _ in range(scale * 5):
        _read(os.path.join(www, f"page{rng.randrange(scale * 3)}.html"))
        _connect("127.0.0.1", 9)
    _run(["cat", "/etc/hostname"], root)


def benign_admin(root: str, scale: int, rng: random.Random):
    """Routine admin: package/metadata reads and log appends (apt/dpkg/cron shape)."""
    for p in ("/etc/passwd", "/etc/hostname", "/etc/hosts", "/proc/version"):
        _read(p)
    logs = os.path.join(root, "log"); os.makedirs(logs, exist_ok=True)
    for i in range(scale * 3):
        _write(os.path.join(logs, "app.log"), b"line %d\n" % i)
        _run(["cat", os.path.join(logs, "app.log")], root)
    _run(["date"], root)


def benign_user(root: str, scale: int, rng: random.Random):
    """Interactive user: edit documents, list directories."""
    docs = os.path.join(root, "docs"); os.makedirs(docs, exist_ok=True)
    for i in range(scale * 3):
        _write(os.path.join(docs, f"note{i}.txt"), b"hello %d" % i)
        _read(os.path.join(docs, f"note{i}.txt"))
    _run(["ls", docs], root)


BENIGN = {"build": benign_build, "web": benign_web, "admin": benign_admin, "user": benign_user}


# ----------------------------------------------------------------------------- attack-shaped scenarios (harmless)
def attack_dropper(root: str, scale: int, rng: random.Random):
    """Drop-and-execute: a process writes a NEW executable into a world-writable dir and runs it; the dropped
    program connects to an external address. (DARPA 'malicious file write then execute'.)"""
    drop = os.path.join(root, "tmp"); os.makedirs(drop, exist_ok=True)
    payload = os.path.join(drop, "update.sh")
    _write(payload, b"#!/bin/sh\ncat /etc/passwd >/dev/null\n")
    os.chmod(payload, 0o755)
    _run(["/bin/sh", payload], root)                       # execute the dropped file
    _connect(rng.choice(EXTERNAL), 4444)                   # dropped code calls home


def attack_backdoor(root: str, scale: int, rng: random.Random):
    """Server-spawned shell: a long-running service process execs a shell that reads sensitive files and opens a
    new outbound channel (DARPA Nginx/Firefox backdoor shape)."""
    _read(os.path.join(root, "www", "page0.html"))         # the service's normal activity
    _run(["/bin/sh", "-c", "cat /etc/passwd /etc/shadow 2>/dev/null >/dev/null; id"], root)  # spawned shell, recon
    _connect(rng.choice(EXTERNAL), 8080)


def attack_exfil(root: str, scale: int, rng: random.Random):
    """Staged exfiltration: collect many user files into one archive, then send it out."""
    docs = os.path.join(root, "docs"); os.makedirs(docs, exist_ok=True)
    for i in range(scale * 3):
        _write(os.path.join(docs, f"secret{i}.txt"), os.urandom(64))
    archive = os.path.join(root, "tmp", "arch.tar"); os.makedirs(os.path.dirname(archive), exist_ok=True)
    _run(["tar", "cf", archive, docs], root)               # stage
    _read(archive)
    _connect(rng.choice(EXTERNAL), 443)                    # send


def attack_lotl(root: str, scale: int, rng: random.Random):
    """Living-off-the-land recon: trusted system tools used for discovery then a network beacon."""
    for cmd in (["whoami"], ["id"], ["uname", "-a"], ["cat", "/etc/os-release"], ["ls", "/root"]):
        _run(cmd, root)
    _connect(rng.choice(EXTERNAL), 53)


ATTACKS = {"dropper": attack_dropper, "backdoor": attack_backdoor, "exfil": attack_exfil, "lotl": attack_lotl}
ALL = {**BENIGN, **ATTACKS}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=list(ALL))
    ap.add_argument("--root", default=None)
    ap.add_argument("--scale", type=int, default=3)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    root = a.root or os.path.join("/tmp", f"pdp-wl-{os.getpid()}")
    os.makedirs(root, exist_ok=True)
    ALL[a.scenario](root, a.scale, random.Random(a.seed))


if __name__ == "__main__":
    main()
