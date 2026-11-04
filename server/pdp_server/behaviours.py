"""Attack behaviours recognised in an incident's provenance graph, used for its title and summary.

Detection itself is done by the agent's layers; this module only *names* what an already-alerted incident shows, so
an analyst reads "Ransomware: kworker-x rewrote 74 files as *.locked" instead of a generic data-flow rule. Every
behaviour is derived from graph structure (who started whom, who wrote/read/executed which file, who connected
where), file paths and command lines - never from a test's scenario labels - so it applies unchanged to client data.

The patterns are deliberately specific (a shell started by a process *after* it connected out, files rewritten
under a new extension, a system-process name running from outside the system directories ...). A pattern that is
not clearly present is not reported; the incident then keeps the title of its strongest detection.
"""
from __future__ import annotations

import ipaddress
import os
import re

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "fish", "tcsh", "csh"}
WEB_SERVERS = re.compile(r"^(nginx|apache2?|httpd|lighttpd|caddy|php-fpm[\d.]*|php[\d.]*|php-cgi|tomcat\d*|catalina|"
                         r"gunicorn|uwsgi|node|w3wp|jetty|traefik)$")
WEB_DIR = re.compile(r"/(www|htdocs|public_html|wwwroot|webapps|html)/")
WEB_SCRIPT = re.compile(r"\.(php\d?|phtml|jsp|jspx|asp|aspx|ashx|cgi)$", re.I)
SYSTEM_EXE = re.compile(r"^/(usr/)?(s?bin|lib|lib32|lib64|libexec)/|^/usr/(local/)?(s?bin|lib|libexec|share)/|^/snap/|^/opt/")
STAGING = re.compile(r"/(tmp|var/tmp|dev/shm|\.cache|\.local/bin|\.X11-unix|\.ICE-unix)/|/\.[^/]+$")
MASQUERADE = re.compile(r"^(kworker|kthreadd|kswapd|ksoftirqd|kdevtmpfs|migration|rcu_|watchdogd?|systemd|dbus|snapd|"
                        r"cron|crond|anacron|udevadm|udevd|polkit|sshd|rsyslogd?|init$|agetty|irqbalance|networkd|"
                        r"containerd|journald|auditd)", re.I)
MINER_NAMES = re.compile(r"^(xmrig.*|xmr-stak.*|kdevtmpfsi|kinsing|minerd|cpuminer.*|ccminer|nbminer|t-rex|lolminer|"
                         r"phoenixminer|kswapd0|ethminer|bminer|srbminer.*)$", re.I)
MINER_PORTS = {3333, 5555, 7777, 14433, 14444, 45560, 45700, 3357, 9999}
MINER_CMD = re.compile(r"stratum\+(tcp|ssl)://|--donate-level|--cpu-max-threads|-o\s+pool\.|cryptonight|randomx", re.I)
ADMIN_PORTS = {22: "SSH", 23: "Telnet", 135: "RPC", 139: "SMB", 445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 5900: "VNC"}
ADMIN_CLIENTS = {"ssh", "scp", "sftp", "rsync", "ansible", "ansible-playbook", "mosh-client", "git"}
CREDENTIALS = re.compile(r"^/etc/(shadow|gshadow)$|/\.ssh/id_[^/.]+$|/\.ssh/id_[^/]+(?<!\.pub)$|/\.aws/credentials$|"
                         r"/\.git-credentials$|/\.netrc$|/\.docker/config\.json$|/\.kube/config$|/Login Data$|"
                         r"/etc/ssl/private/|/\.gnupg/private-keys|/\.password-store/|/keyrings?/")
AUTH_PROGRAMS = re.compile(r"^(sshd|sudo|su|login|passwd|unix_chkpwd|chage|chpasswd|useradd|usermod|newgrp|polkitd|"
                           r"systemd.*|cron|crond|gdm.*|lightdm|sssd.*|nscd|ssh|ssh-agent|ssh-add|git.*|docker.*|"
                           r"kubectl|gpg.*|pass|vipw|pwck|grpck|dbus.*)$")
KEY_HUNT = re.compile(r"-name\s+['\"]?(id_|\*\.pem|\*\.key|\*credential|\*password)|grep\s+-[a-zA-Z]*r[a-zA-Z]*\s+['\"]?(password|passwd|secret|BEGIN .*PRIVATE)", re.I)
ARCHIVERS = {"tar", "zip", "7z", "7za", "7zr", "rar", "gzip", "bzip2", "xz", "zstd", "pigz"}
ARCHIVE_FILE = re.compile(r"\.(tar|tgz|zip|7z|rar|gz|bz2|xz|zst)$")
RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"}
DNS_ENCODE = re.compile(r"b32encode|b64encode|base32|base64|xxd\s+-p|\bdnscat|\biodine|\bdns2tcp", re.I)
RESOLVER_PROGRAMS = re.compile(r"^(systemd-resolve.*|dnsmasq|named|unbound|nscd|resolved|pdns.*|coredns|bind9?)$")
PERSISTENCE = [
    (re.compile(r"/\.ssh/authorized_keys2?$"), "SSH key added", "an SSH key was added to {path}"),
    (re.compile(r"/cron\.(d|daily|hourly|weekly|monthly)/[^/]+$|/crontabs?(/[^/]+)?$|/var/spool/cron/"), "Cron job installed",
     "a scheduled job was written to {path}"),
    (re.compile(r"/systemd/(system|user)/[^/]+\.(service|timer|socket)$|/etc/init\.d/[^/]+$"), "Service installed",
     "a service definition was written to {path}"),
    (re.compile(r"/(\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile)$|/etc/profile\.d/|/etc/rc\.local$|/etc/bash\.bashrc$"),
     "Login script modified", "a login script was modified ({path})"),
    (re.compile(r"^/etc/ld\.so\.preload$"), "Library preload installed", "{path} was written (every program loads it)"),
]
LOG_WIPE = re.compile(r"(:\s*>|>\s*|truncate\s+(-s\s*0\s+)?|shred\s+(-\w+\s+)*|rm\s+(-\w+\s+)*)['\"]?([^\s;&|'\"]*/var/log/[^\s;&|'\"]+)|"
                      r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null")
SUID_HUNT = re.compile(r"-perm\s+[-/]?(4000|2000|6000|u=s|g=s)|\bsudo\s+-l\b|getcap\s+-r|linpeas|linenum|linux-exploit-suggester|pspy")
RECON = [
    ("whoami", re.compile(r"(^|[\s;&|/])whoami\b")), ("id", re.compile(r"(^|[\s;&|/])id(\s|$|;)")),
    ("uname", re.compile(r"(^|[\s;&|/])uname\b")), ("hostname", re.compile(r"(^|[\s;&|/])hostname(\s|$|;)")),
    ("ps", re.compile(r"(^|[\s;&|/])ps\s+-?[aefux]")), ("w", re.compile(r"(^|[\s;&|/])w(\s|$|;)")),
    ("who", re.compile(r"(^|[\s;&|/])who(\s|$|;)")), ("last", re.compile(r"(^|[\s;&|/])last(\s|$|;)")),
    ("netstat", re.compile(r"\bnetstat\b")), ("ss", re.compile(r"(^|[\s;&|/])ss\s+-")),
    ("ip addr", re.compile(r"(^|[\s;&|/])ip\s+(a|addr|route|r)\b")), ("ifconfig", re.compile(r"\bifconfig\b")),
    ("arp", re.compile(r"(^|[\s;&|/])arp\s")), ("env", re.compile(r"(^|[\s;&|/])(env|printenv)(\s|$|;)")),
    ("/etc/passwd", re.compile(r"cat\s+/etc/passwd")), ("/etc/issue", re.compile(r"cat\s+/etc/(issue|os-release|lsb-release)")),
    ("/etc/hosts", re.compile(r"cat\s+/etc/hosts")), ("/proc/version", re.compile(r"cat\s+/proc/(version|cpuinfo|meminfo)")),
    ("/proc/net", re.compile(r"cat\s+/proc/net/")), ("ls /home", re.compile(r"ls\s+(-\w+\s+)*/(home|root)?\s*($|;|>)")),
    ("lsb_release", re.compile(r"\blsb_release\b")),
]

# Ordered most to least important: the first one found is the incident's title.
KINDS = {
    "ransomware":      ("Ransomware", "Impact"),
    "web_shell":       ("Web shell", "Initial access"),
    "remote_shell":    ("Remote shell", "Command and control"),
    "cryptominer":     ("Cryptominer", "Impact"),
    "credential":      ("Credential access", "Credential access"),
    "dns_tunnel":      ("DNS tunnelling", "Exfiltration"),
    "staged_exfil":    ("Data staged and sent", "Exfiltration"),
    "dropped_exec":    ("Dropped program run", "Execution"),
    "persistence":     ("Persistence", "Persistence"),
    "lateral":         ("Lateral movement", "Lateral movement"),
    "masquerade":      ("Masquerading", "Defense evasion"),
    "log_wipe":        ("Traces removed", "Defense evasion"),
    "tool_download":   ("Tool download", "Command and control"),
    "privesc_recon":   ("Privilege-escalation recon", "Discovery"),
    "discovery":       ("Discovery", "Discovery"),
}
SERIOUS = {"ransomware", "web_shell", "remote_shell", "cryptominer", "credential", "dns_tunnel", "staged_exfil", "dropped_exec"}


# ---------------------------------------------------------------------------------------------- graph view
class _G:
    def __init__(self, alerts: list[dict]):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        seen = set()
        for a in alerts:
            ctx = a.get("context") or {}
            for n in ctx.get("nodes", []):
                self.nodes.setdefault(n["uuid"], n)
            for e in ctx.get("edges", []):
                k = (e["src"], e["dst"], e["op"], e.get("ts_ns"))
                if k not in seen:
                    seen.add(k); self.edges.append(e)
            self.nodes.setdefault(a["node_uuid"], {"uuid": a["node_uuid"], "ntype": a["ntype"], "label": a["label"]})
            if a.get("display"):
                self.nodes[a["node_uuid"]] = dict(self.nodes[a["node_uuid"]], display=a["display"])
        self.out: dict[str, list[dict]] = {}
        self.inn: dict[str, list[dict]] = {}
        for e in self.edges:
            self.out.setdefault(e["src"], []).append(e); self.inn.setdefault(e["dst"], []).append(e)
        self.procs = [u for u, n in self.nodes.items() if self.kind(u) == "subject"]

    def kind(self, u: str) -> str:
        n = self.nodes.get(u) or {}
        t = n.get("ntype")
        if t:
            return t
        first = (n.get("label") or "").split(" ", 1)[0]
        if first in ("subject", "file", "netflow"):
            return first
        return "file" if u.startswith("file:") else "subject" if u.startswith("proc:") else "netflow" if u.startswith("net") else "?"

    def _body(self, u: str) -> str:
        lab = (self.nodes.get(u) or {}).get("label") or ""
        return lab.split(" ", 1)[1] if " " in lab else ""

    def exe(self, u: str) -> str | None:
        d = (self.nodes.get(u) or {}).get("display") or {}
        if d.get("exe_path") not in (None, "", "None", "null"):
            return d["exe_path"]
        p = self._body(u).split(" ", 1)[0]
        return p if p and p not in ("None", "null") else None

    def cmd(self, u: str) -> str:
        d = (self.nodes.get(u) or {}).get("display") or {}
        if d.get("argv") not in (None, "", "None", "null"):
            return d["argv"]
        parts = self._body(u).split(" ", 1)
        return parts[1] if len(parts) > 1 and parts[1] not in ("None", "null") else ""

    def name(self, u: str) -> str:
        e = self.exe(u)
        if e:
            return os.path.basename(e)
        c = self.cmd(u)
        return os.path.basename(c.split(" ", 1)[0]) if c else "a process"

    def path(self, u: str) -> str | None:
        p = self._body(u)
        return p if p and p not in ("None", "null") else None

    def addr(self, u: str) -> tuple[str, int | None]:
        p = self._body(u).split()
        if not p:
            return "", None
        try:
            return p[0], int(p[1]) if len(p) > 1 else None
        except ValueError:
            return p[0], None

    def files(self, proc: str, op: str) -> list[str]:
        if op == "WRITE":
            return [e["dst"] for e in self.out.get(proc, []) if e["op"] == "WRITE" and self.kind(e["dst"]) == "file"]
        return [e["src"] for e in self.inn.get(proc, []) if e["op"] in ("READ",) and self.kind(e["src"]) == "file"]

    def net(self, proc: str, ops=("CONNECT", "SENDTO", "SENDMSG")) -> list[tuple[str, int]]:
        """(peer node, first ts) for outgoing network activity to an external address."""
        out = []
        for e in self.out.get(proc, []):
            if e["op"] in ops and self.kind(e["dst"]) == "netflow" and external(self.addr(e["dst"])[0]):
                out.append((e["dst"], int(e.get("ts_ns") or 0)))
        return out

    def children(self, proc: str) -> list[tuple[str, int]]:
        return [(e["dst"], int(e.get("ts_ns") or 0)) for e in self.out.get(proc, []) if e["op"] == "CLONE"]

    def family(self, proc: str) -> list[str]:
        """The process and its fork copies (children running the same program before they exec something else)."""
        out, todo = [proc], [proc]
        while todo and len(out) < 50:
            q = todo.pop()
            for c, _ in self.children(q):
                if c not in out and self.exe(c) == self.exe(proc) and self.exe(proc):
                    out.append(c); todo.append(c)
        return out


def external(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # documentation ranges (RFC 5737/3849) count as external: they are what test traffic and examples use
    return not (a.is_private and not _doc(a)) and not a.is_loopback and not a.is_link_local and not a.is_unspecified and not a.is_multicast


def _doc(a) -> bool:
    return any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def _short(p: str, n: int = 48) -> str:
    return p if len(p) <= n else "..." + p[-(n - 3):]


def _dir(p: str) -> str:
    d = os.path.dirname(p) or "/"
    parts = d.strip("/").split("/")
    if len(d) <= 32 or len(parts) <= 1:
        return _short(d, 40)
    tail = "/".join(parts[-2:])
    return ".../" + (tail if len(tail) <= 30 else _short(parts[-1], 30))


def _hp(g: _G, u: str) -> str:
    ip, port = g.addr(u)
    return f"{ip}:{port}" if port is not None else ip


# ---------------------------------------------------------------------------------------------- behaviours
def _ransomware(g: _G):
    for p in g.procs:
        reads = {g.path(f) for f in g.files(p, "READ")} - {None}
        writes = [g.path(f) for f in g.files(p, "WRITE")]
        writes = [w for w in writes if w]
        if len(writes) < 10:
            continue
        exts, n = {}, 0
        for w in set(writes):
            base, ext = os.path.splitext(w)
            if base in reads and ext and not ARCHIVE_FILE.search(w):
                n += 1; exts[ext] = exts.get(ext, 0) + 1
        if n >= 10:
            ext = max(exts, key=exts.get)
            note = next((w for w in writes if re.search(r"(readme|restore|decrypt|recover|how_to|ransom)[^/]*\.(txt|html?)$", w, re.I)), None)
            yield {"kind": "ransomware", "actor": p,
                   "title": f"Ransomware: {g.name(p)} rewrote {n} files as *{ext}",
                   "text": f"{g.name(p)} read {n} files and wrote each back under the new extension {ext}"
                           + (f", then left the note {os.path.basename(note)}" if note else "")}


def _web_shell(g: _G):
    for p in g.procs:
        if WEB_SERVERS.match(g.name(p)):
            kids = [c for c, _ in g.children(p) if g.name(c) in SHELLS]
            if kids:
                yield {"kind": "web_shell", "actor": p, "title": f"Web shell: web server {g.name(p)} ran shell commands",
                       "text": f"{g.name(p)} started {g.name(kids[0])}: {_short(g.cmd(kids[0]), 80)}"}
                return
    for p in g.procs:
        for f in g.files(p, "WRITE"):
            path = g.path(f) or ""
            if WEB_SCRIPT.search(path) and WEB_DIR.search(path):
                yield {"kind": "web_shell", "actor": p, "title": f"Web shell: {os.path.basename(path)} planted in a web directory",
                       "text": f"{g.name(p)} wrote the server-side script {_short(path, 80)}"}
                return
    for p in g.procs:
        c = g.cmd(p)
        m = re.search(r">\s*(\S*" + WEB_DIR.pattern + r"\S*)", c)
        if g.name(p) in SHELLS and m:
            yield {"kind": "web_shell", "actor": p, "title": "Web shell: command output written to a web directory",
                   "text": f"a shell ran '{_short(c.split('>', 1)[0].strip(), 70)}' and wrote the output to {_short(m.group(1), 60)}"}
            return


def _remote_shell(g: _G):
    for p in g.procs:
        fam = g.family(p)
        conns = [x for q in fam for x in g.net(q)]
        if not conns:
            continue
        first = min(t for _, t in conns)
        for c, t in ((c, t) for q in fam for c, t in g.children(q)):
            if g.name(c) in SHELLS and (t == 0 or first == 0 or t >= first):
                peer = min(conns, key=lambda x: x[1])[0]
                yield {"kind": "remote_shell", "actor": p,
                       "title": f"Remote shell: {g.name(p)} connected to {_hp(g, peer)} and ran shell commands",
                       "text": f"{g.name(p)} connected to {_hp(g, peer)}, then started {g.name(c)}"
                               + (f": {_short(g.cmd(c), 80)}" if g.cmd(c) else "")}
                return
    for p in g.procs:      # a shell that itself talks to the network (bash -i >& /dev/tcp/...)
        if g.name(p) in SHELLS and g.net(p) and re.search(r"/dev/(tcp|udp)/|\s-i(\s|$)|\b(nc|ncat|socat|telnet)\b", g.cmd(p)):
            peer = g.net(p)[0][0]
            yield {"kind": "remote_shell", "actor": p, "title": f"Remote shell: {g.name(p)} connected to {_hp(g, peer)}",
                   "text": f"the shell {g.name(p)} opened a connection to {_hp(g, peer)}"}
            return


def _cryptominer(g: _G):
    for p in g.procs:
        name, cmd = g.name(p), g.cmd(p)
        pool = next((u for u, _ in g.net(p, ("CONNECT",)) if g.addr(u)[1] in MINER_PORTS), None)
        named = bool(MINER_NAMES.match(name)) or bool(MINER_CMD.search(cmd))
        if pool and named:
            yield {"kind": "cryptominer", "actor": p, "title": f"Cryptominer: {name} connected to mining-pool port {_hp(g, pool)}",
                   "text": f"{name} carries a known miner name and connected to {_hp(g, pool)} (a common mining-pool port)"}
            return
        if named:
            yield {"kind": "cryptominer", "actor": p, "title": f"Cryptominer: {name} ran",
                   "text": f"{name} carries the name or options of a known cryptocurrency miner"}
            return


def _credential(g: _G):
    for p in g.procs:
        if AUTH_PROGRAMS.match(g.name(p)):
            continue
        hits = sorted({g.path(f) for f in g.files(p, "READ") if CREDENTIALS.search(g.path(f) or "")})
        if hits:
            more = f" and {len(hits) - 1} more" if len(hits) > 1 else ""
            yield {"kind": "credential", "actor": p, "title": f"Credential access: {g.name(p)} read {_short(hits[0], 40)}{more}",
                   "text": f"{g.name(p)} read " + ", ".join(_short(h, 60) for h in hits[:4]) + ("..." if len(hits) > 4 else "")}
            return
    for p in g.procs:
        if KEY_HUNT.search(g.cmd(p)):
            yield {"kind": "credential", "actor": p, "title": f"Credential access: {g.name(p)} searched for private keys",
                   "text": f"{g.name(p)} ran '{_short(g.cmd(p), 90)}'"}
            return


def _dns_tunnel(g: _G):
    for p in g.procs:
        if RESOLVER_PROGRAMS.match(g.name(p)):
            continue
        e = g.exe(p) or ""
        # ordinary programs resolve names by sending to the configured DNS server; a tunnel is a program that does
        # this itself from outside the system directories, or an interpreter/tool told to encode data into queries
        if (not e or SYSTEM_EXE.search(e)) and not DNS_ENCODE.search(g.cmd(p)):
            continue
        for u, _ in g.net(p, ("SENDTO", "SENDMSG")):
            ip, port = g.addr(u)
            if port == 53 and ip not in RESOLVERS:
                yield {"kind": "dns_tunnel", "actor": p, "title": f"DNS tunnelling: {g.name(p)} sent data to {ip}:53",
                       "text": f"{g.name(p)} sent DNS-port datagrams straight to {ip} instead of using the system resolver"}
                return


def _staged_exfil(g: _G):
    archives = {}
    for p in g.procs:
        if g.name(p) in ARCHIVERS:
            for f in g.files(p, "WRITE"):
                if ARCHIVE_FILE.search(g.path(f) or ""):
                    archives[f] = p
    by_path = {g.path(f): f for f in archives}
    for p in g.procs:
        conns = g.net(p)
        if not conns:
            continue
        for f in g.files(p, "READ"):
            path = g.path(f) or ""
            if f in archives or path in by_path or (ARCHIVE_FILE.search(path) and any(path.startswith((g.path(a) or "\0")) for a in archives)):
                yield {"kind": "staged_exfil", "actor": p,
                       "title": f"Data staged and sent: {os.path.basename(path)} sent to {_hp(g, conns[0][0])}",
                       "text": f"files were packed into {_short(path, 60)}, which {g.name(p)} read and sent to {_hp(g, conns[0][0])}"}
                return
    for f, p in archives.items():
        if STAGING.search(g.path(f) or ""):
            yield {"kind": "staged_exfil", "actor": p, "title": f"Data staged: {g.name(p)} packed files into {os.path.basename(g.path(f))}",
                   "text": f"{g.name(p)} wrote the archive {_short(g.path(f), 70)} to a temporary or hidden location"}
            return


def _dropped(g: _G):
    written = {}
    for p in g.procs:
        for f in g.files(p, "WRITE"):
            if g.path(f):
                written.setdefault(g.path(f), p)
    for p in g.procs:
        e = g.exe(p)
        if e and e in written and not SYSTEM_EXE.search(e):
            w = written[e]
            yield {"kind": "dropped_exec", "actor": p, "title": f"Dropped program run: {os.path.basename(e)} from {_dir(e)}",
                   "text": f"{g.name(w)} wrote {_short(e, 70)}, which was then run"}
            return
    for p in g.procs:
        m = re.search(r"chmod\s+(\+x|[0-7]?[157][0-7]{2})\s+(\S+)", g.cmd(p))
        if m and STAGING.search(m.group(2)):
            ran = next((q for q in g.procs if g.exe(q) == m.group(2)), None)
            if ran:
                yield {"kind": "dropped_exec", "actor": ran, "title": f"Dropped program run: {os.path.basename(m.group(2))} from {_dir(m.group(2))}",
                       "text": f"{_short(m.group(2), 70)} was made executable and run"}
                return


def _persistence(g: _G):
    seen = set()
    for p in g.procs:
        cands = [(g.path(f) or "", f"{g.name(p)} wrote") for f in g.files(p, "WRITE")]
        cands += [(t, f"{g.name(p)} ran '{_short(g.cmd(p), 60)}' on") for t in _write_targets(g.cmd(p))]
        for path, how in cands:
            for rx, label, text in PERSISTENCE:
                if rx.search(path) and label not in seen:
                    seen.add(label)
                    yield {"kind": "persistence", "actor": p, "title": f"Persistence: {label} ({os.path.basename(path)})",
                           "text": text.format(path=_short(path, 70)) + f" - {how} it", "label": label}
        if g.name(p) == "crontab" and re.search(r"crontab\s+(-\s*$|[^-\s])", g.cmd(p)) and "Cron job installed" not in seen:
            seen.add("Cron job installed")
            yield {"kind": "persistence", "actor": p, "title": "Persistence: cron job installed",
                   "text": f"crontab was run as '{_short(g.cmd(p), 60)}'", "label": "Cron job installed"}


def _write_targets(cmd: str) -> list[str]:
    """Paths a command line writes to: redirections, tee, and the destination of cp/mv/install/ln/chmod/chown."""
    out = re.findall(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*(/[^\s;&|'\"]+)", cmd)
    for part in re.split(r"[;&|]+", cmd):
        m = re.match(r"\s*(?:\S*/)?(cp|mv|install|ln|chmod|chown)\s+.*\s(/[^\s'\"]+)\s*$", part)
        if m:
            out.append(m.group(2))
    return out


def _lateral(g: _G):
    for p in g.procs:
        hosts: dict[str, set] = {}
        for e in g.out.get(p, []):          # internal hosts count: that is where lateral movement goes
            if e["op"] != "CONNECT" or g.kind(e["dst"]) != "netflow":
                continue
            ip, port = g.addr(e["dst"])
            if port in ADMIN_PORTS and not ip.startswith(("127.", "::1", "0.")):
                hosts.setdefault(ip, set()).add(ADMIN_PORTS[port])
        if not hosts or (len(hosts) < 2 and g.name(p) in ADMIN_CLIENTS):
            continue
        svcs = sorted({s for v in hosts.values() for s in v})
        n = len(hosts)
        yield {"kind": "lateral", "actor": p,
               "title": f"Lateral movement: {g.name(p)} contacted {n} host{'s' if n > 1 else ''} on {', '.join(svcs)}",
               "text": f"{g.name(p)} connected to remote-access services ({', '.join(svcs)}) on " + ", ".join(sorted(hosts)[:5]) + ("..." if n > 5 else "")}
        return


def _masquerade(g: _G):
    for p in g.procs:
        e = g.exe(p)
        if e and MASQUERADE.match(os.path.basename(e)) and not SYSTEM_EXE.search(e):
            yield {"kind": "masquerade", "actor": p, "title": f"Masquerading: '{os.path.basename(e)}' ran from {_dir(e)}",
                   "text": f"a program named like a system process ({os.path.basename(e)}) ran from {_short(e, 70)}, outside the system directories"}
            return


def _log_wipe(g: _G):
    exes = {g.exe(p) for p in g.procs} - {None}
    for p in g.procs:
        c = g.cmd(p)
        m = LOG_WIPE.search(c)
        if m:
            target = m.group(5) or "shell history"
            yield {"kind": "log_wipe", "actor": p, "title": f"Traces removed: {os.path.basename(target) if '/' in target else target} cleared",
                   "text": f"'{_short(c, 90)}'"}
            return
        m = re.search(r"\brm\s+(-\w+\s+)*(\S+)", c)
        if m and m.group(2) in exes and not SYSTEM_EXE.search(m.group(2)):
            yield {"kind": "log_wipe", "actor": p, "title": f"Traces removed: {os.path.basename(m.group(2))} deleted after it ran",
                   "text": f"the program {_short(m.group(2), 70)} was deleted after running"}
            return


def _tool_download(g: _G):
    for p in g.procs:
        conns = g.net(p, ("CONNECT",))
        if not conns:
            continue
        first = min(t for _, t in conns)
        for e in g.out.get(p, []):
            f, path = e["dst"], g.path(e["dst"]) or ""
            if e["op"] != "WRITE" or g.kind(f) != "file" or int(e.get("ts_ns") or 0) < first:
                continue
            if STAGING.search(path) and not ARCHIVE_FILE.search(path) and not path.endswith((".log", ".txt")):
                yield {"kind": "tool_download", "actor": p, "title": f"Tool download: {g.name(p)} saved {os.path.basename(path)} from {_hp(g, conns[0][0])}",
                       "text": f"{g.name(p)} connected to {_hp(g, conns[0][0])} and wrote {_short(path, 70)}"}
                return


def _privesc_recon(g: _G):
    for p in g.procs:
        if SUID_HUNT.search(g.cmd(p)):
            yield {"kind": "privesc_recon", "actor": p, "title": "Privilege-escalation recon: searched for set-uid programs",
                   "text": f"{g.name(p)} ran '{_short(g.cmd(p), 90)}'"}
            return
    for p in g.procs:
        if not AUTH_PROGRAMS.match(g.name(p)) and any((g.path(f) or "") == "/etc/sudoers" for f in g.files(p, "READ")):
            yield {"kind": "privesc_recon", "actor": p, "title": f"Privilege-escalation recon: {g.name(p)} read /etc/sudoers",
                   "text": f"{g.name(p)} read the sudo configuration"}
            return


def _discovery(g: _G):
    found, who = [], {}
    for p in g.procs:
        c = g.cmd(p) or g.exe(p) or ""
        for label, rx in RECON:
            if label not in found and rx.search(" " + c):
                found.append(label); who[label] = p
    if len(found) >= 3:
        yield {"kind": "discovery", "actor": who[found[0]],
               "title": f"Discovery: {len(found)} reconnaissance commands ({', '.join(found[:3])}{', ...' if len(found) > 3 else ''})",
               "text": "system, user and network information was collected: " + ", ".join(found)}


DETECTORS = [_ransomware, _web_shell, _remote_shell, _cryptominer, _credential, _dns_tunnel, _staged_exfil, _dropped,
             _persistence, _lateral, _masquerade, _log_wipe, _tool_download, _privesc_recon, _discovery]


def analyse(alerts: list[dict]) -> list[dict]:
    """Behaviours in an incident (alerts with their provenance context), most important first:
    [{kind, label, tactic, title, text, node}]."""
    if not any(a.get("context") for a in alerts):
        return []
    g = _G(alerts)
    out = []
    for det in DETECTORS:
        try:
            for b in det(g):
                label, tactic = KINDS[b["kind"]]
                out.append({"kind": b["kind"], "label": b.get("label", label), "tactic": tactic, "title": b["title"],
                            "text": b["text"], "node": b.get("actor")})
        except Exception:      # a naming helper must never break the incident list
            continue
    return out
