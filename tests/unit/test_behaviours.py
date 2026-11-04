"""Attack-behaviour naming (pdp_server.behaviours) on small provenance graphs, positives and look-alike negatives.
Run: PYTHONPATH=server:engine python tests/unit/test_behaviours.py"""
import sys

from pdp_server import behaviours as B
from pdp_server import incidents as I

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


def P(uid, exe, cmd=None):
    return (f"p:{uid}", f"subject {exe} {cmd or exe}")


def F(path):
    return (f"f:{path}", f"file {path}")


def N(ip, port):
    return (f"n:{ip}:{port}", f"netflow {ip} {port}")


def incident(edges, alerted=None):
    """edges: (src node, op, dst node, ts). One alert carries the whole context."""
    nodes = {}
    for s, _, d, _ in edges:
        nodes[s[0]] = s[1]; nodes[d[0]] = d[1]
    a = alerted or edges[0][0]
    ctx = {"nodes": [{"uuid": u, "label": l} for u, l in nodes.items()],
           "edges": [{"src": s[0], "dst": d[0], "op": op, "ts_ns": t} for s, op, d, t in edges]}
    return [{"id": 1, "endpoint_id": "ep", "endpoint_name": "ep", "window_start_ns": 0, "node_uuid": a[0], "ntype": "subject",
             "label": a[1], "display": None, "layer": "novelty", "rule": "novel_executable", "reason": "runs x", "status": "open",
             "context": ctx}]


def kinds(edges):
    return [b["kind"] for b in B.analyse(incident(edges))]


def title(edges):
    al = incident(edges)
    return I.summarise(al, B.analyse(al))


# ransomware: read N files, write each back under a new extension, ransom note
lock = P(1, "/home/u/.cache/kworker-x")
e = [(F(f"/home/u/Pictures/img{i}.jpg"), "READ", lock, i) for i in range(12)]
e += [(lock, "WRITE", F(f"/home/u/Pictures/img{i}.jpg.locked"), 100 + i) for i in range(12)]
e += [(lock, "WRITE", F("/home/u/Pictures/README_RESTORE.txt"), 200)]
s = title(e)
check(kinds(e)[0] == "ransomware" and s["title"] == "Ransomware: kworker-x rewrote 12 files as *.locked", f"ransomware named: {s['title']}")
check(s["severity"] == "high" and "Impact" in s["tactics"], f"ransomware raises severity to high, tactic Impact ({s['severity']}, {s['tactics']})")
# a build tool rewriting sources in place (same names) is not ransomware
cc = P(2, "/usr/bin/sed", "sed -i s/a/b/")
e = [(F(f"/src/f{i}.c"), "READ", cc, i) for i in range(15)] + [(cc, "WRITE", F(f"/src/f{i}.c"), 50 + i) for i in range(15)]
check("ransomware" not in kinds(e), "in-place rewrite without a new extension is not ransomware")

# remote shell: an implant connects out, its fork copy starts a shell
imp, fork, sh = P(3, "/tmp/.x/cron-check"), P(4, "/tmp/.x/cron-check"), P(5, "/bin/sh", "/bin/sh -c id; uname -a")
e = [(imp, "CONNECT", N("203.0.113.9", 443), 10), (imp, "CLONE", fork, 20), (fork, "CLONE", sh, 21)]
check(title(e)["title"] == "Remote shell: cron-check connected to 203.0.113.9:443 and ran shell commands", f"remote shell through a fork copy: {title(e)['title']}")
# a shell started *before* the connection (a script that then uploads) is not a remote shell
e = [(imp, "CLONE", sh, 5), (imp, "CONNECT", N("203.0.113.9", 443), 10)]
check("remote_shell" not in kinds(e), "shell started before connecting is not a remote shell")
# a local connection is not remote
e = [(imp, "CONNECT", N("127.0.0.1", 8080), 1), (imp, "CLONE", sh, 2)]
check("remote_shell" not in kinds(e), "loopback connection does not make a remote shell")

# web shell: web server starts a shell
ng, sh2 = P(6, "/usr/sbin/nginx", "nginx: worker process"), P(7, "/bin/sh", "/bin/sh -c whoami")
check(kinds([(ng, "CLONE", sh2, 1)])[:1] == ["web_shell"], "web server spawning a shell is a web shell")
php = P(8, "/usr/sbin/php-fpm8.1")
check("web_shell" in kinds([(php, "WRITE", F("/var/www/html/upload/x.php"), 1)]), "a .php written into a web directory is a web shell")

# DNS: a normal program talking to the configured resolver is not tunnelling; a dropped program is
links = P(9, "/usr/local/bin/links")
check("dns_tunnel" not in kinds([(links, "SENDTO", N("128.55.12.10", 53), 1)]), "system program querying its DNS server is not tunnelling")
dnsd = P(10, "/home/u/.local/bin/dnsd")
check("dns_tunnel" in kinds([(dnsd, "SENDTO", N("198.51.100.4", 53), 1)]), "dropped program sending to :53 is DNS tunnelling")
py = P(11, "/usr/bin/python3", "python3 -c import base64,socket; d=base64.b32encode(x)")
check("dns_tunnel" in kinds([(py, "SENDTO", N("198.51.100.4", 53), 1)]), "interpreter encoding data into DNS is tunnelling")

# persistence: writing a cron file is, running one is not
cron = P(12, "/bin/dash", "/bin/sh /etc/cron.daily/logrotate")
check("persistence" not in kinds([(cron, "READ", F("/etc/cron.daily/logrotate"), 1)]) and
      "persistence" not in kinds([(cron, "CLONE", P(13, "/usr/sbin/logrotate"), 1)]), "running a cron job is not persistence")
w = P(14, "/bin/bash", "bash -c echo k >> /root/.ssh/authorized_keys")
check(kinds([(w, "CLONE", P(15, "/bin/true"), 1)]) == ["persistence"], "echo >> authorized_keys is SSH-key persistence")
check("persistence" in kinds([(w, "WRITE", F("/etc/cron.d/0hourly"), 1)]), "writing /etc/cron.d is persistence")

# cryptominer, lateral movement, masquerading
xm = P(16, "/tmp/xmrig")
check(title([(xm, "CONNECT", N("192.0.2.5", 3333), 1)])["title"] == "Cryptominer: xmrig connected to mining-pool port 192.0.2.5:3333", "cryptominer named")
lm = P(17, "/tmp/.t/scan")
e = [(lm, "CONNECT", N(f"10.0.0.{i}", p), i) for i, p in ((2, 445), (3, 3389), (4, 22))]
check("lateral" in kinds(e), "remote-access ports on several hosts are lateral movement")
ssh = P(18, "/usr/bin/ssh", "ssh admin@10.0.0.2")
check("lateral" not in kinds([(ssh, "CONNECT", N("10.0.0.2", 22), 1)]), "one ssh session is not lateral movement")
check("masquerade" in kinds([(P(19, "/dev/shm/kworker"), "READ", F("/etc/hostname"), 1)]), "kworker running from /dev/shm is masquerading")
check("masquerade" not in kinds([(P(20, "/usr/lib/systemd/systemd-journald"), "READ", F("/etc/hostname"), 1)]), "real systemd binary is not masquerading")

# credential access, discovery
cat = P(21, "/bin/cat", "cat /etc/shadow")
check("credential" in kinds([(F("/etc/shadow"), "READ", cat, 1)]), "reading /etc/shadow is credential access")
check("credential" not in kinds([(F("/etc/shadow"), "READ", P(22, "/usr/sbin/sshd"), 1)]), "sshd reading /etc/shadow is not")
rc = P(23, "/bin/sh", "/bin/sh -c id; whoami; uname -a; hostname")
check("discovery" in kinds([(rc, "CLONE", P(24, "/usr/bin/id"), 1)]), "several recon commands are discovery")

# no behaviour: title falls back to the strongest detection
plain = incident([(P(25, "/usr/bin/vim"), "READ", F("/home/u/notes.txt"), 1)])
check(I.summarise(plain, B.analyse(plain))["title"] == "New program vim ran", "nothing recognised keeps the detection title")
check(B.analyse([{**plain[0], "context": None}]) == [], "no context, no behaviours")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
