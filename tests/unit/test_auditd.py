"""Unit tests for the auditd normaliser (synthetic records)."""
import sys

sys.path.insert(0, "/home/platform/engine"); sys.path.insert(0, "/home/platform/agent")
from pdp_agent.sources.auditd import AuditNormaliser, parse_line, sockaddr  # noqa: E402


def hexs(s: str) -> str:
    return s.encode().hex().upper()


def feed(n, lines):
    out = []
    for l in lines:
        out.extend(n.feed(l))
    out.extend(n.flush())
    return out


def test_parse_line():
    r = parse_line('type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=257 success=yes exit=3 a2=0 pid=1234 ppid=1 exe="/usr/bin/cat" key="pdp"')
    assert r[0] == "SYSCALL" and r[1] == 1700000000123000000 and r[2] == 42 and r[3]["pid"] == "1234"


def test_sockaddr():
    # AF_INET (2), port 80, 1.2.3.4
    assert sockaddr("0200" + "0050" + "01020304" + "0000000000000000") == ("1.2.3.4", "80")


def test_open_read_write_and_exec():
    n = AuditNormaliser(boot_id="b1")
    lines = [
        'type=SYSCALL msg=audit(1700000000.100:1): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd a2=0 pid=10 ppid=1 exe="/usr/bin/cat" key="pdp"',
        'type=CWD msg=audit(1700000000.100:1): cwd="/home/u"',
        'type=PATH msg=audit(1700000000.100:1): item=0 name="etc/passwd" inode=1 nametype=NORMAL',
        'type=EOE msg=audit(1700000000.100:1): ',
        'type=SYSCALL msg=audit(1700000000.200:2): arch=c000003e syscall=257 success=yes exit=4 a2=241 pid=10 ppid=1 exe="/usr/bin/cat" key="pdp"',
        'type=PATH msg=audit(1700000000.200:2): item=0 name="/tmp/out" nametype=CREATE',
        'type=EOE msg=audit(1700000000.200:2): ',
        'type=SYSCALL msg=audit(1700000000.300:3): arch=c000003e syscall=59 success=yes exit=0 pid=11 ppid=10 exe="/usr/bin/curl" key="pdp"',
        'type=EXECVE msg=audit(1700000000.300:3): argc=2 a0="curl" a1=' + hexs("http://x.y/z") ,
        'type=EOE msg=audit(1700000000.300:3): ',
        'type=SYSCALL msg=audit(1700000000.400:4): arch=c000003e syscall=42 success=yes exit=0 pid=11 ppid=10 exe="/usr/bin/curl" key="pdp"',
        'type=SOCKADDR msg=audit(1700000000.400:4): saddr=0200005001020304' + "0" * 16,
        'type=EOE msg=audit(1700000000.400:4): ',
    ]
    evs = feed(n, lines)
    ops = [(e.op, [x.ntype for x in ents]) for ents, e in evs]
    assert ops[0] == ("OPEN", ["file", "subject"]) and ops[1] == ("READ", ["file", "subject"])   # read-only open
    assert ("WRITE", ["subject", "file"]) in ops and ("OPEN", ["file", "subject"]) in ops[2:]      # O_WRONLY|O_CREAT|O_TRUNC
    assert ("EXECUTE", ["file", "subject"]) in ops and ("CLONE", ["subject", "subject"]) in ops
    assert ops[-1] == ("CONNECT", ["subject", "netflow"])
    # relative path resolved against cwd, label format of the framework
    first_file = evs[0][0][0]
    assert first_file.label == "file /home/u/etc/passwd"
    curl = [x for ents, e in evs for x in ents if x.ntype == "subject" and "curl" in x.label][0]
    assert curl.label == "subject /usr/bin/curl curl http://x.y/z"
    sock = evs[-1][0][1]
    assert sock.label == "netflow 1.2.3.4 80" and sock.uuid == "net:1.2.3.4:80"
    # exec creates a new process generation (new uuid) for the same pid
    uuids = {x.uuid for ents, e in evs for x in ents if x.ntype == "subject"}
    assert "proc:b1:11:0" in uuids and "proc:b1:11:1" in uuids


if __name__ == "__main__":
    test_parse_line(); test_sockaddr(); test_open_read_write_and_exec()
    print("auditd tests OK")
