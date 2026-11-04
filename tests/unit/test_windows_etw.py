"""Unit tests for the Windows ETW collector's event mapping (no Windows/pywintrace needed).
Run: PYTHONPATH=engine:agent python tests/unit/test_windows_etw.py
"""
import sys

from pdp_agent.sources.windows_etw import EtwNormaliser, EtwLive

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


n = EtwNormaliser("host")


def feed(ev):
    return [(e.op, ents[0].ntype, ents[1].ntype, ents[0].label, ents[1].label) for ents, e in n.decode_event(ev, ts_ns=1)]


e = feed({"kind": "process_start", "pid": 10, "ppid": 4, "image": "C:\\Windows\\cmd.exe", "cmdline": "cmd /c x"})
check(any(o == "CLONE" for o, *_ in e) and any(o == "EXECUTE" for o, *_ in e), "process_start -> CLONE + EXECUTE")
check(any(d == "subject" and "cmd /c x" in lbl for o, s, d, sl, lbl in e if o == "EXECUTE"), "process label carries image + cmdline")

e = feed({"kind": "file", "pid": 10, "path": "C:\\Users\\a\\secret.txt", "access": "read"})
check([o for o, *_ in e] == ["OPEN", "READ"], "file read -> OPEN + READ")

e = feed({"kind": "file", "pid": 10, "path": "C:\\tmp\\out.bin", "access": "write"})
check("WRITE" in [o for o, *_ in e] and "READ" not in [o for o, *_ in e], "file write -> WRITE only")

e = feed({"kind": "net", "pid": 10, "raddr": "203.0.113.5", "rport": 443, "direction": "out"})
check(len(e) == 1 and e[0][0] == "CONNECT" and e[0][2] == "netflow" and e[0][4] == "netflow 203.0.113.5 443",
      "net out -> CONNECT process->netflow")

# raw pywintrace-shaped event translation
m = EtwLive()._map_raw({"Task Name": "ProcessStart", "ProcessID": 11, "ParentProcessID": 10, "ImageName": "a.exe", "CommandLine": "a.exe"})
check(m and m["kind"] == "process_start" and m["pid"] == 11, "raw ETW ProcessStart mapped to normaliser schema")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
