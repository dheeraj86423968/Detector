"""Client attack suite: every scenario runs, stays inside its scratch root, uses only TEST-NET addresses, records
usable ground truth, and is randomised but reproducible. Run: PYTHONPATH=engine:sim python tests/unit/test_suite.py"""
import ipaddress
import os
import sys
import tempfile

from pdp_sim.suite import SCENARIOS, run_scenario

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


TEST_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
base = tempfile.mkdtemp()
outside_before = set(os.listdir(tempfile.gettempdir()))
for name in sorted(SCENARIOS):
    root = os.path.join(base, name)
    r = run_scenario(name, root, seed=7, fast=True)
    ok_markers = bool(r["markers"]) and all(m.startswith(root) or ipaddress.ip_address(m.split()[0]) in TEST_NETS[0] or
                                             any(ipaddress.ip_address(m.split()[0]) in n for n in TEST_NETS) for m in r["markers"])
    nets = [s.split()[1].split(":")[0] for s in r["steps"] if s.startswith(("tcp ", "udp "))]
    ok_nets = all(any(ipaddress.ip_address(ip) in n for n in TEST_NETS) for ip in nets)
    check(ok_markers and ok_nets and r["techniques"], f"{name}: {len(r['markers'])} markers (scratch paths / TEST-NET only), {len(nets)} connections to TEST-NET")
a = run_scenario("staged_exfiltration", os.path.join(base, "x1"), seed=1, fast=True)
b = run_scenario("staged_exfiltration", os.path.join(base, "x2"), seed=2, fast=True)
c = run_scenario("staged_exfiltration", os.path.join(base, "x3"), seed=1, fast=True)
strip = lambda r, root: sorted(m.replace(root, "R") for m in r["markers"])
check(strip(a, os.path.join(base, "x1")) != strip(b, os.path.join(base, "x2")), "different seeds -> different names / C2")
check(strip(a, os.path.join(base, "x1")) == strip(c, os.path.join(base, "x3")), "same seed -> same scenario (reproducible)")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
