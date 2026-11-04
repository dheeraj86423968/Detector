"""Kernels without BTF: the eBPF collector does not crash-loop the agent (idle ticks, the reason in health, retried),
finds a BTF file locally or downloads it from the server (raw, or BTFHub's .btf.tar.xz) and hands it to the loader.
No kernel needed (the kernel BTF path is pointed at a missing file). Run: PYTHONPATH=engine:agent python tests/unit/test_nobtf.py
"""
import io
import lzma
import os
import sys
import tarfile
import tempfile

import pdp_agent.sources.ebpf as eb
from pdp_agent.agent import Agent
from pdp_agent.config import Config
from pdp_agent.transport import TransportError

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


eb.KERNEL_BTF = "/nonexistent/vmlinux"
rel = os.uname().release
d = tempfile.mkdtemp()
check(eb.find_btf(d) is None, "no kernel BTF and no file: none found")
try:
    eb.CoreTracer(1024, loader="/bin/true")
    check(False, "CoreTracer without BTF raises")
except RuntimeError as e:
    check("has no BTF" in str(e) and rel in str(e), f"clear error naming the kernel ({str(e)[:80]}...)")

# the source keeps the agent alive: idle ticks, the reason recorded, retried
calls = []
src = eb.EbpfLive(btf=lambda: calls.append(1) or None, retry_s=0.01)
ticks, stop_after = 0, 3
it = src.batches(lambda: ticks >= stop_after)
for b in it:
    ticks += 1
    if ticks >= stop_after:
        break
check(ticks == 3 and src.error and "has no BTF" in src.error and len(calls) >= 2, f"idle ticks while the collector cannot start, retried ({len(calls)} attempts)")


class FakeTr:
    def __init__(self, payload, status=200):
        self.payload, self.status, self.paths = payload, status, []

    def download(self, path, dest, attempts=6):
        self.paths.append(path)
        if self.status != 200:
            raise TransportError(self.status, "no BTF")
        open(dest, "wb").write(self.payload)
        return {}


def agent():
    dd = tempfile.mkdtemp()
    a = Agent(Config(data_dir=dd, pki_dir=dd + "/pki", source={"kind": "ebpf"}, day_tz="UTC"))
    a.eid = "e1"
    return a


a = agent(); a.tr = FakeTr(b"\x9f\xeb\x01\x00raw-btf")
f = a.kernel_btf()
check(f and open(f, "rb").read() == b"\x9f\xeb\x01\x00raw-btf" and a.tr.paths == [f"/v1/endpoints/e1/btf/{rel}"], "raw BTF downloaded from the server")
check(eb.find_btf(a.cfg.data_dir) == f, "found locally next time (no second download)")
a.tr = FakeTr(b""); check(a.kernel_btf() == f and a.tr.paths == [], "cached file used")

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:xz") as t:
    data = b"\x9f\xeb\x01\x00hub-btf"
    ti = tarfile.TarInfo(f"{rel}.btf"); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
a = agent(); a.tr = FakeTr(buf.getvalue())
f = a.kernel_btf()
check(f and open(f, "rb").read() == b"\x9f\xeb\x01\x00hub-btf", "BTFHub .btf.tar.xz unpacked")

a = agent(); a.tr = FakeTr(b"", status=404)
check(a.kernel_btf() is None and not os.listdir(os.path.join(a.cfg.data_dir, "btf")), "server without a BTF for this kernel: none, no partial file")

a.source = src
h = a.health()
check("has no BTF" in h.get("collector_error", ""), "health carries the collector error")
src.error = None
check("collector_error" not in a.health(), "no error field once the collector runs")

# the server turns the heartbeat's collector_error into an error-level problem (console health, notifications);
# cluster nodes are told to re-apply the manifest instead of running the installer
try:
    from pdp_server.health import problems
except ImportError:          # the slim agent image has no server code
    problems = None
if problems:
    p = problems({"health": {"collector_error": "this kernel has no BTF"}, "agent_version": "0.3.18"})
    check(any(x["key"] == "collector_error" and x["level"] == "error" and "no BTF" in x["text"] for x in p), "server: collector error is an error-level problem")
    up = {"update": {"updater": False}}
    k = problems({"health": up, "agent_version": "0.3.17", "config": {"cluster": "prod"}}, "0.3.18")
    v = problems({"health": up, "agent_version": "0.3.17", "config": {}}, "0.3.18")
    check("manifest" in k[0]["text"] and "--upgrade" in v[0]["text"], "server: update advice for cluster nodes vs hosts")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
