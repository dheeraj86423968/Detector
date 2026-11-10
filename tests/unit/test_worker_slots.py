"""0.11 parallel training slots (pdp_server.worker): how many slots by default, and when a slot may start a job.
Run: PYTHONPATH=server:engine python tests/unit/test_worker_slots.py"""
import contextlib
import subprocess
import sys
import types

from pdp_server import worker as W

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


GB = 2**30
mem = {"MemTotal": 62 * GB, "MemAvailable": 40 * GB}
W._meminfo = lambda f: mem[f]
gpu = {"total_mib": "46068", "free": 30 * GB}
_run = subprocess.run
subprocess.run = lambda *a, **k: types.SimpleNamespace(stdout=gpu["total_mib"] + "\n")
W.os.cpu_count = lambda: 8
check(W.auto_slots("cpu") == 1, "CPU worker: one job at a time")
check(W.auto_slots("cuda") == 4, f"46 GB GPU, 8 cores, 62 GB RAM: 4 slots ({W.auto_slots('cuda')})")
gpu["total_mib"] = "16384"
check(W.auto_slots("cuda") == 1, f"16 GB GPU: 1 slot ({W.auto_slots('cuda')})")
gpu["total_mib"] = "81920"; W.os.cpu_count = lambda: 4
check(W.auto_slots("cuda") == 2, f"80 GB GPU but 4 cores: 2 slots ({W.auto_slots('cuda')})")
subprocess.run = lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("nvidia-smi"))
check(W.auto_slots("cuda") == 1, "no nvidia-smi: 1 slot")
subprocess.run = _run

# admission
torch = types.ModuleType("torch"); torch.cuda = types.SimpleNamespace(mem_get_info=lambda: (gpu["free"], 46 * GB))
sys.modules["torch"] = torch
recent = {"v": None}


@contextlib.contextmanager
def fake_conn(*a, **k):
    yield None


W.db = types.SimpleNamespace(conn=fake_conn, q=lambda c, sql, params=None, one=False: recent["v"])
check(W.admit(0, "cuda", ("train",)) == (True, ""), "slot 0 always takes work (as before 0.11)")
check(W.admit(1, "cpu", ("train",))[0], "CPU slots are not memory-gated")
check(W.admit(1, "cuda", ("train",)) == (True, ""), "slot 1 with room on the GPU and the host: starts")
mem["MemAvailable"] = 6 * GB
ok, why = W.admit(1, "cuda", ("train",))
check(not ok and "host memory" in why, f"too little host memory: waits ({why})")
mem["MemAvailable"] = 40 * GB; gpu["free"] = 3 * GB
ok, why = W.admit(2, "cuda", ("train",))
check(not ok and "GPU memory" in why, f"too little GPU memory: waits ({why})")
gpu["free"] = 30 * GB; recent["v"] = {"?column?": 1}
ok, why = W.admit(1, "cuda", ("train",))
check(not ok and "started less than" in why, f"another job just started (memory not allocated yet): waits ({why})")
check("NOT EXISTS" in W.NEXT_JOB and "r.endpoint_id = j.endpoint_id" in W.NEXT_JOB, "one job per endpoint at a time")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
