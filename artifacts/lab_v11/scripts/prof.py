"""Profile one full training (same Trainer and defaults as worker.job_train) of a replay endpoint's baseline store:
phase times, peak host RSS, peak GPU memory. Usage: prof.py <endpoint_id> <bundle_dir> <out_dir>"""
import json, os, resource, sys, time, threading
import torch
from pdp_engine.trainer import Trainer, TrainConfig
from pdp_engine.data import WindowStore

eid, bdir, out = sys.argv[1:4]
m = json.load(open(os.path.join(bdir, "manifest.json")))
store = WindowStore(f"/data/endpoints/{eid}/baseline")
t0 = time.time()
tr = Trainer(store, m["train_days"], m["val_day"], TrainConfig(device="cuda"), out)
print(f"PROF registry {len(tr.reg)} nodes load {time.time()-t0:.1f}s", flush=True)
peak = [0]
def sample():
    while True:
        peak[0] = max(peak[0], torch.cuda.max_memory_allocated() if torch.cuda.is_available() else 0)
        time.sleep(1)
threading.Thread(target=sample, daemon=True).start()
t1 = time.time()
tr.run({"endpoint": eid, "bundle_id": "prof", "window_ns": m["window_ns"], "trained_on": "cuda"})
print(f"PROF total {time.time()-t1:.1f}s rss_peak {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/2**20:.1f} GiB "
      f"gpu_peak {torch.cuda.max_memory_allocated()/2**30:.1f} GiB", flush=True)
