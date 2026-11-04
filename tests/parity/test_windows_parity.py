"""Parity: pdp_engine window construction vs PIDSMaker's stored nx graphs for one day.

Usage (in the dev container): python tests/parity/test_windows_parity.py CADETS_E3 2018-04-06 <transformation nx dir>
"""
import os
import sys

import torch

sys.path.insert(0, "/home/platform/engine")
from pdp_engine.schema import EDGE_TYPE_ID, Registry  # noqa: E402
from pdp_engine.sources.pg_replay import PostgresReplay  # noqa: E402
from pdp_engine.windows import WindowBuilder  # noqa: E402

dataset, date, nx_dir = sys.argv[1:4]
db = {"CADETS_E3": "cadets_e3", "THEIA_E3": "theia_e3"}[dataset]

src = PostgresReplay(db)
reg = Registry()
for ent in src.entities():
    reg.add(ent)
print(f"{len(reg)} entities")

builder = WindowBuilder()
windows = []
for ev in src.events(date):
    windows.extend(builder.push(reg.get(ev.src), reg.get(ev.dst), ev.ts_ns, EDGE_TYPE_ID[ev.op], ev.event_uuid))
windows.extend(builder.finish())
print(f"engine: {len(windows)} windows, {sum(w.num_edges for w in windows)} fused edges")

ref_files = sorted(os.listdir(os.path.join(nx_dir, f"graph_{date}")))
print(f"framework: {len(ref_files)} windows")
assert len(ref_files) == len(windows), "window count differs"

mismatch = 0
for f, w in zip(ref_files, windows):
    g = torch.load(os.path.join(nx_dir, f"graph_{date}", f))
    ref = sorted((int(u), int(v), int(a["time"]), a["label"], a["event_uuid"]) for u, v, k, a in g.edges(data=True, keys=True))
    # engine ids are dense registry ids; map back to framework index ids via the entity uuid field (= index id)
    mine = sorted((int(reg[s].uuid), int(reg[d].uuid), int(t), "EVENT_" + list(EDGE_TYPE_ID)[e], u)
                  for s, d, t, e, u in zip(w.src, w.dst, w.t, w.etype, w.event_uuid))
    start_ref = f.split("~")[0]
    if ref != mine:
        mismatch += 1
        if mismatch <= 3:
            print(f"MISMATCH {f}: ref {len(ref)} edges vs engine {len(mine)}; first diff:",
                  next(((a, b) for a, b in zip(ref, mine) if a != b), None))
print("windows with identical edge sets:", len(windows) - mismatch, "/", len(windows))
print("PARITY OK" if mismatch == 0 else "PARITY FAILED")
