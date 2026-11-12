"""Lab 0.13 prep: re-fit one set's known programs from its released bundle's layers.json fit_days (training +
validation), with the old parser and with backslash_paths. Usage: prep16.py SET  -> out/known16-SET.json"""
import json, sys, time
from pdp_engine.layers import NoveltyLayer
from common8 import Set, log
BUNDLE = {s: "b07rel" for s in [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)] + ["THEIA_E5-theia"]}
name = sys.argv[1]
S = Set(name)
spec = json.load(open(f"{S.work}/{BUNDLE.get(name, 'v07rel')}/layers.json"))
days, fp = spec["fit_days"], spec["config"].get("full_paths", False)
bst = S.base_store(); breg = bst.load_registry()
out = {"set": name, "fit_days": days, "released": sorted(spec["known_executables"])}
for tag, bs in (("old", False), ("bs", True)):
    t = time.time()
    out[tag] = sorted(NoveltyLayer.fit((bst.windows(d) for d in days), breg, fp, bs))
    log(f"{name} {tag}: {len(out[tag])} known programs ({time.time()-t:.0f}s)")
out["old_equals_released"] = out["old"] == out["released"]
log(f"{name}: old parser re-fit equals the released known programs: {out['old_equals_released']}")
json.dump(out, open(f"out/known16-{name}.json", "w"))
