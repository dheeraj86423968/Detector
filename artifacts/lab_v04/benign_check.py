"""Label-free check: alarms on benign baseline days, leave-one-day-out (no labels used; allowed on held-out sets).
Novelty: programs on day k unseen on the other baseline days (alerts as 0.3 counts them vs 0.4 with program keys and
one alert per new program per day). Rules: benign alarm events of the calibration replay (0.3 vs 0.4 settings)."""
import json, sys, collections
import numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.layers import LayerConfig, TagParams, fit_layers, executable, program_key, program_name
eid = sys.argv[1]
bst = WindowStore(f"/data/endpoints/{eid}/baseline"); reg = bst.load_registry()
import glob
spec0 = json.load(open(glob.glob(f"/data/bundles/{eid}/*/layers.json")[0]))
days = spec0["fit_days"]
per_day = []
for d in days:
    procs = {}
    for w in bst.windows(d):
        for n in np.unique(np.concatenate([w.src, w.dst])).tolist():
            e = reg.entities[n]
            if e.ntype == "subject":
                procs[n] = e.label
    per_day.append(procs)
old_tot = new_tot = 0
for k, procs in enumerate(per_day):
    others_old = {executable(l) for j, p in enumerate(per_day) if j != k for l in p.values()}
    others_new = {program_key(executable(l, True)) for j, p in enumerate(per_day) if j != k for l in p.values()}
    names_new = {program_name(x) for x in others_new}
    old = sum(1 for l in procs.values() if executable(l) not in others_old and executable(l) not in ("None", "", "null"))
    new_progs = set()
    for l in procs.values():
        x = executable(l, True)
        if x in ("None", "", "null"):
            continue
        kk = program_key(x)
        if kk in others_new or ("/" not in kk and program_name(kk) in names_new):
            continue
        new_progs.add(kk)
    old_tot += old; new_tot += len(new_progs)
print(f"{eid[:8]} novelty LODO alerts over {len(days)} baseline days: 0.3 {old_tot}  0.4 {new_tot}")
for name, cfg in (("0.3", LayerConfig(tags=TagParams(**spec0["config"]["tags"]))),
                  ("0.4", LayerConfig(tags=TagParams(**spec0["config"]["tags"]), normalize_programs=True, full_paths=True, novel_instances=1,
                                      image_exec=True, local_multicast=True))):
    s = fit_layers(bst, days, reg, len(reg), cfg, log=lambda m: None)
    print(f"{eid[:8]} rules {name}: benign alarm events {s['benign_alarm_events']}  keys {sum(len(v) for v in s['thresholds'].values())}")
