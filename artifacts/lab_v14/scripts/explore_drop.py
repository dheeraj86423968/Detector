"""Exploration (before any protocol): of the new-program alerts of the released layer 1, which programs' files were
written earlier in the monitored stream ("dropped"), by which program, and does that writer drop-and-run programs
during the baseline? CPU only. Usage: explore_drop.py SET"""
import json, sys
from collections import Counter, defaultdict
import numpy as np
from pdp_engine.layers import NoveltyLayer, executable, canonical_path, program_key, file_path, EXECUTE, CLONE, WRITE
from common8 import Set
BUNDLE = {s: "b07rel" for s in [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)] + ["THEIA_E5-theia"]}
name = sys.argv[1]; S = Set(name)
spec = json.load(open(f"{S.work}/{BUNDLE.get(name, 'v07rel')}/layers.json")); c = spec["config"]
pk = lambda x: program_key(x, True, True)
cp = lambda p: canonical_path(p.replace("\\", "/")) if (":" in p[:3] or "\\" in p) else p


def scan(store, reg, days, nov=None):
    ents = reg.entities; written = {}; started = set(); out = []; droppers = defaultdict(set)
    for k, d in enumerate(days):
        for w in store.windows(d):
            hits = {h.nodes[0]: h for h in nov.process(w, reg, w.nodes())} if nov is not None else {}
            order = np.argsort(w.t, kind="stable")
            for s_, d_, e, t in zip(w.src[order].tolist(), w.dst[order].tolist(), w.etype[order].tolist(), w.t[order].tolist()):
                if e == WRITE and ents[d_].ntype == "file" and ents[s_].ntype == "subject":
                    p = cp(file_path(ents[d_].label))
                    if p not in ("None", ""):
                        written[p] = executable(ents[s_].label, True, True)
                elif e in (CLONE, EXECUTE) and ents[d_].ntype == "subject" and d_ not in started:
                    started.add(d_)
                    exe = executable(ents[d_].label, True, True)
                    wr = written.get(cp(exe))
                    if wr is not None:
                        droppers[pk(wr)].add(k)
                    if d_ in hits:
                        out.append((exe, wr, ents[d_].uuid))
            for n, h in hits.items():
                if n not in started:
                    started.add(n); exe = executable(ents[n].label, True, True)
                    out.append((exe, written.get(cp(exe)), ents[n].uuid))
    return out, droppers


bst = S.base_store(); breg = bst.load_registry()
_, droppers = scan(bst, breg, spec["fit_days"])
st = S.eval_store(); reg = st.load_registry()
nov = NoveltyLayer(set(spec["known_executables"]), None, normalize=c.get("normalize_programs", False), instances=0,
                   full_paths=c.get("full_paths", False), strict_keys=c.get("strict_program_key", False))
hits, _ = scan(st, reg, S.test_days, nov)
cat = Counter(); ex = defaultdict(list)
for exe, wr, uuid in hits:
    gt = uuid in S.allgt
    kind = "not-written" if wr is None else ("routine-dropper" if pk(wr) in droppers else "new-dropper")
    cat[(kind, "TP" if gt else "FP")] += 1
    if len(ex[(kind, gt)]) < 12:
        ex[(kind, gt)].append(f"{exe[-48:]} <= {str(wr)[-36:]}")
print(json.dumps({"set": name, "baseline_droppers": len(droppers), "top_droppers": sorted(droppers, key=lambda k: -len(droppers[k]))[:8],
                  "counts": {f"{k[0]}/{k[1]}": n for k, n in sorted(cat.items())}, "examples": {f"{k[0]}/{'TP' if k[1] else 'FP'}": v for k, v in ex.items()}}))
