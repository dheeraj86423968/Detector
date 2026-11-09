"""Product path check: Runtime.set_fleet_programs with the server's key computation (pdp_server.fleet) reproduces the
lab variant (eval13 rewrites hits after the layer). Usage: verify13.py SET MODE K"""
import json, sys, time
from collections import Counter
import numpy as np
from pdp_engine.runtime import Runtime
from pdp_engine.layers import UNKNOWN_PROGRAM, program_key
from common8 import Set, log, at
sys.argv += []
s, mode, k = sys.argv[1], sys.argv[2], int(sys.argv[3])
exec(open("eval13.py").read().split("VARIANTS =")[0].split("from common8 import Set, log, at")[1])   # FLEETS, BUNDLE
S = Set(s); st = S.eval_store(); reg = st.load_registry()
rt = Runtime(f"{S.work}/{BUNDLE.get(s, 'v07rel')}", reg, device="cuda", feat_device="cuda")
fleet = next(m for m in FLEETS.values() if s in m)
cnt = Counter()
for o in fleet:
    if o != s:
        So = Set(o)
        cnt.update({program_key(str(x), strict=True) for x in json.load(open(f"{So.work}/{BUNDLE.get(o, 'v07rel')}/layers.json"))["known_executables"] if str(x) not in UNKNOWN_PROGRAM})
rt.set_fleet_programs({p: n for p, n in cnt.items() if n >= k}, mode)
alerted = set(); seen = np.zeros(0, bool)
for d in S.test_days:
    for w in st.windows(d):
        r = rt.score(w); alerted |= set(r.alerts.tolist())
        if len(seen) < len(reg): seen = np.concatenate([seen, np.zeros(len(reg) - len(seen), bool)])
        seen[w.src] = True; seen[w.dst] = True
ix = np.where(seen)[0]; uu = [reg.entities[int(i)].uuid for i in ix]
labels = np.array([u in S.allgt for u in uu]); na = [{x for x, v in S.gt.items() if u in v} for u in uu]
pred = np.array([int(i) in alerted for i in ix])
print(s, mode, k, at(pred, labels, na))
