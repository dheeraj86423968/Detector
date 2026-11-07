"""Production detector-3 (pdp_engine.behaviour) vs the lab prototype: identical edge scores on a dev endpoint, and a
save/load round trip."""
import sys, tempfile, numpy as np
from pdp_engine.data import WindowStore
from pdp_engine.behaviour import BehaviourModel
import bl
from common import D, bundle_split
eid = D[sys.argv[1]][0]; tr, val = bundle_split(eid)
base = WindowStore(f"/data/endpoints/{eid}/baseline"); reg = base.load_registry()
days = tr[:2]
m, K = BehaviourModel.fit(base, days, reg)
voc = bl.Vocab(); KB = bl.Keyed(voc, reg); lm = bl.BL(); lm.floor = "proper"
for d in days:
    for w in base.windows(d):
        lm.fit_window(w, KB)
lm.finish()
d = tempfile.mkdtemp(); m.save(d); m2 = BehaviourModel.load(d); K2 = m2.keys(reg)
mx = 0.0; n = 0
for k, w in enumerate(base.windows(val)):
    if k > 10: break
    _, _, _, _, s_lab = bl.instance_scores(lm, KB, w, "once")
    p, x, e, s_prod = m.edge_scores(w, K)
    _, _, _, s_load = m2.edge_scores(w, K2)
    mx = max(mx, float(np.abs(s_lab - s_prod).max(initial=0)), float(np.abs(s_prod - s_load).max(initial=0))); n += len(s_prod)
print("events", n, "max abs diff", mx)
