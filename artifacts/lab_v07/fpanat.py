import sys, collections, re, numpy as np
from pdp_engine.data import WindowStore
from common import D
ds, key = sys.argv[1], sys.argv[2]
eid = D[ds][0]; reg = WindowStore(f"/data/endpoints/{eid}/eval-test").load_registry()
z = np.load(f"/lab/s4-{ds}.npz"); ix, lab, sc = z["ix"], z["labels"], z[key]
fp = np.where((sc > 1) & ~lab)[0]
c = collections.Counter(reg.entities[int(ix[j])].ntype for j in fp); print("FP by type", c)
pat = collections.Counter(re.sub(r"\d+", "#", reg.entities[int(ix[j])].label)[:70] for j in fp)
for k, v in pat.most_common(25): print(v, k)
