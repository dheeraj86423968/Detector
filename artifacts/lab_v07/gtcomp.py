import sys, collections, numpy as np
from pdp_engine.data import WindowStore
from common import D
z = np.load(sys.argv[2]); eid = D[sys.argv[1]][0]
reg = WindowStore(f"/data/endpoints/{eid}/eval-test").load_registry()
ix, raw, lab = z["ix"], z["raw"], z["labels"]
gi = ix[lab]
c = collections.Counter(reg.entities[int(i)].ntype for i in gi); print("GT by type", c)
import random; random.seed(1)
for t in ("subject", "file", "netflow"):
    xs = [(float(raw[j]), reg.entities[int(ix[j])].label[:110]) for j in np.where(lab)[0] if reg.entities[int(ix[j])].ntype == t]
    xs.sort(reverse=True)
    print("==", t, len(xs), "top:", xs[:8]); print("   random:", random.sample(xs, min(8, len(xs))))
    if xs: print("   score quantiles", np.percentile([x[0] for x in xs], [10, 50, 90]).round(1))
