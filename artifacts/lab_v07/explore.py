import json, sys, collections, numpy as np
from pdp_engine.data import WindowStore
for eid in sys.argv[1:]:
    for part in ("baseline", "eval-test"):
        st = WindowStore(f"/data/endpoints/{eid}/{part}")
        reg = st.load_registry()
        c = collections.Counter(e.ntype for e in reg.entities)
        days = st.days()
        print(eid[:8], part, dict(c), [(d, st.count(d)) for d in days])
    ents = reg.entities
    import random; random.seed(0)
    for t in ("subject", "file", "netflow"):
        xs = [e.label for e in ents if e.ntype == t]
        print(t, [x[:120] for x in random.sample(xs, min(6, len(xs)))])
    print("display keys", list((ents[0].display or {}).keys())[:10])
