"""Dry run of the laundering transform on top of LotL (no detector, no scoring): payload files per set."""
import json, sys
import numpy as np
from common8 import Set, log
import lotl, launder
BUNDLE = lambda s: "b07rel" if s.startswith(("CARBANAKV2", "THEIA_E5", "CLEARSCOPE_E5")) else "v07rel"
out = {}
for s in sys.argv[1:]:
    S = Set(s); st = S.eval_store(); reg = st.load_registry(); bdir = f"{S.work}/{BUNDLE(s)}"
    N = json.load(open(f"{bdir}/manifest.json"))["num_nodes"]
    seen = set()
    for d in S.test_days:
        for w in st.windows(d):
            seen.update(np.unique(np.concatenate([w.src, w.dst])).tolist())
    rl, rep = lotl.build(S, reg, bdir, N, seen); lotl.apply(reg, rl)
    LA = launder.Launder(S, reg, bdir, N, st, set(rl))
    out[s] = LA.report
    log(f"{s}: {json.dumps(LA.report, default=list)[:2500]}")
json.dump(out, sys.stdout, indent=1, default=list)
