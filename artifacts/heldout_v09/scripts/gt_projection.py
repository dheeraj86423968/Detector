"""argv: ref npz (survey), gt csv (relative to /gt) ...  Ground-truth lookup only: for each GT csv, how many node ids are
referenced by a kept event of the base (train+val) days / test days. The eval-test registry of a conversion is exactly the
referenced ids (base U test) that exist in the node tables, so this is the registry GT count before converting (upper
bound if a referenced id had no node row; THEIA_E5 / the CLEARSCOPE_E5 sample: 0 such)."""
import json, sys
import numpy as np
from pdp_server.tools.darpa_eval import load_gt
z = np.load(sys.argv[1]); b, t = set(map(str, z["base"].tolist())), set(map(str, z["test"].tolist()))
out = {}
for f in sys.argv[2:]:
    ids = next(iter(load_gt("/gt", [f]).values()))
    out[f] = {"gt_nodes": len(ids), "referenced_base_or_test": len(ids & (b | t)), "referenced_test_days": len(ids & t),
              "not_referenced": sorted(ids - b - t, key=int)}
print(json.dumps(out, indent=1))
