"""argv: host dir, referenced npz, gt csv (relative to /gt) ...
Adds manifest["ground_truth_not_in_pidsmaker_list"]: GT lookups (same counting as heldout_stream manifest) for orthrus
csvs that PIDSMaker leaves out of CLEARSCOPE_E5's ground_truth_relative_path (recorded separately, not evaluation GT).
Ground-truth lookup against the registry only; nothing is scored."""
import collections, json, os, sys
import numpy as np
from pdp_engine.data import WindowStore
from pdp_server.tools.darpa_eval import load_gt

hdir, refp, files = sys.argv[1], sys.argv[2], sys.argv[3:]
reg = WindowStore(os.path.join(hdir, "eval-test")).load_registry()
z = np.load(refp)
refb, reft = set(map(str, z["base"].tolist())), set(map(str, z["test"].tolist()))
out = {}
for f in files:
    ids = next(iter(load_gt("/gt", [f]).values()))
    found = {i for i in ids if i in reg.ids}
    miss = ids - found
    r = {"csv": f, "gt_nodes": len(ids), "found_in_eval_test_registry": len(found), "not_found": len(miss),
         "found_by_type": dict(collections.Counter(reg.entities[reg.ids[i]].ntype for i in found))}
    if miss:
        r["not_found_breakdown"] = {"no_kept_event_on_prepared_days_or_not_in_database": sum(1 for i in miss if i not in refb and i not in reft),
                                    "referenced_but_entity_missing": sum(1 for i in miss if i in refb or i in reft)}
    out[os.path.basename(f)[:-4]] = r
mp = os.path.join(hdir, "manifest.json")
man = json.load(open(mp))
man["ground_truth_not_in_pidsmaker_list"] = out
json.dump(man, open(mp, "w"), indent=1, default=str)
print(json.dumps(out, indent=1))
