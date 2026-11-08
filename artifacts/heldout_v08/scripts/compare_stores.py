"""Compare two host directories (baseline + eval-test WindowStores) array by array."""
import json, os, sys
import numpy as np
a, b = sys.argv[1], sys.argv[2]
ok = True
for part in ("baseline", "eval-test"):
    ra, rb = (json.load(open(os.path.join(x, part, "registry.json"))) for x in (a, b))
    same = ra == rb
    ok &= same
    print(part, "registry entities", len(ra["entities"]), len(rb["entities"]), "identical" if same else "DIFFERENT")
    if not same:
        for i, (x, y) in enumerate(zip(ra["entities"], rb["entities"])):
            if x != y:
                print("  first diff at", i, x, y); break
    da, db = (sorted(os.listdir(os.path.join(x, part, "windows"))) for x in (a, b))
    print(part, "days", da, db); ok &= da == db
    for d in da:
        fa, fb = (sorted(os.listdir(os.path.join(x, part, "windows", d))) for x in (a, b))
        if fa != fb:
            print("  window files differ", d, len(fa), len(fb)); ok = False; continue
        n = 0
        for f in fa:
            za, zb = (np.load(os.path.join(x, part, "windows", d, f)) for x in (a, b))
            for k in ("src", "dst", "t", "etype", "start", "end", "uuid"):
                if not np.array_equal(za[k], zb[k]) or za[k].dtype != zb[k].dtype:
                    print("  DIFF", d, f, k); ok = False
            n += len(za["src"])
        print(f"  {d}: {len(fa)} windows, {n} edges compared")
print("EQUIVALENT" if ok else "NOT EQUIVALENT")
