import json, os
from common8 import Set
from eval13_fleets import FLEETS, BUNDLE
out = {}
for f, ms in FLEETS.items():
    for s in ms:
        S = Set(s); b = f"{S.work}/{BUNDLE.get(s, 'v07rel')}"
        out[s] = {"fleet": f, "bundle": b, "ok": os.path.exists(b + "/manifest.json"), "train_days": S.train_days, "val_day": S.val_day,
                  "test_days": S.test_days}
print(json.dumps(out))
