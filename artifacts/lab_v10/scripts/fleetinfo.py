import json, os
from common8 import Set
FLEETS = {"CARBANAKV2": [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)], "OPTC": ["OPTC_H201", "OPTC_H501", "OPTC_H051"],
          "ATLASV2": ["ATLASV2_EDR-h1", "ATLASV2_EDR-h2"], "THEIA": ["THEIA_E3", "THEIA_E5-theia"]}
B = {"CARBANAKV2": "b07rel", "THEIA_E5-theia": "b07rel"}
for f, sets in FLEETS.items():
    for s in sets:
        S = Set(s); b = B.get(s, B.get(f, "v07rel"))
        L = json.load(open(f"{S.work}/{b}/layers.json"))
        print(f, s, "train", S.train_days[0], "..", S.train_days[-1], "val", S.val_day, "test", S.test_days, "known", len(L["known_executables"]), L.get("config", {}).get("novelty"))
