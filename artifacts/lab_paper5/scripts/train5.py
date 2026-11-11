"""paper5 (artifacts/lab_paper5/PROTOCOL.md): train one more bundle of the 0.10 configuration for a set, changing only
the random seeds. Path = run 1's: Trainer(cfg6) -> b06, upgrade_bundle_07(b06, cfg7) -> b07 (heldout10.py / heldout08.py).
Usage: train5.py SET RUN   (RUN 2..5; seed base 100 x (RUN - 1))"""
import functools, json, os, shutil, sys, time
import pdp_engine.trainer as T
from pdp_engine.featurizer import Word2VecFeaturizer
from pdp_engine.trainer import TrainConfig, Trainer, upgrade_bundle_07
from common8 import Set, log

RUN1 = {"CARBANAKV2_EDR-h1": "b07rel", "CARBANAKV2_EDR-h2": "b07rel", "CARBANAKV2_EDR-h3": "b07rel", "CARBANAKV2_EDR-h4": "b07rel",
        "CARBANAKV2_EDR-h5": "b07rel", "THEIA_E5-theia": "b07rel", "CLEARSCOPE_E5-clearscope": "b07rel"}
D2_128 = {"orthrus_hid_dim": 128, "orthrus_out_dim": 128}
OVERRIDES = {"THEIA_E3": D2_128, "OPTC_H051": D2_128, "OPTC_H201": D2_128}


def run1_bundle(s):
    return f"{Set(s).work}/{RUN1.get(s, 'v07rel')}"


def out_dir(s, r):
    return f"/data/paper5/{s}/r{r}"


if __name__ == "__main__":
    s, r = sys.argv[1], int(sys.argv[2])
    assert 2 <= r <= 5
    base = 100 * (r - 1)
    S = Set(s)
    m1 = json.load(open(run1_bundle(s) + "/manifest.json"))
    assert list(m1["train_days"]) == list(S.train_days) and m1["val_day"] == S.val_day, (m1["train_days"], S.train_days)
    d2 = m1["detectors"]["detector-2"]
    ov = OVERRIDES.get(s, {})
    assert d2["hid_dim"] == ov.get("orthrus_hid_dim", 256) and d2["out_dim"] == ov.get("orthrus_out_dim", 256), d2
    seeds = {"word2vec": base, "detector-1": [base + k for k in range(3)], "detector-2": [base + k for k in range(5)]}
    T.Word2VecFeaturizer = functools.partial(Word2VecFeaturizer, seed=base)   # the trainer builds it with seed 0 otherwise
    cfg8 = TrainConfig(device="cuda", velox_seed=base, orthrus_seeds=tuple(seeds["detector-2"]), **ov)
    cfg7 = TrainConfig(**{**cfg8.__dict__, "d3_breadth": False, "layer_novelty": True})
    cfg6 = TrainConfig(**{**cfg8.__dict__, "detector3": False, "d3_breadth": False, "layer_novelty": True,
                          "novelty_as_evidence": False, "learned_alerts": False})
    od = out_dir(s, r)
    b6, b7 = od + "/b06", od + "/b07"
    os.makedirs(od, exist_ok=True)
    if os.path.exists(b7 + "/manifest.json") and json.load(open(b7 + "/manifest.json")).get("calibration", {}).get("final", {}).get("pending") is None:
        log(f"{b7} exists"); sys.exit(0)
    for d in (b6, b7):
        if os.path.exists(d):
            shutil.rmtree(d)
    t0 = time.time()
    base_store = S.base_store()
    Trainer(base_store, list(S.train_days), S.val_day, cfg6, b6).run({"endpoint": s, "paper5_run": r, "paper5_seeds": seeds})
    log(f"0.6-config bundle {time.time()-t0:.0f}s")
    upgrade_bundle_07(b6, b7, base_store, cfg7)
    log(f"0.7 released bundle {time.time()-t0:.0f}s")
    shutil.rmtree(b6)
    same = json.load(open(b7 + "/layers.json")) == json.load(open(run1_bundle(s) + "/layers.json"))
    json.dump({"set": s, "run": r, "seeds": seeds, "overrides": ov, "train_s": round(time.time() - t0), "layers_equal_run1": same,
               "train_days": S.train_days, "val_day": S.val_day}, open(od + "/train5.json", "w"), indent=1)
    log(f"done; layers.json equal to run 1: {same}")
