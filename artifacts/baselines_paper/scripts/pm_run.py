"""Run PIDSMaker (unmodified checkout mounted read-only at /pids) for one system/dataset/seed, adding:
 - --spec spec.json: replace/add the dataset's DATASET_DEFAULT_CONFIG entry (our split / converted database);
 - a dump of every evaluated epoch's per-node results (score, y_hat at PIDSMaker's own threshold, y_true) and the
   threshold, written to <dump_dir>/<model_epoch_dir>.pkl by wrapping node_evaluation.get_node_predictions.
Nothing else is changed: PIDSMaker evaluates every second epoch as configured (run_evaluation=each_epoch); we score
the LAST evaluated epoch (no test-based selection) and, for reference only, PIDSMaker's own best_adp pick.
Usage: pm_run.py --dump DIR [--spec spec.json] -- <PIDSMaker main.py args>"""
import json, os, pickle, sys
sys.path.insert(0, "/pids")
i = sys.argv.index("--"); own, rest = sys.argv[1:i], sys.argv[i + 1:]
dump = own[own.index("--dump") + 1]
spec = own[own.index("--spec") + 1] if "--spec" in own else ""
os.makedirs(dump, exist_ok=True)
from pidsmaker.config import config as PC
ds = rest[1]
if spec:
    PC.DATASET_DEFAULT_CONFIG[ds] = json.load(open(spec))
from pidsmaker.detection.evaluation_methods import node_evaluation as NE
for fname in ("get_node_predictions", "get_node_predictions_node_level"):
    orig = getattr(NE, fname)
    def wrapped(val_tw_path, test_tw_path, cfg, _orig=orig, **kw):
        out = _orig(val_tw_path, test_tw_path, cfg, **kw)
        results, thr = out[0], out[1]
        ep = os.path.basename(os.path.normpath(test_tw_path))
        pickle.dump({"thr": float(thr), "results": {int(k): (float(v["score"]), int(v["y_hat"]), int(v["y_true"]))
                                                    for k, v in results.items()}},
                    open(os.path.join(dump, f"{ep}.pkl"), "wb"))
        return out
    setattr(NE, fname, wrapped)
import runpy
sys.argv = ["pidsmaker/main.py"] + rest
os.environ.setdefault("WANDB_MODE", "disabled")
runpy.run_path("/pids/pidsmaker/main.py", run_name="__main__")
