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
    # PIDSMaker picks the relation vocabulary by dataset NAME. Converted lab hosts (conv_store.py) use the DARPA TC
    # vocabulary, so their (new) names are registered as TC datasets.
    from pidsmaker.utils import dataset_utils as DU
    if ds not in DU.DARPA_TC_DATASETS and ds.startswith("TCFMT_"):
        DU.DARPA_TC_DATASETS.add(ds)
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
        # disk: drop the per-edge score table PIDSMaker would pickle next to the figures (not used by any metric)
        return (out[0], out[1], None) + tuple(out[3:]) if len(out) >= 3 else out
    setattr(NE, fname, wrapped)
# Disk: PIDSMaker writes several large figures per evaluated epoch (~150 MB/epoch on FiveDirections). They do not
# affect any number, so they are replaced by no-ops (the ADP function, which also draws, is kept).
for fname in ("plot_scores_with_paths_node_level", "plot_scores_neat", "plot_scores_distribution",
              "plot_discrimination_metric"):
    if hasattr(NE, fname):
        setattr(NE, fname, lambda *a, **k: None)
# Headline = last evaluated epoch only (PROTOCOL amendment 05:55): evaluate just that epoch, so pruning older epochs'
# edge losses can never race with the evaluation's directory listing.
from pidsmaker.tasks import evaluation as EV
_orig_lds = EV.listdir_sorted
def _last_only(path):
    files = _orig_lds(path)
    ep = [f for f in files if f.startswith("model_epoch_")]
    return [max(ep, key=lambda f: int(f.split("_")[-1]))] if ep else files
EV.listdir_sorted = _last_only
import runpy
sys.argv = ["pidsmaker/main.py"] + rest
os.environ.setdefault("WANDB_MODE", "disabled")
runpy.run_path("/pids/pidsmaker/main.py", run_name="__main__")
