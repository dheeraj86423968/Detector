"""Run ProvFusion's main_transductive.main() unchanged for one dataset/seed, in a run directory (cwd) that holds
configs.yml (ProvFusion's, plus an entry for a new dataset that copies the entry every provenance dataset uses) and
<DS>_attack_to_nids.pt. For a dataset not in configs/dataset_weights.DATASET_WEIGHTS, --weights gives its 11 loss
weights (rule in PROTOCOL.md). All other arguments are passed to ProvFusion's own argument parser.
Usage: pf_train.py --rundir R [--weights w0,...,w10] -- <main_transductive.py args>"""
import os, shutil, sys, json
sys.path.insert(0, "/pf")
i = sys.argv.index("--")
own, rest = sys.argv[1:i], sys.argv[i + 1:]
rundir = own[own.index("--rundir") + 1]
weights = own[own.index("--weights") + 1] if "--weights" in own else ""
os.makedirs(rundir, exist_ok=True); os.chdir(rundir)
import yaml
cfgs = yaml.safe_load(open("/pf/configs.yml"))
ds = rest[rest.index("--dataset") + 1]
if ds not in cfgs:
    cfgs[ds] = dict(cfgs["CADETS_E3"])   # identical for all nine provenance datasets
yaml.safe_dump(cfgs, open("configs.yml", "w"))
import configs.dataset_weights as DW
if weights:
    DW.DATASET_WEIGHTS[ds] = [float(x) for x in weights.split(",")]
sys.argv = ["main_transductive.py"] + rest
import main_transductive as M
from graphmae.utils import build_args, load_best_configs
args = build_args()
if args.use_cfg:
    args = load_best_configs(args, "configs.yml")
print("ARGS", json.dumps(vars(args), default=str), flush=True)
M.main(args)
