"""Exploration (CPU, before any protocol): the unusual_network alarm on the recorded test data and on the LotL
counterfactual (lotl_paper/scripts/lotl.py: the attacker's new programs relabelled as baseline programs).
Layers: the bundle's configuration + rule_key_norm, rule_backslash_paths, version_names, net_profile, re-fitted
on fit_days. No learned detector. Usage: explore_net.py SET"""
import copy, dataclasses, json, sys
from collections import Counter
import numpy as np
from pdp_engine.layers import DeterministicLayers, LayerConfig, TagParams, fit_layers
import lotl
from common8 import Set
BUNDLE = {s: "b07rel" for s in [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)] + ["THEIA_E5-theia"]}
name = sys.argv[1]; S = Set(name)
bdir = f"{S.work}/{BUNDLE.get(name, 'v07rel')}"
spec0 = json.load(open(f"{bdir}/layers.json")); N = json.load(open(f"{bdir}/manifest.json"))["num_nodes"]
c = dict(spec0["config"]); c.pop("sigma", None)
fields = {f.name for f in dataclasses.fields(LayerConfig)}
base = {k: v for k, v in c.items() if k in fields and k != "tags"}; base["evidence_rules"] = tuple(base.get("evidence_rules", ()))
cfg = LayerConfig(**{**base, "rule_key_norm": True, "rule_backslash_paths": True, "version_names": True, "net_profile": True,
                     "tags": TagParams(**c.get("tags", {})), "sigma_fit_levels": (), "sigma_levels": ()})
bst = S.base_store(); breg = bst.load_registry()
spec = fit_layers(bst, spec0["fit_days"], breg, N, cfg, log=lambda m: None)
json.dump(spec, open(f"out/layersnet-{name}.json", "w"))
out = {"set": name, "benign_net_programs": len(spec["thresholds"].get("unusual_network", {}))}
st = S.eval_store()
for tr in ("none", "lotl"):
    reg = st.load_registry()
    if tr == "lotl":
        if not S.allgt:
            continue
        tn = set()
        for d in S.test_days:
            for w in st.windows(d):
                tn.update(w.nodes().tolist())
        relabel, rep = lotl.build(S, reg, bdir, N, tn)
        lotl.apply(reg, relabel)
        out["lotl_renamed"] = rep.get("renamed_nodes")
    L = DeterministicLayers(copy.deepcopy(spec), N); ents = reg.entities
    seen = {}; att = set(); allr = Counter(); att_any = set()
    for d in S.test_days:
        for w in st.windows(d):
            for h in L.process(w, reg, w.nodes()):
                gt = [ents[n].uuid in S.allgt for n in h.nodes]
                if h.rule not in ("novel_executable_repeat", "tainted_spawn", "tainted_modify") and any(gt):
                    att_any.update(k for n in h.nodes for k, v in S.gt.items() if ents[n].uuid in v)
                if h.rule == "unusual_network":
                    n = h.nodes[0]
                    if n not in seen:
                        seen[n] = (ents[n].uuid in S.allgt, h.key)
                    att.update(k for n_ in h.nodes for k, v in S.gt.items() if ents[n_].uuid in v)
    tp = sum(1 for g, _ in seen.values() if g); fp = len(seen) - tp
    keys_fp = Counter(k[-50:] for g, k in seen.values() if not g); keys_tp = Counter(k[-50:] for g, k in seen.values() if g)
    out[tr] = {"proc_TP": tp, "proc_FP": fp, "distinct_fp_programs": len(keys_fp), "attacks_touched": sorted(att),
               "attacks_any_rule": sorted(att_any), "top_fp": keys_fp.most_common(8), "top_tp": keys_tp.most_common(6)}
print(json.dumps(out))
