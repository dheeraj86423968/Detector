"""Lab 0.17 prep (net_profile fitted; the alarm is switched per variant at scoring time): re-fit one set's deterministic layers (fit_layers, the bundle's fit_days and configuration, Sigma
off) under each variant. Usage: prep17.py SET -> out/layers20-SET-<variant>.json, out/prep20-SET.json"""
import dataclasses, json, sys, time
from pdp_engine.layers import LayerConfig, TagParams, fit_layers
from common8 import Set, log
BUNDLE = {s: "b07rel" for s in [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)] + ["THEIA_E5-theia"]}
VARIANTS = {"RN": {"net_profile": True},
            "NN": {"rule_key_norm": True, "rule_backslash_paths": True, "version_names": True, "net_profile": True}}
name = sys.argv[1]
S = Set(name)
bdir = f"{S.work}/{BUNDLE.get(name, 'v07rel')}"
spec = json.load(open(f"{bdir}/layers.json")); man = json.load(open(f"{bdir}/manifest.json"))
c = dict(spec["config"]); c.pop("sigma", None)
fields = {f.name for f in dataclasses.fields(LayerConfig)}
base = {k: v for k, v in c.items() if k in fields and k != "tags"}
base["evidence_rules"] = tuple(base.get("evidence_rules", ()))
bst = S.base_store(); breg = bst.load_registry()
summary = {"set": name, "fit_days": spec["fit_days"]}
for v, opt in VARIANTS.items():
    t = time.time()
    cfg = LayerConfig(**{**base, **opt, "tags": TagParams(**c.get("tags", {})), "sigma_fit_levels": (), "sigma_levels": ()})
    out = fit_layers(bst, spec["fit_days"], breg, int(man["num_nodes"]), cfg, log=lambda m: None)
    json.dump(out, open(f"out/layers20-{name}-{v}.json", "w"))
    nthr = {r: len(kv) for r, kv in out["thresholds"].items()}
    summary[v] = {"known": len(out["known_executables"]), "trusted_ips": len(out["trusted_ips"]), "thresholds": nthr,
                  "private_services": len(out["private_services"]), "seconds": round(time.time() - t)}
    if v == "RN":
        same = {k: out.get(k) == spec.get(k) for k in ("known_executables", "trusted_ips", "thresholds", "private_services")}
        summary["RN_equals_released"] = same
        log(f"{name} RN equals released (thresholds differ by the new alarm's keys): {same}")
    log(f"{name} {v}: {summary[v]}")
json.dump(summary, open(f"out/prep20-{name}.json", "w"), indent=1)
