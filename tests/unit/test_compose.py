"""Deployment wiring: every worker that builds models signs bundles, so it needs the KMS settings and token when
PDP_KMS=transit (the ingest worker, which builds the early rules-only models, lacked them: every early model failed)."""
import os
import sys

import yaml

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


dc = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "../../deploy/docker-compose.yml")))
signers = {n: s for n, s in dc["services"].items() if any(k in " ".join(map(str, s.get("command") or [])) for k in ("train", "train_rules"))}
check({"worker-train", "worker-ingest"} <= set(signers), f"model-building workers found: {sorted(signers)}")
for n, s in signers.items():
    env = s.get("environment") or {}
    vols = " ".join(map(str, s.get("volumes") or []))
    check("PDP_KMS" in env and "PDP_KMS_ADDR" in env and "/run/pdp-kms" in vols, f"{n} has the KMS settings and token (it signs bundles)")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
