"""Run the client attack-emulation suite on an endpoint that has the PDP agent installed.

  python -m pdp_sim.suite list
  python -m pdp_sim.suite run [--scenarios all|random:N|name,name] [--seed S] [--repeat K] [--noise 0.5]
                              [--gap-min 5 --gap-max 60] [--root DIR] [--manifest suite-manifest.json]
  python -m pdp_sim.suite one <scenario> --root DIR --seed S [--manifest FILE] [--fast]

`run` executes the chosen scenarios in a random order with random pauses between them and benign "cover" activity
interleaved (builds, editing, log writes, local web requests), and writes a ground-truth manifest. Score the
endpoint afterwards with
  docker exec pdp-api-1 python -m pdp_server.tools.suite_eval --endpoint <id> --manifest suite-manifest.json
(alerts are reported when the agent's 15-minute detection window closes, so evaluate >= 20 min after the run).
Everything is harmless: see scenarios.py.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import tempfile
import time

from .scenarios import SCENARIOS, run_scenario


def benign_noise(root: str, rng: random.Random):
    from pdp_sim.sandbox.workloads import BENIGN
    name = rng.choice(sorted(BENIGN))
    d = os.path.join(root, f"noise-{name}-{rng.randrange(1 << 30):x}")
    os.makedirs(d, exist_ok=True)
    BENIGN[name](d, 2, rng)
    return name


def append_manifest(path: str, rec: dict):
    data = {"version": 1, "runs": []}
    if os.path.exists(path):
        try:
            data = json.load(open(path))
        except (OSError, ValueError):
            pass
    data["runs"].append(rec)
    tmp = path + ".tmp"
    json.dump(data, open(tmp, "w"), indent=1)
    os.replace(tmp, path)


def pick(spec: str, rng: random.Random) -> list[str]:
    names = sorted(SCENARIOS)
    if spec == "all":
        return names
    if spec.startswith("random:"):
        k = int(spec.split(":", 1)[1])
        return [rng.choice(names) for _ in range(k)] if k > len(names) else rng.sample(names, k)
    bad = [s for s in spec.split(",") if s not in SCENARIOS]
    if bad:
        raise SystemExit(f"unknown scenarios {bad}; see `list`")
    return spec.split(",")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m pdp_sim.suite")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    r = sub.add_parser("run")
    r.add_argument("--scenarios", default="all"); r.add_argument("--seed", type=int, default=None)
    r.add_argument("--repeat", type=int, default=1); r.add_argument("--noise", type=float, default=0.5)
    r.add_argument("--gap-min", type=float, default=5); r.add_argument("--gap-max", type=float, default=60)
    r.add_argument("--root", default=None); r.add_argument("--manifest", default="suite-manifest.json")
    r.add_argument("--fast", action="store_true")
    o = sub.add_parser("one")
    o.add_argument("scenario", choices=sorted(SCENARIOS)); o.add_argument("--root", required=True)
    o.add_argument("--seed", type=int, default=0); o.add_argument("--manifest"); o.add_argument("--fast", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "list":
        for n, (fn, tactic, tech) in sorted(SCENARIOS.items()):
            print(f"{n:24s} {tactic:26s} {','.join(tech):34s} {fn.__doc__.split(':', 1)[1].strip().splitlines()[0][:70]}")
        return
    if a.cmd == "one":
        rec = run_scenario(a.scenario, a.root, a.seed, fast=a.fast)
        if a.manifest:
            append_manifest(a.manifest, rec)
        print(json.dumps({k: rec[k] for k in ("scenario", "markers")}))
        return

    seed = a.seed if a.seed is not None else random.SystemRandom().randrange(1 << 31)
    rng = random.Random(seed)
    base = a.root or tempfile.mkdtemp(prefix="pdp-suite-")
    plan = [s for _ in range(a.repeat) for s in pick(a.scenarios, rng)]
    rng.shuffle(plan)
    meta = {"version": 1, "host": socket.gethostname(), "seed": seed, "plan": plan, "started_ns": time.time_ns(), "runs": [], "noise": []}
    print(f"suite seed {seed}: {len(plan)} scenarios in {base}", flush=True)
    for i, sc in enumerate(plan):
        if rng.random() < a.noise:
            meta["noise"].append({"workload": benign_noise(base, rng), "ns": time.time_ns()})
        root = os.path.join(base, f"{i:03d}-{rng.randrange(1 << 40):010x}")
        rec = run_scenario(sc, root, rng.randrange(1 << 31), fast=a.fast)
        meta["runs"].append(rec)
        print(f"  [{i + 1}/{len(plan)}] {sc:24s} markers={len(rec['markers'])}", flush=True)
        json.dump(meta, open(a.manifest, "w"), indent=1)
        if i < len(plan) - 1:
            time.sleep(rng.uniform(a.gap_min, a.gap_max))
    meta["finished_ns"] = time.time_ns()
    json.dump(meta, open(a.manifest, "w"), indent=1)
    print(f"manifest: {os.path.abspath(a.manifest)}")


if __name__ == "__main__":
    main()
