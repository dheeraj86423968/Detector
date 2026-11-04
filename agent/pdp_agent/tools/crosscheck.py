"""Collector cross-check: run the same workloads under the strace collector and the eBPF collector and compare the
normalised event streams (docs/DEPLOYMENT.md §1: "this proves the eBPF mapping is correct on a real kernel").

  python -m pdp_agent.tools.crosscheck [--scenarios build,web,admin,user,dropper,backdoor,exfil,lotl] [--json out.json]

Needs strace + CAP_SYS_PTRACE and the eBPF requirements (see sources/ebpf.py). Each scenario runs once per collector
in a fresh scratch directory at the same path with the same seed; the comparison is on (op, src label, dst label)
edges, which is what the featuriser and the detectors see. Timing-dependent noise (e.g. a library probed by the
dynamic loader in one run only) shows up as a small non-overlap; a mapping bug shows up as a missing edge class.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections import Counter

from pdp_agent.sources.ebpf import EbpfLive, EbpfTracer
from pdp_agent.sources.strace_src import StraceLive

DEFAULT = ["build", "web", "admin", "user", "dropper", "backdoor", "exfil", "lotl"]


def run(live) -> list:
    out = []
    for b in live.batches(lambda: False):
        out.extend(b)
    return out


def edges(evs) -> Counter:
    return Counter((e.op, ents[0].label, ents[1].label) for ents, e in evs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default=",".join(DEFAULT))
    ap.add_argument("--root", default="/tmp/pdp-crosscheck")
    ap.add_argument("--scale", type=int, default=2)
    ap.add_argument("--json")
    a = ap.parse_args()
    tracer = EbpfTracer()
    rows, total = [], {"strace": Counter(), "ebpf": Counter()}
    for sc in a.scenarios.split(","):
        res = {}
        for name in ("strace", "ebpf"):
            shutil.rmtree(a.root, ignore_errors=True); os.makedirs(a.root)
            cmd = [sys.executable, "-m", "pdp_sim.sandbox.workloads", sc, "--root", a.root, "--scale", str(a.scale), "--seed", "7"]
            live = StraceLive(command=cmd, batch=10**9) if name == "strace" else EbpfLive(command=cmd, tracer=tracer, batch=10**9)
            res[name] = edges(run(live))
            total[name].update(res[name])
        s, b = set(res["strace"]), set(res["ebpf"])
        ops_s = Counter(op for op, _, _ in res["strace"].elements()); ops_b = Counter(op for op, _, _ in res["ebpf"].elements())
        jac = len(s & b) / max(1, len(s | b))
        rows.append({"scenario": sc, "edges_strace": sum(res["strace"].values()), "edges_ebpf": sum(res["ebpf"].values()),
                     "distinct_jaccard": round(jac, 3), "ops_strace": dict(ops_s), "ops_ebpf": dict(ops_b),
                     "only_strace": sorted(f"{o} {x[:60]} -> {y[:60]}" for o, x, y in s - b)[:8],
                     "only_ebpf": sorted(f"{o} {x[:60]} -> {y[:60]}" for o, x, y in b - s)[:8]})
        print(f"{sc:9s} edges strace {rows[-1]['edges_strace']:5d}  ebpf {rows[-1]['edges_ebpf']:5d}  distinct-edge Jaccard {jac:.3f}", flush=True)
    s, b = set(total["strace"]), set(total["ebpf"])
    summary = {"distinct_jaccard": round(len(s & b) / max(1, len(s | b)), 3),
               "edge_classes_strace": sorted({op for op, _, _ in s}), "edge_classes_ebpf": sorted({op for op, _, _ in b})}
    print(json.dumps(summary))
    for r in rows:
        if r["only_strace"] or r["only_ebpf"]:
            print(f"-- {r['scenario']}: only strace {r['only_strace'][:4]}  only ebpf {r['only_ebpf'][:4]}")
    if a.json:
        json.dump({"rows": rows, "summary": summary}, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
