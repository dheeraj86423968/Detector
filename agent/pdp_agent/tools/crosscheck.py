"""Collector cross-check: run the same workloads under two collectors and compare the normalised event streams
(docs/DEPLOYMENT.md §1: "this proves the eBPF mapping is correct on a real kernel").

  python -m pdp_agent.tools.crosscheck [--compare strace,ebpf] [--scenarios syscalls,build,web,...] [--json out.json]

--compare picks the two collectors: `strace`, `ebpf` (the default eBPF engine), `core` (libbpf CO-RE) or `bcc`.
* strace vs an eBPF engine: each scenario runs once per collector in a fresh scratch directory at the same path with
  the same seed. Timing-dependent noise (e.g. a library probed by the dynamic loader in one run only) shows up as a
  small non-overlap; a mapping bug shows up as a missing edge class. The eBPF side's socket-data (SOCKIO) records
  are left out here: strace does not trace read/write/send/recv on connected sockets.
* two eBPF engines (`--compare bcc,core`): both kernel programs are attached at once and each scenario runs ONCE, so
  both engines see the very same syscalls. Compared: the raw kernel records (every field but the timestamp, as
  multisets) - exact equality is expected - and the provenance edges (op, src type+label, dst type+label), where
  only /proc lookups at decode time (cwd of an already-exited process) can differ.
The comparison is on (op, src label, dst label) edges, which is what the featuriser and the detectors see.
Needs strace + CAP_SYS_PTRACE and the eBPF requirements of the engines compared (see sources/ebpf.py).
Scenario `syscalls` is tools/syscall_workload.py; the others are pdp_sim.sandbox.workloads.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter

from pdp_agent.sources.ebpf import FORK, EbpfLive, EbpfTracer
from pdp_agent.sources.strace_src import StraceLive

DEFAULT = ["syscalls", "build", "web", "admin", "user", "dropper", "backdoor", "exfil", "lotl"]


def command(sc: str, root: str, scale: int) -> list[str]:
    if sc == "syscalls":
        return [sys.executable, "-m", "pdp_agent.tools.syscall_workload", "--root", root]
    return [sys.executable, "-m", "pdp_sim.sandbox.workloads", sc, "--root", root, "--scale", str(scale), "--seed", "7"]


def run(live) -> list:
    out = []
    for b in live.batches(lambda: False):
        out.extend(b)
    return out


def edges(evs) -> Counter:
    return Counter((e.op, ents[0].label, ents[1].label) for ents, e in evs)


def typed_edges(evs) -> Counter:
    return Counter((e.op, ents[0].ntype, ents[0].label, ents[1].ntype, ents[1].label) for ents, e in evs)


def rec_key(r) -> tuple:
    return (r.kind, r.pid, r.tid, r.aux, r.ret, r.flags, r.dirfd, r.family, r.port, r.addr, r.s, r.raw)


def run_simultaneous(cmd: list[str], tracers: dict) -> dict:
    """One run of `cmd` observed by several attached tracers: {engine: (records, events)} for its process tree."""
    lives = {k: EbpfLive(tracer=t, batch=10**9) for k, t in tracers.items()}
    for t in tracers.values():                       # discard anything recorded before the workload starts
        t.poll(0)
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    track = {k: {proc.pid} for k in tracers}
    recs = {k: [] for k in tracers}
    evs = {k: [] for k in tracers}

    def step(timeout_ms):
        for k, t in tracers.items():
            got = []
            for r in t.poll(timeout_ms):
                if r.kind == FORK:
                    if r.pid not in track[k]:
                        continue
                    track[k].add(r.aux)
                elif r.pid not in track[k]:
                    continue
                got.append(r)
            recs[k].extend(got)
            evs[k].extend(lives[k]._decode(got, None))   # already filtered to the workload's tree
    while proc.poll() is None:
        step(20)
    end = time.time() + 0.5                           # records still in flight when the workload exited
    while time.time() < end:
        step(50)
    return {k: (recs[k], evs[k]) for k in tracers}


def compare(a: Counter, b: Counter) -> dict:
    sa, sb = set(a), set(b)
    return {"n_a": sum(a.values()), "n_b": sum(b.values()), "distinct_jaccard": round(len(sa & sb) / max(1, len(sa | sb)), 4),
            "multiset_equal": a == b, "only_a": sorted(str(x)[:160] for x in (a - b).elements())[:8],
            "only_b": sorted(str(x)[:160] for x in (b - a).elements())[:8]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compare", default="strace,ebpf", help="two of: strace, ebpf, core, bcc")
    ap.add_argument("--scenarios", default=",".join(DEFAULT))
    ap.add_argument("--root", default="/tmp/pdp-crosscheck")
    ap.add_argument("--scale", type=int, default=2)
    ap.add_argument("--json")
    a = ap.parse_args()
    A, B = a.compare.split(",")
    engine = {"ebpf": None, "core": "core", "bcc": "bcc"}
    rows = []
    if A in engine and B in engine:                  # two eBPF engines, attached at the same time
        tracers = {A: EbpfTracer(engine=engine[A]), B: EbpfTracer(engine=engine[B])}
        print(f"startup: {A} {tracers[A].startup_s:.3f}s  {B} {tracers[B].startup_s:.3f}s", flush=True)
        tot = {"rec": [Counter(), Counter()], "edge": [Counter(), Counter()]}
        for sc in a.scenarios.split(","):
            shutil.rmtree(a.root, ignore_errors=True); os.makedirs(a.root)
            res = run_simultaneous(command(sc, a.root, a.scale), tracers)
            rc = [Counter(rec_key(r) for r in res[k][0]) for k in (A, B)]
            ec = [typed_edges(res[k][1]) for k in (A, B)]
            for i in (0, 1):
                tot["rec"][i].update(rc[i]); tot["edge"][i].update(ec[i])
            row = {"scenario": sc, "records": compare(*rc), "edges": compare(*ec),
                   "ops": [dict(Counter(e[0] for e in c.elements())) for c in ec]}
            rows.append(row)
            print(f"{sc:9s} records {A} {row['records']['n_a']:6d} {B} {row['records']['n_b']:6d} identical "
                  f"{row['records']['multiset_equal']!s:5s} | edges {A} {row['edges']['n_a']:6d} {B} {row['edges']['n_b']:6d} "
                  f"identical {row['edges']['multiset_equal']!s:5s} distinct-edge Jaccard {row['edges']['distinct_jaccard']:.4f}", flush=True)
        summary = {"records": compare(*tot["rec"]), "edges": compare(*tot["edge"]),
                   "edge_classes": [sorted({e[0] for e in c}) for c in tot["edge"]],
                   "lost": {k: t.stats.get("lost", 0) for k, t in tracers.items()}}
        for t in tracers.values():
            t.close()
    else:                                            # strace vs an eBPF engine: one run per collector
        tracer = EbpfTracer(engine=engine.get(B if A == "strace" else A))
        total = {A: Counter(), B: Counter()}
        for sc in a.scenarios.split(","):
            res = {}
            for name in (A, B):
                shutil.rmtree(a.root, ignore_errors=True); os.makedirs(a.root)
                cmd = command(sc, a.root, a.scale)
                # strace does not trace data on connected sockets (read/write/send/recv without an address): the eBPF
                # side's SOCKIO records are left out of this comparison (--compare bcc,core compares them)
                live = (StraceLive(command=cmd, batch=10**9) if name == "strace"
                        else EbpfLive(command=cmd, tracer=tracer, batch=10**9, socket_data=False))
                res[name] = edges(run(live))
                total[name].update(res[name])
            row = {"scenario": sc, **compare(res[A], res[B]),
                   "ops": [dict(Counter(op for op, _, _ in res[k].elements())) for k in (A, B)]}
            rows.append(row)
            print(f"{sc:9s} edges {A} {row['n_a']:5d}  {B} {row['n_b']:5d}  distinct-edge Jaccard {row['distinct_jaccard']:.3f}", flush=True)
        summary = {**compare(total[A], total[B]), "edge_classes": [sorted({op for op, _, _ in total[k]}) for k in (A, B)]}
        tracer.close()
    print(json.dumps({k: v for k, v in summary.items() if k not in ("only_a", "only_b")}, default=str))
    for r in rows:
        d = r.get("edges", r)
        if d["only_a"] or d["only_b"]:
            print(f"-- {r['scenario']}: only {A} {d['only_a'][:4]}  only {B} {d['only_b'][:4]}")
    if a.json:
        json.dump({"compare": [A, B], "rows": rows, "summary": summary}, open(a.json, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
