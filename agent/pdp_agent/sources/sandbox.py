"""Sandbox live source: drives real workloads, captures their syscalls with the strace collector, and presents
them to the agent as calendar days so the normal baseline/train/detect pipeline runs on genuine live telemetry.

Each session is a real traced program (sim.pdp_sim.sandbox.workloads). The events are real; only their day label
is assigned by the schedule (the same convenience the DARPA replays use — a capture is tagged with its day).
Baseline days are benign; after a bundle is deployed, the test day(s) add the attack-shaped scenarios, whose
telemetry is scored live on the endpoint exactly like a real intrusion.

Schedule (agent config `source`):
  {"kind": "sandbox", "baseline_days": 3, "sessions_per_day": 4, "scale": 3, "base_date": "2025-01-01",
   "benign": ["build","web","admin","user"], "test_days": [{"attacks": ["dropper","backdoor","exfil","lotl"]}]}
"""
from __future__ import annotations

import os
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator

from pdp_engine.schema import Event

from .strace_src import StraceLive

SESSION_GAP_NS = 20 * 60 * 1_000_000_000      # 20 min between sessions -> separate 15-min detection windows
DAY_NS = 24 * 3600 * 1_000_000_000


class SandboxSource:
    def __init__(self, cfg: dict, state=None):
        self.state = state
        self.baseline_days = int(cfg.get("baseline_days", 3))
        self.sessions_per_day = int(cfg.get("sessions_per_day", 4))
        self.scale = int(cfg.get("scale", 3))
        self.benign = cfg.get("benign", ["build", "web", "admin", "user"])
        self.test_days = cfg.get("test_days", [{"attacks": ["dropper", "backdoor", "exfil", "lotl"]}])
        self.python = cfg.get("python", "python")
        base = cfg.get("base_date", "2025-01-01")
        self.base_ns = int(datetime.strptime(base, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp() * 1e9)
        self.rng = random.Random(cfg.get("seed", 0))
        self.run_root = cfg.get("root", "/var/lib/pdp/sandbox")
        os.makedirs(self.run_root, exist_ok=True)
        self.manifest = cfg.get("manifest", os.path.join(self.run_root, "suite-manifest.json"))
        self.collector = cfg.get("collector", "strace")     # "strace" (ptrace) or "ebpf" (kernel tracer, one for all sessions)
        self.cfg_engine = cfg.get("engine")                 # ebpf engine: "core" (default) or "bcc"
        self._tracer = None

    # ---- one real traced session, timestamps remapped into `day_ns` at `slot` ----
    def _session(self, scenario: str, day_ns: int, slot: int) -> list:
        root = os.path.join(self.run_root, f"d{day_ns}-{slot}-{scenario.replace(':', '-')}")
        os.makedirs(root, exist_ok=True)
        if scenario.startswith("suite:"):       # a client-suite attack emulation; its ground truth goes to the manifest
            cmd = [self.python, "-m", "pdp_sim.suite", "one", scenario.split(":", 1)[1], "--root", root,
                   "--seed", str(self.rng.randrange(1 << 30)), "--manifest", self.manifest, "--fast"]
        else:
            cmd = [self.python, "-m", "pdp_sim.sandbox.workloads", scenario, "--root", root,
                   "--scale", str(self.scale), "--seed", str(self.rng.randrange(1 << 30))]
        if self.collector == "ebpf":
            from .ebpf import EbpfLive, EbpfTracer
            if self._tracer is None:
                self._tracer = EbpfTracer(engine=self.cfg_engine)
            live = EbpfLive(command=cmd, tracer=self._tracer, batch=100000)
        else:
            live = StraceLive(command=cmd, batch=100000)
        raw = []
        stop = lambda: False
        for batch in live.batches(stop):
            raw.extend(batch)
            if live.proc is not None and live.proc.poll() is not None and not batch:
                break
        if not raw:
            return []
        t0 = min(ev.ts_ns for _, ev in raw)
        base = day_ns + slot * SESSION_GAP_NS
        out = []
        for ents, ev in raw:                               # preserve intra-session ordering and spacing
            out.append((ents, Event(base + (ev.ts_ns - t0), ev.src, ev.op, ev.dst, ev.event_uuid)))
        out.sort(key=lambda x: x[1].ts_ns)
        return out

    def _test_plan(self, spec: dict) -> list[str]:
        """Sessions of a test day: benign cover traffic, then the attack-shaped workloads; with `suite`, a randomised
        client-suite campaign ({"scenarios": "all" | "random:N" | "a,b", "repeat": K, "seed": S, "noise": p}) whose
        scenarios run in random order with benign sessions mixed in."""
        plan = list(spec.get("benign", self.benign)) + list(spec.get("attacks", []))
        su = spec.get("suite")
        if su:
            from pdp_sim.suite.__main__ import pick
            rng = random.Random(su.get("seed", 0))
            attacks = [f"suite:{x}" for _ in range(int(su.get("repeat", 1))) for x in pick(su.get("scenarios", "all"), rng)]
            rng.shuffle(attacks)
            mixed = []
            for x in attacks:
                if rng.random() < float(su.get("noise", 0.3)):
                    mixed.append(rng.choice(self.benign))
                mixed.append(x)
            plan = list(spec.get("benign", self.benign)) + mixed
        return plan

    def _day_label(self, day_ns: int) -> str:
        return datetime.fromtimestamp(day_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%d")

    def batches(self, stop: Callable[[], bool]) -> Iterator[list]:
        done = set(self.state.get("sandbox_days_done", [])) if self.state else set()
        # baseline days: benign sessions only
        for k in range(self.baseline_days + 1):            # +1 validation day
            day_ns = self.base_ns + k * DAY_NS
            label = self._day_label(day_ns)
            if label in done or stop():
                continue
            for slot in range(self.sessions_per_day):
                scenario = self.benign[slot % len(self.benign)]
                evs = self._session(scenario, day_ns, slot)
                for i in range(0, len(evs), 2000):
                    yield evs[i:i + 2000]
                    if stop():
                        return
            if self.state:
                self.state.complete_day(label)
                self.state.set("sandbox_days_done", sorted(done | {label})); done.add(label)
            yield []
        # wait for the trained bundle before the test day(s), so attack telemetry is scored live
        while self.state is not None and not self.state.get("bundle_id") and not stop():
            yield []
            time.sleep(5)
        for j, spec in enumerate(self.test_days):
            day_ns = self.base_ns + (self.baseline_days + 1 + j) * DAY_NS
            label = self._day_label(day_ns)
            if label in done or stop():
                continue
            slot = 0
            for scenario in self._test_plan(spec):
                evs = self._session(scenario, day_ns, slot); slot += 1
                for i in range(0, len(evs), 2000):
                    yield evs[i:i + 2000]
            if self.state:
                self.state.complete_day(label)
                self.state.set("sandbox_days_done", sorted(done | {label})); done.add(label)
            yield []
        while not stop():
            yield []
            time.sleep(5)
