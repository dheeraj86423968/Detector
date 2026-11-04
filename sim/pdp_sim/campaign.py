"""Campaign planning, execution and metrics."""
from __future__ import annotations

import hashlib
import json
import math
import os
import random
import time
from dataclasses import dataclass, field

import numpy as np

from pdp_engine.data import WindowStore
from pdp_engine.runtime import Runtime
from pdp_engine.schema import Registry
from pdp_engine.scoring import above

from . import attacks, evasion, transplant
from .inject import LabelIndex, Placement, bind, inject

DEFAULT_FAMILIES = list(attacks.FAMILIES)
DEFAULT_LEVELS = ["none", "low", "medium", "high"]


@dataclass
class Spec:
    days: list[str]                       # days of the window store to simulate on ("validation" = last store day)
    runs: int = 40                        # number of attacks
    attacks_per_pass: int = 3             # attacks injected into one scoring pass of a day (spaced apart)
    families: list = field(default_factory=lambda: list(DEFAULT_FAMILIES))
    evasion_levels: list = field(default_factory=lambda: list(DEFAULT_LEVELS))
    seed: int = 0
    horizon_windows: int = 8              # windows after the attack start in which a detection still counts
    transplant_dir: str = ""
    fp_budget: str | None = None          # None = validation-max thresholds, else percentile key ("99.9")

    @staticmethod
    def from_dict(d: dict) -> "Spec":
        known = {k: v for k, v in d.items() if k in Spec.__dataclass_fields__}
        return Spec(**known)

    def hash(self) -> str:
        d = {k: getattr(self, k) for k in self.__dataclass_fields__ if k not in ("seed",)}
        return hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()[:16]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, c - h), min(1.0, c + h))


def bootstrap_median(xs: list[float], rng: random.Random, n: int = 1000) -> tuple[float, float] | None:
    if not xs:
        return None
    meds = []
    for _ in range(n):
        s = [rng.choice(xs) for _ in xs]
        meds.append(float(np.median(s)))
    return (float(np.percentile(meds, 2.5)), float(np.percentile(meds, 97.5)))


class Campaign:
    def __init__(self, spec: Spec, store: WindowStore, bundle_dir: str, device: str = "cpu", log=print):
        self.spec, self.store, self.bundle_dir, self.device, self.log = spec, store, bundle_dir, device, log
        self.base_reg = store.load_registry()
        self.rt = Runtime(bundle_dir, self.base_reg, device=device, fp_budget=spec.fp_budget)
        days = store.days()
        val_day = self.rt.m.get("val_day") or days[-1]     # the bundle's validation day, not merely the last stored day
        self.val_day = val_day
        self.days = [val_day if d == "validation" else d for d in spec.days]
        if val_day in self.days and not self.rt.has_validation_state:
            log(f"warning: bundle has no validation-start state; the validation day {val_day} is scored from the deployed (end) state and is not a clean calibration replay")
        for d in self.days:
            if d not in days:
                raise RuntimeError(f"day {d} not in window store {store.root}")
        self._cache: dict[str, list] = {}
        self.ctx = self._context()

    # ---- context sampled from the endpoint's own baseline ----
    def _context(self):
        from collections import Counter
        rng = random.Random(self.spec.seed)
        reg = self.base_reg
        pc = Counter(e.label for e in reg.entities if e.ntype == "subject")
        procs = [lab for lab, _ in pc.most_common(200) if "None None" not in lab]
        files = [e.label.split(" ", 1)[1] for e in reg.entities if e.ntype == "file" and e.label != "file None"]
        rng.shuffle(files)
        ips = list({e.label.split()[1] for e in reg.entities if e.ntype == "netflow"})[:500]
        subj = [e.label for e in reg.entities if e.ntype == "subject"]
        exe_none = subj and sum(1 for l in subj if l.startswith("subject None ")) > 0.5 * len(subj)
        # files each benign process label touches on the first simulated day (mimicry source)
        from collections import defaultdict
        pf: dict[str, set] = defaultdict(set)
        for w in self.windows(self.days[0]):
            for a, b in zip(w.src.tolist(), w.dst.tolist()):
                ea, eb = reg[a], reg[b]
                if ea.ntype == "subject" and eb.ntype == "file":
                    pf[ea.label].add(eb.label.split(" ", 1)[1])
                elif eb.ntype == "subject" and ea.ntype == "file":
                    pf[eb.label].add(ea.label.split(" ", 1)[1])
        proc_files = {k: sorted(v)[:2000] for k, v in pf.items()}
        return attacks.Ctx(rng, procs, files[:20000], ips, exe_none=bool(exe_none), proc_files=proc_files)

    def windows(self, day: str) -> list:
        if day not in self._cache:
            self._cache[day] = list(self.store.windows(day))
        return self._cache[day]

    # ---- planning ----
    def plan(self) -> list[dict]:
        """Balanced random design: every (family, evasion) cell gets about the same number of runs; attacks are
        grouped into passes per day with placements at least horizon_windows apart."""
        rng = random.Random(self.spec.seed)
        cells = [(f, l) for f in self.spec.families for l in self.spec.evasion_levels]
        draws = []
        while len(draws) < self.spec.runs:
            c = cells[:]; rng.shuffle(c); draws.extend(c)
        draws = draws[: self.spec.runs]
        passes, k, gap = [], self.spec.attacks_per_pass, self.spec.horizon_windows + 1
        for i in range(0, len(draws), k):
            group = draws[i: i + k]
            day = rng.choice(self.days)
            n = len(self.windows(day))
            usable = list(range(1, max(2, n - 2)))
            slots = []
            for _ in range(50):
                cand = sorted(rng.sample(usable, min(len(group), len(usable))))
                if all(b - a >= gap for a, b in zip(cand, cand[1:])):
                    slots = cand; break
            if not slots:
                slots = sorted(rng.sample(usable, min(len(group), len(usable))))
            passes.append({"day": day, "attacks": [{"family": f, "evasion": l, "window_index": s, "seed": rng.getrandbits(32)} for (f, l), s in zip(group, slots)]})
        return passes

    # ---- execution ----
    def build(self, a: dict, windows: list, reg: Registry, index: LabelIndex, run_tag: str) -> tuple[Placement, attacks.AttackGraph]:
        rng = random.Random(a["seed"])
        fam = a["family"]
        if fam.startswith("transplant:"):
            g = transplant.load(os.path.join(self.spec.transplant_dir, fam.split(":", 1)[1] + ".json"))
        else:
            g = attacks.generate(fam, rng, self.ctx)
        evasion.apply(g, a["evasion"], rng, self.ctx)
        w = windows[a["window_index"]]
        p = Placement(a["day"], a["window_index"], rng.randint(int(w.start_ns), int(max(w.start_ns, w.end_ns - 1))))
        bind(g, reg, index, w, p, rng, run_tag, day_windows=windows)
        return p, g

    def score_day(self, day: str, windows: list, reg: Registry, attacks_: list[tuple[Placement, dict]] | None = None) -> dict:
        """One pass over a day from fresh runtime state. Returns per-window alert sets and, per attack, the detection record."""
        self.rt.reset(reg, at="validation" if day == self.val_day else "end")
        per_attack = []
        if attacks_:
            for p, a in attacks_:
                per_attack.append({"p": p, "first": {"fused": None, "d1": None, "d2": None}, "max": {"fused": 0.0, "r1": 0.0, "r2": 0.0},
                                   "seen": set(), "flagged": set(), "flag_labels": [], "collateral": 0})
        alerts_by_window = []
        for i, w in enumerate(windows):
            r = self.rt.score(w)
            alerted = set(int(x) for x in r.alerts)
            alerts_by_window.append(alerted)
            if not attacks_:
                continue
            pos = {int(n): j for j, n in enumerate(r.node_ids)}
            for rec in per_attack:
                p = rec["p"]
                if i < p.window_index or i > p.window_index + self.spec.horizon_windows:
                    continue
                hit = [pos[m] for m in p.malicious_ids if m in pos]
                if not hit:
                    continue
                rec["seen"].update(m for m in p.malicious_ids if m in pos)
                f, r1, r2 = r.fused[hit], r.r1[hit], r.r2[hit]
                rec["max"] = {"fused": max(rec["max"]["fused"], float(f.max())), "r1": max(rec["max"]["r1"], float(r1.max())), "r2": max(rec["max"]["r2"], float(r2.max()))}
                # "fused" = the product's verdict: a malicious node among the window's alerts (all layers; for
                # pre-0.3 bundles exactly the fused score above its threshold); d1 / d2 = each detector alone
                fl = [m for m in p.malicious_ids if m in pos and m in alerted]
                if rec["first"]["fused"] is None and fl:
                    rec["first"]["fused"] = (i, int(w.end_ns))
                for key, arr in (("d1", r1), ("d2", r2)):
                    if rec["first"][key] is None and bool(above(arr).any()):
                        rec["first"][key] = (i, int(w.end_ns))
                for m in fl:
                    if m not in rec["flagged"]:
                        rec["flagged"].add(m); rec["flag_labels"].append(reg[m].label[:80])
        return {"alerts": alerts_by_window, "attacks": per_attack}

    def run(self, on_result=None) -> dict:
        t0 = time.time()
        passes = self.plan()
        clean: dict[str, dict] = {}
        for day in self.days:
            ws = self.windows(day)
            self.log(f"clean pass {day}: {len(ws)} windows")
            res = self.score_day(day, ws, self._copy_registry())
            nodes = set().union(*res["alerts"]) if res["alerts"] else set()
            clean[day] = {"alerts": res["alerts"], "windows": len(ws), "alert_nodes": len(nodes), "alert_windows": sum(1 for a in res["alerts"] if a)}
            self.log(f"clean pass {day}: {len(nodes)} alerted nodes in {clean[day]['alert_windows']} windows")
        results, run_index = [], 0
        for pi, ps in enumerate(passes):
            day, ws = ps["day"], self.windows(ps["day"])
            reg = self._copy_registry()
            index = LabelIndex(reg)
            placed, graphs = [], []
            for a in ps["attacks"]:
                a = dict(a, day=day)
                p, g = self.build(a, ws, reg, index, f"{pi}-{a['window_index']}")
                placed.append((p, a)); graphs.append(g)
            edges = [e for p, _ in placed for e in p.edges]
            rebuilt = inject(ws, edges)
            ws2 = [rebuilt.get(i, w) for i, w in enumerate(ws)]
            res = self.score_day(day, ws2, reg, placed)
            # collateral false positives: alerted benign nodes that the clean pass did not alert in the same window
            touched = {x for p, _ in placed for e in p.edges for x in (e[0], e[1])}   # every node an injected edge touches
            coll = sum(len((a - touched) - c) for a, c in zip(res["alerts"], clean[day]["alerts"]))
            for (p, a), g, rec in zip(placed, graphs, res["attacks"]):
                seen = len(rec["seen"])
                def ttd(key):
                    x = rec["first"][key]
                    return None if x is None else max(0.0, (x[1] - p.start_ns) / 1e9)
                row = {"run_index": run_index, "pass": pi,
                       "attack": {"family": a["family"], "evasion": a["evasion"], "day": day, "window_index": p.window_index, "start_ns": p.start_ns,
                                  "host": {"id": p.host, "label": p.host_label}, "n_new_nodes": len(p.new_ids), "n_malicious": len(p.malicious_ids),
                                  "n_edges": len(p.edges), "bound_context": p.bound_context, "params": g.params},
                       "result": {"detected": {k: rec["first"][k] is not None for k in ("fused", "d1", "d2")},
                                  "ttd_s": {k: ttd(k) for k in ("fused", "d1", "d2")},
                                  "windows_to_detect": None if rec["first"]["fused"] is None else rec["first"]["fused"][0] - p.window_index + 1,
                                  "node_recall": (len(rec["flagged"]) / seen) if seen else 0.0, "malicious_seen": seen,
                                  "max": rec["max"], "flagged_labels": rec["flag_labels"][:20], "collateral_fp_pass": coll}}
                results.append(row); run_index += 1
                if on_result:
                    on_result(row)
            self.log(f"pass {pi + 1}/{len(passes)} {day}: " + ", ".join(f"{r['attack']['family']}/{r['attack']['evasion']}={'HIT' if r['result']['detected']['fused'] else 'miss'}" for r in results[-len(placed):]))
        summary = summarise(results, clean, self.spec, random.Random(self.spec.seed))
        summary["elapsed_s"] = time.time() - t0
        summary["spec_hash"] = self.spec.hash()
        return {"spec": self.spec.__dict__, "plan": passes, "clean": {d: {k: v for k, v in c.items() if k != "alerts"} for d, c in clean.items()},
                "results": results, "summary": summary}

    def _copy_registry(self) -> Registry:
        r = Registry()
        r.entities = list(self.base_reg.entities)
        r.ids = dict(self.base_reg.ids)
        return r


def summarise(results: list[dict], clean: dict, spec: Spec, rng: random.Random) -> dict:
    def rate(rows, key):
        n = len(rows); k = sum(1 for r in rows if r["result"]["detected"][key])
        return {"n": n, "k": k, "rate": (k / n) if n else None, "ci": wilson(k, n)}
    def block(rows):
        tt = [r["result"]["ttd_s"]["fused"] for r in rows if r["result"]["ttd_s"]["fused"] is not None]
        return {"runs": len(rows), "fused": rate(rows, "fused"), "d1": rate(rows, "d1"), "d2": rate(rows, "d2"),
                "ttd_median_s": float(np.median(tt)) if tt else None, "ttd_ci_s": bootstrap_median(tt, rng),
                "node_recall_mean": float(np.mean([r["result"]["node_recall"] for r in rows])) if rows else None,
                "max_fused_median": float(np.median([r["result"]["max"]["fused"] for r in rows])) if rows else None}
    fams = sorted({r["attack"]["family"] for r in results})
    levels = [l for l in spec.evasion_levels if any(r["attack"]["evasion"] == l for r in results)]
    by_family = [{"family": f, **block([r for r in results if r["attack"]["family"] == f])} for f in fams]
    by_evasion = [{"level": l, **block([r for r in results if r["attack"]["evasion"] == l])} for l in levels]
    matrix = [{"family": f, "level": l, **block([r for r in results if r["attack"]["family"] == f and r["attack"]["evasion"] == l])} for f in fams for l in levels]
    overall = block(results)
    days = max(1, len(clean))
    fp_nodes = sum(c["alert_nodes"] for c in clean.values())
    coll = [r["result"]["collateral_fp_pass"] for r in results]
    return {"overall": overall, "by_family": by_family, "by_evasion": by_evasion, "matrix": matrix,
            "fp_per_day": fp_nodes / days, "fp_alert_windows_per_day": sum(c["alert_windows"] for c in clean.values()) / days,
            "collateral_fp_mean": float(np.mean(coll)) if coll else 0.0, "days": list(clean), "runs": len(results),
            # flat fields for list views
            "detection_rate": overall["fused"]["rate"], "detection_rate_ci": overall["fused"]["ci"],
            "robustness": {l: b["fused"]["rate"] for l, b in zip(levels, by_evasion)}}
