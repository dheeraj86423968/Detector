"""Training of detector-1 (Velox) and detector-2 (ORTHRUS, k seeds) on a baseline store, calibration of
thresholds and of the fusion on the validation day, and bundle export.

Model selection: lowest validation loss (never a test metric). Validation windows are scored with the
selected epoch to calibrate thresholds; the TGN state at the end of the validation day is stored so the
endpoint runtime continues the same stream.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

import numpy as np
import torch

from .behaviour import BehaviourModel, top_threshold
from .bundle import detector1_file, requirements, save_state_dict, write_manifest
from .data import WindowStore, nodes_in_days
from .featurizer import Word2VecFeaturizer
from .layers import LayerConfig, TagParams, fit_layers
from .models import (OrthrusModel, TGNState, VeloxModel, load_tgn_state, make_tgn_batch, save_tgn_state, seed_everything,
                     velox_input_dim, velox_window_inputs)
from .schema import NUM_NODE_TYPES
from .scoring import Calibration, FusionCalibration, aggregate_weights, fill_missing, node_scores
from .windows import batches


@dataclass
class TrainConfig:
    emb_dim: int = 256
    w2v_epochs: int = 50
    # detector-1 (tuned values from the study)
    velox_out_dim: int = 256
    velox_lr: float = 1e-3           # 0.5: 1e-3 (with the batch_scale input it was >= 1e-4 on all development sets)
    velox_epochs: int = 12
    velox_seed: int = 0               # first detector-1 seed; seeds velox_seed .. velox_seed + velox_runs - 1
    velox_runs: int = 3               # detector-1 seed ensemble (ratios averaged): single runs are unstable
    velox_input: str = "batch_scale"     # structural input (models.VELOX_INPUTS); 0.3/0.4 used "window_degrees"
    velox_degree_features: bool = False  # legacy override: True selects the 0.3/0.4 window degree input
    velox_average_top: int = 3           # 0.5: detector-1 weights = mean of the 3 lowest-validation-loss epochs (1: best only)
    # detector-2
    orthrus_seeds: tuple = (0, 1, 2, 3, 4)
    orthrus_hid_dim: int = 256
    orthrus_out_dim: int = 256
    orthrus_lr: float = 1e-3
    orthrus_dropout: float = 0.3
    orthrus_epochs: int = 12
    neighbor_size: int = 20
    weight_decay: float = 1e-5
    batch_size: int = 1024
    patience: int = 3
    fusion_weights: tuple = (2.0, 1.0)   # mode "weighted" only
    fusion_mode: str = "max"             # 0.5: max of the two ratios (scoring.FusionCalibration); 0.2-0.4: "weighted" 2:1
    # label-free aggregation of the k detector-2 seeds into one ratio: "best_val_loss" (only the seed with the
    # lowest benign validation loss), "mean" (average of per-seed ratios), "weighted" (softmax of -val_loss).
    # 0.3 default: "mean" over 5 seeds. best_val_loss scored higher on injected attacks (28% vs 18% on CADETS), but
    # on DARPA E3 it made detector-2 swing between ADP 0.09 and 1.00 across training runs (docs/BENCHMARK_E3.md):
    # selecting one seed keeps all of its variance. The learned layer is now a ranker behind the deterministic
    # layers, where stability matters more than peak sensitivity.
    orthrus_aggregate: str = "mean"
    # 0.7: detector-3 (behavioural likelihood, pdp_engine.behaviour) and learned-seeded propagation. Thresholds are
    # set so that `calibration_budget` benign validation nodes would alert (0 = the validation maximum, 0.3-0.6).
    detector3: bool = True
    calibration_budget: int = 10
    propagation: bool = True
    propagation_delta: float = 0.95       # suspicion kept per hop
    propagation_gate: float = 0.4         # an edge carries suspicion only if its detector-3 score >= 0.4 x the threshold
    propagation_clip: float = 3.0         # one extreme score reaches at most as far as a 3x one
    propagation_seed: float = 0.3         # only nodes at >= 0.3 of the threshold pass suspicion on
    propagation_passes: int = 2           # hops per window
    # deterministic layers (pdp_engine.layers) and the learned layer's alerting policy
    layer_novelty: bool = False       # 0.7: the "new executable" rule no longer alerts on its own (detector-3 covers it)
    layer_rules: bool = True
    learned_daily_budget: int = 20    # at most this many learned-only alerts per day (highest scores first)
    learned_alerts: bool = True       # 0.7: the learned layer alerts (recall first, within the daily budget);
                                      # 0.4-0.6: it only ranked
    corroboration_percentile: str = "99.9"   # learned score (validation percentile) that alerts next to a layer 1/2 alert
    alert_layers: tuple | None = None        # layers allowed to alert (None = all); early models restrict this
    layers_only: bool = False                # rules-only model: layers 1-2 fitted, no learned detectors (early models
                                             # below one day of baseline: seconds on a CPU instead of a GPU run)
    device: str = "cuda" if torch.cuda.is_available() else "cpu"


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, flush=True)


def average_top(kept: list, k: int) -> dict:
    """Weights of the k epochs with the lowest validation loss, averaged (k <= 1: the best epoch alone). Label-free
    model selection: detector-1's validation loss jumps between epochs (CADETS: 0.63 -> 0.84 -> 0.65), and the single
    best epoch is a noisy pick; averaging nearby minima of the same run is a standard variance reduction (stochastic
    weight averaging) that costs nothing at inference. Development sets (artifacts/lab_v05): ensemble ADP CADETS
    0.36 -> 0.64, THEIA unchanged (0.90), the weakest seed of each better."""
    top = [sd for _, sd in sorted(kept, key=lambda t: t[0])[:max(1, k)]]
    return {name: sum(sd[name] for sd in top) / len(top) for name in top[0]}


class Trainer:
    def __init__(self, store: WindowStore, train_days: list[str], val_day: str, cfg: TrainConfig = TrainConfig(), out_dir: str = "bundle"):
        self.store, self.train_days, self.val_day, self.cfg, self.out_dir = store, train_days, val_day, cfg, out_dir
        self.dev = torch.device(cfg.device)
        self.reg = store.load_registry()
        self.N = len(self.reg)
        self.x = None  # node features on device
        self.layer_exclude: dict | None = None   # 0.6 learning integrity: kept out of layers 1-2 (fit_layers exclude)
        self.layer_prior: dict | None = None     # 0.6: layers.json of the model a retrain replaces (fit_layers prior)
        self.node_exclude = None                 # 0.7: registry positions kept out of detector-3's counts

    # ---------------------------------------------------------------- featurisation
    def fit_featurizer(self) -> Word2VecFeaturizer:
        ids = nodes_in_days(self.store, self.train_days)  # labels of nodes present in the training days only
        labels = self.reg.labels(); types = self.reg.types()
        log(f"fitting word2vec on {len(ids)} baseline nodes")
        self.feat = Word2VecFeaturizer(emb_dim=self.cfg.emb_dim, epochs=self.cfg.w2v_epochs).fit((labels[i], types[i]) for i in ids)
        log("computing node features")
        self.x = torch.from_numpy(self.feat.features(labels, types)).to(self.dev)
        return self.feat

    # ---------------------------------------------------------------- detector-1
    @property
    def velox_input(self) -> str:
        """Detector-1 structural input (models.VELOX_INPUTS). An explicit velox_degree_features=True (0.3/0.4 endpoint
        overrides) still selects the window degrees."""
        return "window_degrees" if self.cfg.velox_degree_features else self.cfg.velox_input

    def _velox_batches(self, w):
        """(a, b, x_src, x_dst, etype) per 1024-edge batch of a window, with the configured structural input."""
        src, dst, et = (torch.from_numpy(a).to(self.dev) for a in (w.src, w.dst, w.etype))
        for a, b, xs, xd in velox_window_inputs(src, dst, et, lambda i: self.x[i], self.velox_input, self.cfg.batch_size):
            yield a, b, xs, xd, et[a:b]

    @property
    def velox_in_dim(self) -> int:
        return velox_input_dim(int(self.x.shape[1]), self.velox_input)

    def _velox_epoch(self, model, opt, days, train: bool):
        model.train(train)
        tot, n = 0.0, 0
        for d in days:
            for w in self.store.windows(d):
                for a, b, xs, xd, et in self._velox_batches(w):
                    with torch.set_grad_enabled(train):
                        loss = model.losses(xs, xd, et, reduce=True)
                    if train:
                        opt.zero_grad(); loss.backward(); opt.step()
                    tot += float(loss) * (b - a); n += b - a
        return tot / max(n, 1)

    def train_velox(self, seed: int | None = None) -> VeloxModel:
        seed = self.cfg.velox_seed if seed is None else seed
        seed_everything(seed)
        model = VeloxModel(self.velox_in_dim, self.cfg.velox_out_dim).to(self.dev)
        opt = torch.optim.Adam(model.parameters(), lr=self.cfg.velox_lr, weight_decay=self.cfg.weight_decay)
        best, bad, kept = float("inf"), 0, []      # kept: (validation loss, weights) of every epoch
        for ep in range(self.cfg.velox_epochs):
            tr = self._velox_epoch(model, opt, self.train_days, True)
            va = self._velox_epoch(model, None, [self.val_day], False)
            log(f"detector-1 seed {seed} epoch {ep}: train {tr:.4f} val {va:.4f}")
            kept.append((va, {k: v.detach().clone() for k, v in model.state_dict().items()}))
            if va < best:
                best, bad = va, 0
            else:
                bad += 1
                if bad >= self.cfg.patience:
                    break
        model.load_state_dict(average_top(kept, self.cfg.velox_average_top))
        self.velox = model
        return model

    @torch.no_grad()
    def velox_val_scores(self, model: VeloxModel | None = None) -> np.ndarray:
        model = model or self.velox
        model.eval()
        scores = np.full(self.N, -np.inf, dtype=np.float32)
        for w in self.store.windows(self.val_day):
            loss = torch.cat([model.losses(xs, xd, et) for a, b, xs, xd, et in self._velox_batches(w)])
            node_scores(self.N, w.src, w.dst, loss.cpu().numpy(), scores)
        return scores

    # ---------------------------------------------------------------- detector-2
    def _orthrus_pass(self, model, opt, days, state: TGNState, train: bool, collect: np.ndarray | None = None):
        model.train(train)
        tot, n = 0.0, 0
        for d in days:
            for w in self.store.windows(d):
                src, dst, et = (torch.from_numpy(a).to(self.dev) for a in (w.src, w.dst, w.etype))
                wl = []
                for a, b in batches(w, self.cfg.batch_size):
                    s, t_, e = src[a:b], dst[a:b], et[a:b]
                    tb = make_tgn_batch(s, t_, self.x, state)
                    with torch.set_grad_enabled(train):
                        losses = model.losses(tb, e, reduce=False)
                        loss = losses.mean()
                    if train:
                        opt.zero_grad(); loss.backward(); opt.step()
                    state.insert(s, t_, e)
                    tot += float(loss) * (b - a); n += b - a
                    if collect is not None:
                        wl.append(losses.detach().cpu().numpy())
                if collect is not None:
                    node_scores(self.N, w.src, w.dst, np.concatenate(wl), collect)
        return tot / max(n, 1)

    def train_orthrus(self, seed: int) -> tuple[OrthrusModel, np.ndarray, TGNState]:
        seed_everything(seed)
        model = OrthrusModel(self.x.shape[1], hid_dim=self.cfg.orthrus_hid_dim, out_dim=self.cfg.orthrus_out_dim, dropout=self.cfg.orthrus_dropout).to(self.dev)
        opt = torch.optim.Adam(model.parameters(), lr=self.cfg.orthrus_lr, weight_decay=self.cfg.weight_decay)
        best, best_sd, bad = float("inf"), None, 0
        for ep in range(self.cfg.orthrus_epochs):
            state = TGNState(self.N, self.cfg.neighbor_size, self.dev)
            tr = self._orthrus_pass(model, opt, self.train_days, state, True)
            va = self._orthrus_pass(model, None, [self.val_day], state, False)
            log(f"detector-2 seed {seed} epoch {ep}: train {tr:.4f} val {va:.4f}")
            if va < best:
                best, bad = va, 0
                best_sd = {k: v.detach().clone() for k, v in model.state_dict().items()}
            else:
                bad += 1
                if bad >= self.cfg.patience:
                    break
        model.load_state_dict(best_sd)
        # validation node scores with the selected epoch, replaying the stream from scratch
        state = TGNState(self.N, self.cfg.neighbor_size, self.dev)
        self._orthrus_pass(model, None, self.train_days, state, False)
        val_start = {k: (v.clone() if torch.is_tensor(v) else v) for k, v in state.state().items()}   # state at the start of the validation day
        scores = np.full(self.N, -np.inf, dtype=np.float32)
        val_loss = self._orthrus_pass(model, None, [self.val_day], state, False, collect=scores)
        return model, scores, state, val_start, val_loss

    # ---------------------------------------------------------------- full run
    def run(self, meta: dict | None = None) -> str:
        os.makedirs(self.out_dir, exist_ok=True)
        if self.cfg.layers_only:
            return self.run_layers_only(meta)
        self.fit_featurizer()
        self.feat.save(os.path.join(self.out_dir, "featurizer"))
        cal1s, ratios1 = [], []
        for k in range(max(1, self.cfg.velox_runs)):
            seed = self.cfg.velox_seed + k
            model = self.train_velox(seed)
            sc = self.velox_val_scores(model)
            c = Calibration.from_validation(sc)
            cal1s.append(c); ratios1.append(fill_missing(c.ratio(sc)))
            save_state_dict(os.path.join(self.out_dir, detector1_file(self.velox_input, k)), model.state_dict())
            log(f"detector-1 seed {seed} threshold {c.threshold:.3f}")
        cal1 = cal1s[0]

        ratios2, cal2, val_losses = [], [], []
        state = None
        for k, seed in enumerate(self.cfg.orthrus_seeds):
            model, scores, state, val_start, val_loss = self.train_orthrus(seed)
            c = Calibration.from_validation(scores)
            cal2.append(c); ratios2.append(fill_missing(c.ratio(scores))); val_losses.append(float(val_loss))
            save_state_dict(os.path.join(self.out_dir, f"detector-2-s{k}.npz"), model.state_dict())
            log(f"detector-2 seed {seed} threshold {c.threshold:.3f} val-loss {val_loss:.4f}")
        agg = aggregate_weights(self.cfg.orthrus_aggregate, val_losses)
        log(f"detector-2 aggregate '{self.cfg.orthrus_aggregate}' weights {[round(w, 3) for w in agg]}")
        st = state.state()
        save_tgn_state(os.path.join(self.out_dir, "tgn_state.npz"), st)
        save_tgn_state(os.path.join(self.out_dir, "tgn_state_val_start.npz"), val_start)
        r1 = np.mean(ratios1, axis=0)       # the runtime averages the detector-1 seed ratios the same way
        r2 = np.average(ratios2, axis=0, weights=agg)   # the aggregation the runtime will apply, so the fusion is calibrated on it
        fcal = FusionCalibration.from_validation(r1, r2, self.cfg.fusion_weights, self.cfg.fusion_mode)
        log(f"fusion threshold {fcal.threshold:.3f}")
        d3 = self.fit_detector3() if self.cfg.detector3 else None
        calibration = {
            "detector-1": {"threshold": cal1.threshold, "percentiles": cal1.percentiles},
            "detector-1-seeds": [{"threshold": c.threshold, "percentiles": c.percentiles} for c in cal1s],
            "detector-2": [{"threshold": c.threshold, "percentiles": c.percentiles} for c in cal2],
            "detector-2-aggregate": {"mode": self.cfg.orthrus_aggregate, "weights": [float(w) for w in agg], "val_loss": val_losses},
            "fusion": {"weights": list(fcal.weights), "threshold": fcal.threshold, "percentiles": fcal.percentiles, "mode": fcal.mode},
        }
        if d3 is not None:
            fv = fcal.fuse(r1, r2) / fcal.threshold
            calibration["fusion"]["budget_threshold"] = top_threshold(fv, self.cfg.calibration_budget)
            calibration["detector-3"] = d3
            if self.cfg.propagation:
                calibration["propagation"] = {"delta": self.cfg.propagation_delta, "gate": self.cfg.propagation_gate,
                                              "clip": self.cfg.propagation_clip, "seed": self.cfg.propagation_seed,
                                              "passes": self.cfg.propagation_passes}
            calibration["final"] = {"threshold": 1.0, "budget": self.cfg.calibration_budget, "pending": True}
        json.dump(calibration, open(os.path.join(self.out_dir, "calibration.json"), "w"), indent=1)
        # layers 1 + 2: fitted on the same benign days (training + validation), no attack data
        lcfg = LayerConfig(novelty=self.cfg.layer_novelty, rules=self.cfg.layer_rules, tags=TagParams())
        spec = fit_layers(self.store, self.train_days + [self.val_day], self.reg, self.N, lcfg, log=log, exclude=self.layer_exclude, prior=self.layer_prior)
        json.dump(spec, open(os.path.join(self.out_dir, "layers.json"), "w"))
        policy = {"daily_budget": int(self.cfg.learned_daily_budget), "corroboration_percentile": self.cfg.corroboration_percentile,
                  "learned_alerts": bool(self.cfg.learned_alerts)}
        if self.cfg.alert_layers is not None:
            policy["alert_layers"] = sorted(self.cfg.alert_layers)
        write_manifest(self.out_dir, {
            **(meta or {}),
            "num_nodes": self.N, "train_days": self.train_days, "val_day": self.val_day,
            "detectors": {**({"detector-3": {"kind": "behavioural-likelihood", "budget": self.cfg.calibration_budget}} if d3 else {}),
                          "detector-1": {"in_dim": self.velox_in_dim, "out_dim": self.cfg.velox_out_dim, "seeds": len(cal1s),
                                         "degree_features": self.velox_input == "window_degrees", "input": self.velox_input,
                                         "lr": self.cfg.velox_lr, "average_top": self.cfg.velox_average_top},
                          "detector-2": {"in_dim": int(self.x.shape[1]), "hid_dim": self.cfg.orthrus_hid_dim, "out_dim": self.cfg.orthrus_out_dim,
                                         "dropout": self.cfg.orthrus_dropout, "seeds": len(self.cfg.orthrus_seeds), "neighbor_size": self.cfg.neighbor_size}},
            "calibration": calibration,
            "requires": requirements(self.velox_input, self.cfg.fusion_mode, detector3=d3 is not None,
                                     propagation=d3 is not None and self.cfg.propagation),
            "layers": {"file": "layers.json", "novelty": lcfg.novelty, "rules": lcfg.rules,
                       "known_executables": len(spec["known_executables"]),
                       "benign_alarm_keys": {r: len(v) for r, v in spec["thresholds"].items()},
                       **({"excluded": spec["excluded"]} if spec.get("excluded") else {}),
                       **({"coverage": spec["coverage"]} if spec.get("coverage") else {})},
            "learned_policy": policy,
        })
        if d3 is not None:
            self.calibrate_final()
        return self.out_dir

    # ---------------------------------------------------------------- detector-3 (0.7)
    def fit_detector3(self) -> dict:
        """Fit detector-3 on the training days (minus excluded nodes), save it, and calibrate its per-node-type
        thresholds on the validation day (calibration_budget benign nodes over)."""
        m, K = BehaviourModel.fit(self.store, self.train_days, self.reg, self.node_exclude, log=log)
        m.save(self.out_dir)
        n = len(self.reg)
        best = np.zeros(n)
        seen = np.zeros(n, bool)
        for w in self.store.windows(self.val_day):
            own, _ = m.node_scores(w, K, n)
            np.maximum(best, own, out=best)
            seen[w.src] = True
            seen[w.dst] = True
        isp = K.isproc[:n]
        b = self.cfg.calibration_budget
        cal = {"proc": top_threshold(best[seen & isp], b), "obj": top_threshold(best[seen & ~isp], b), "budget": b,
               "keys": len(m.vocab)}
        log(f"detector-3 thresholds proc {cal['proc']:.2f} obj {cal['obj']:.2f} (budget {b})")
        return cal

    def calibrate_final(self) -> None:
        """Replay the validation day through the runtime itself (detectors 1-3, fusion, propagation) and set the final
        threshold so that calibration_budget benign nodes would alert; rewrites calibration and manifest."""
        from .bundle import write_manifest as _wm
        from .runtime import Runtime
        rt = Runtime(self.out_dir, self.store.load_registry(), device=str(self.dev), layers=False)
        rt.reset(at="validation")
        n = len(rt.reg)
        best = np.full(n, -np.inf)
        for w in self.store.windows(self.val_day):
            r = rt.score(w)
            np.maximum.at(best, r.node_ids, r.fused)
        v = best[np.isfinite(best)]
        b = self.cfg.calibration_budget
        thr = top_threshold(v, b)
        pct = {p: float(np.percentile(v, float(p))) for p in ("99", "99.9", "99.99")} if len(v) else {}
        cal = json.load(open(os.path.join(self.out_dir, "calibration.json")))
        cal["final"] = {"threshold": thr, "budget": b, "percentiles": pct, "validation_nodes": int(len(v))}
        json.dump(cal, open(os.path.join(self.out_dir, "calibration.json"), "w"), indent=1)
        man = json.load(open(os.path.join(self.out_dir, "manifest.json")))
        for k in ("sha256", "signature"):
            man.pop(k, None)
        man["calibration"] = cal
        _wm(self.out_dir, man)
        log(f"final threshold {thr:.3f} (validation nodes {len(v)}, budget {b})")
        del rt

    def run_layers_only(self, meta: dict | None = None) -> str:
        """A bundle with layers 1-2 only (known programs, trusted addresses, per-key thresholds): what an early model
        alerts with anyway. The runtime scores nothing learned with it (fused = 0)."""
        lcfg = LayerConfig(novelty=self.cfg.layer_novelty, rules=self.cfg.layer_rules, tags=TagParams())
        spec = fit_layers(self.store, self.train_days + [self.val_day], self.reg, self.N, lcfg, log=log, exclude=self.layer_exclude, prior=self.layer_prior)
        json.dump(spec, open(os.path.join(self.out_dir, "layers.json"), "w"))
        policy = {"daily_budget": 0, "corroboration_percentile": self.cfg.corroboration_percentile,
                  "alert_layers": sorted(self.cfg.alert_layers or ("novelty", "rules"))}
        write_manifest(self.out_dir, {
            **(meta or {}), "layers_only": True,
            "num_nodes": self.N, "train_days": self.train_days, "val_day": self.val_day, "detectors": None, "calibration": None,
            "layers": {"file": "layers.json", "novelty": lcfg.novelty, "rules": lcfg.rules, "known_executables": len(spec["known_executables"]),
                       "benign_alarm_keys": {r: len(v) for r, v in spec["thresholds"].items()}},
            "learned_policy": policy,
        })
        log(f"rules-only bundle: {len(spec['known_executables'])} known programs, {len(spec.get('trusted_ips', []))} trusted addresses")
        return self.out_dir


def upgrade_bundle_07(src_dir: str, out_dir: str, store: WindowStore, cfg: TrainConfig | None = None,
                      node_exclude=None, layer_exclude: dict | None = None, layer_prior: dict | None = None,
                      device: str | None = None) -> str:
    """0.7 upgrade of an existing bundle without retraining detectors 1-2 (no GPU training): copy it, fit
    detector-3 on its training days, calibrate detector-3 and the detector-1/2 fusion at the validation budget
    (the fusion by replaying the validation day through the runtime), re-fit layers 1-2 with the current defaults
    (layer 1 does not alert on its own from 0.7 on), switch the learned layer to alerting within the daily budget,
    and calibrate the final threshold after propagation. The copy is unsigned (the server signs it)."""
    import shutil
    from .runtime import Runtime
    cfg = cfg or TrainConfig()
    if device:
        cfg = TrainConfig(**{**cfg.__dict__, "device": device})
    if os.path.exists(out_dir):
        raise FileExistsError(out_dir)
    shutil.copytree(src_dir, out_dir)
    for f in ("signature.json",):
        if os.path.exists(os.path.join(out_dir, f)):
            os.remove(os.path.join(out_dir, f))
    man = json.load(open(os.path.join(out_dir, "manifest.json")))
    if man.get("layers_only"):
        raise ValueError("rules-only bundle: nothing learned to upgrade")
    tr = Trainer(store, list(man["train_days"]), man["val_day"], cfg, out_dir)
    tr.node_exclude = node_exclude
    # detector-1/2 fusion on the validation day, through the runtime of the original bundle
    rt = Runtime(src_dir, store.load_registry(), device=str(tr.dev), layers=False)
    rt.reset(at="validation")
    best = np.full(len(rt.reg), -np.inf)
    for w in store.windows(tr.val_day):
        r = rt.score(w)
        np.maximum.at(best, r.node_ids, r.fused)
    del rt
    fv = best[np.isfinite(best)]
    d3 = tr.fit_detector3()
    cal = man["calibration"]
    cal["fusion"]["budget_threshold"] = top_threshold(fv, cfg.calibration_budget)
    cal["detector-3"] = d3
    if cfg.propagation:
        cal["propagation"] = {"delta": cfg.propagation_delta, "gate": cfg.propagation_gate, "clip": cfg.propagation_clip,
                              "seed": cfg.propagation_seed, "passes": cfg.propagation_passes}
    cal["final"] = {"threshold": 1.0, "budget": cfg.calibration_budget, "pending": True}
    json.dump(cal, open(os.path.join(out_dir, "calibration.json"), "w"), indent=1)
    lcfg = LayerConfig(novelty=cfg.layer_novelty, rules=cfg.layer_rules, tags=TagParams())
    spec = fit_layers(store, tr.train_days + [tr.val_day], tr.reg, int(man["num_nodes"]), lcfg, log=log,
                      exclude=layer_exclude, prior=layer_prior)
    json.dump(spec, open(os.path.join(out_dir, "layers.json"), "w"))
    meta = {k: v for k, v in man.items() if k not in ("sha256", "format", "created", "signature")}
    meta["calibration"] = cal
    meta["detectors"] = {"detector-3": {"kind": "behavioural-likelihood", "budget": cfg.calibration_budget}, **man["detectors"]}
    req = list(man.get("requires") or [])
    meta["requires"] = req + [f for f in (["detector-3"] + (["propagation"] if cfg.propagation else [])) if f not in req]
    meta["layers"] = {"file": "layers.json", "novelty": lcfg.novelty, "rules": lcfg.rules,
                      "known_executables": len(spec["known_executables"]),
                      "benign_alarm_keys": {r: len(v) for r, v in spec["thresholds"].items()},
                      **({"excluded": spec["excluded"]} if spec.get("excluded") else {}),
                      **({"coverage": spec["coverage"]} if spec.get("coverage") else {})}
    meta["learned_policy"] = {"daily_budget": int(cfg.learned_daily_budget), "corroboration_percentile": cfg.corroboration_percentile,
                              "learned_alerts": bool(cfg.learned_alerts)}
    meta["upgraded_from"] = man.get("bundle_id")
    write_manifest(out_dir, meta)
    tr.calibrate_final()
    return out_dir
