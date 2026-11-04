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

from .bundle import save_state_dict, write_manifest
from .data import WindowStore, nodes_in_days
from .featurizer import Word2VecFeaturizer
from .layers import LayerConfig, TagParams, fit_layers
from .models import DEG_DIM, OrthrusModel, TGNState, VeloxModel, load_tgn_state, make_tgn_batch, save_tgn_state, seed_everything, window_degrees
from .schema import NUM_NODE_TYPES
from .scoring import Calibration, FusionCalibration, aggregate_weights, fill_missing, node_scores
from .windows import batches


@dataclass
class TrainConfig:
    emb_dim: int = 256
    w2v_epochs: int = 50
    # detector-1 (tuned values from the study)
    velox_out_dim: int = 256
    velox_lr: float = 1e-4
    velox_epochs: int = 12
    velox_seed: int = 0               # first detector-1 seed; seeds velox_seed .. velox_seed + velox_runs - 1
    velox_runs: int = 3               # detector-1 seed ensemble (ratios averaged): single runs are unstable
    velox_degree_features: bool = True   # explicit window degree input (models.window_degrees)
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
    fusion_weights: tuple = (2.0, 1.0)
    # label-free aggregation of the k detector-2 seeds into one ratio: "best_val_loss" (only the seed with the
    # lowest benign validation loss), "mean" (average of per-seed ratios), "weighted" (softmax of -val_loss).
    # 0.3 default: "mean" over 5 seeds. best_val_loss scored higher on injected attacks (28% vs 18% on CADETS), but
    # on DARPA E3 it made detector-2 swing between ADP 0.09 and 1.00 across training runs (docs/BENCHMARK_E3.md):
    # selecting one seed keeps all of its variance. The learned layer is now a ranker behind the deterministic
    # layers, where stability matters more than peak sensitivity.
    orthrus_aggregate: str = "mean"
    # deterministic layers (pdp_engine.layers) and the learned layer's alerting policy
    layer_novelty: bool = True
    layer_rules: bool = True
    learned_daily_budget: int = 20    # at most this many learned-only alerts per day (highest scores first)
    corroboration_percentile: str = "99.9"   # learned score (validation percentile) that alerts next to a layer 1/2 alert
    alert_layers: tuple | None = None        # layers allowed to alert (None = all); early models restrict this
    layers_only: bool = False                # rules-only model: layers 1-2 fitted, no learned detectors (early models
                                             # below one day of baseline: seconds on a CPU instead of a GPU run)
    device: str = "cuda" if torch.cuda.is_available() else "cpu"


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, flush=True)


class Trainer:
    def __init__(self, store: WindowStore, train_days: list[str], val_day: str, cfg: TrainConfig = TrainConfig(), out_dir: str = "bundle"):
        self.store, self.train_days, self.val_day, self.cfg, self.out_dir = store, train_days, val_day, cfg, out_dir
        self.dev = torch.device(cfg.device)
        self.reg = store.load_registry()
        self.N = len(self.reg)
        self.x = None  # node features on device

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
    def _velox_inputs(self, w):
        """Per-edge source / destination inputs of detector-1 for a whole window (features [+ window degrees])."""
        src, dst, et = (torch.from_numpy(a).to(self.dev) for a in (w.src, w.dst, w.etype))
        xs, xd = self.x[src], self.x[dst]
        if self.cfg.velox_degree_features:
            ds, dd = window_degrees(src, dst, et)
            xs, xd = torch.cat([xs, ds], 1), torch.cat([xd, dd], 1)
        return xs, xd, et

    @property
    def velox_in_dim(self) -> int:
        return int(self.x.shape[1]) + (DEG_DIM if self.cfg.velox_degree_features else 0)

    def _velox_epoch(self, model, opt, days, train: bool):
        model.train(train)
        tot, n = 0.0, 0
        for d in days:
            for w in self.store.windows(d):
                xs, xd, et = self._velox_inputs(w)
                for a, b in batches(w, self.cfg.batch_size):
                    with torch.set_grad_enabled(train):
                        loss = model.losses(xs[a:b], xd[a:b], et[a:b], reduce=True)
                    if train:
                        opt.zero_grad(); loss.backward(); opt.step()
                    tot += float(loss) * (b - a); n += b - a
        return tot / max(n, 1)

    def train_velox(self, seed: int | None = None) -> VeloxModel:
        seed = self.cfg.velox_seed if seed is None else seed
        seed_everything(seed)
        model = VeloxModel(self.velox_in_dim, self.cfg.velox_out_dim).to(self.dev)
        opt = torch.optim.Adam(model.parameters(), lr=self.cfg.velox_lr, weight_decay=self.cfg.weight_decay)
        best, best_sd, bad = float("inf"), None, 0
        for ep in range(self.cfg.velox_epochs):
            tr = self._velox_epoch(model, opt, self.train_days, True)
            va = self._velox_epoch(model, None, [self.val_day], False)
            log(f"detector-1 seed {seed} epoch {ep}: train {tr:.4f} val {va:.4f}")
            if va < best:
                best, bad = va, 0
                best_sd = {k: v.detach().clone() for k, v in model.state_dict().items()}
            else:
                bad += 1
                if bad >= self.cfg.patience:
                    break
        model.load_state_dict(best_sd)
        self.velox = model
        return model

    @torch.no_grad()
    def velox_val_scores(self, model: VeloxModel | None = None) -> np.ndarray:
        model = model or self.velox
        model.eval()
        scores = np.full(self.N, -np.inf, dtype=np.float32)
        for w in self.store.windows(self.val_day):
            xs, xd, et = self._velox_inputs(w)
            loss = torch.cat([model.losses(xs[a:b], xd[a:b], et[a:b]) for a, b in batches(w, self.cfg.batch_size)])
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
            save_state_dict(os.path.join(self.out_dir, f"detector-1-s{k}.npz"), model.state_dict())
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
        fcal = FusionCalibration.from_validation(r1, r2, self.cfg.fusion_weights)
        log(f"fusion threshold {fcal.threshold:.3f}")
        calibration = {
            "detector-1": {"threshold": cal1.threshold, "percentiles": cal1.percentiles},
            "detector-1-seeds": [{"threshold": c.threshold, "percentiles": c.percentiles} for c in cal1s],
            "detector-2": [{"threshold": c.threshold, "percentiles": c.percentiles} for c in cal2],
            "detector-2-aggregate": {"mode": self.cfg.orthrus_aggregate, "weights": [float(w) for w in agg], "val_loss": val_losses},
            "fusion": {"weights": list(fcal.weights), "threshold": fcal.threshold, "percentiles": fcal.percentiles},
        }
        json.dump(calibration, open(os.path.join(self.out_dir, "calibration.json"), "w"), indent=1)
        # layers 1 + 2: fitted on the same benign days (training + validation), no attack data
        lcfg = LayerConfig(novelty=self.cfg.layer_novelty, rules=self.cfg.layer_rules, tags=TagParams())
        spec = fit_layers(self.store, self.train_days + [self.val_day], self.reg, self.N, lcfg, log=log)
        json.dump(spec, open(os.path.join(self.out_dir, "layers.json"), "w"))
        policy = {"daily_budget": int(self.cfg.learned_daily_budget), "corroboration_percentile": self.cfg.corroboration_percentile}
        if self.cfg.alert_layers is not None:
            policy["alert_layers"] = sorted(self.cfg.alert_layers)
        write_manifest(self.out_dir, {
            **(meta or {}),
            "num_nodes": self.N, "train_days": self.train_days, "val_day": self.val_day,
            "detectors": {"detector-1": {"in_dim": self.velox_in_dim, "out_dim": self.cfg.velox_out_dim, "seeds": len(cal1s),
                                         "degree_features": bool(self.cfg.velox_degree_features)},
                          "detector-2": {"in_dim": int(self.x.shape[1]), "hid_dim": self.cfg.orthrus_hid_dim, "out_dim": self.cfg.orthrus_out_dim,
                                         "dropout": self.cfg.orthrus_dropout, "seeds": len(self.cfg.orthrus_seeds), "neighbor_size": self.cfg.neighbor_size}},
            "calibration": calibration,
            "layers": {"file": "layers.json", "novelty": lcfg.novelty, "rules": lcfg.rules,
                       "known_executables": len(spec["known_executables"]),
                       "benign_alarm_keys": {r: len(v) for r, v in spec["thresholds"].items()}},
            "learned_policy": policy,
        })
        return self.out_dir

    def run_layers_only(self, meta: dict | None = None) -> str:
        """A bundle with layers 1-2 only (known programs, trusted addresses, per-key thresholds): what an early model
        alerts with anyway. The runtime scores nothing learned with it (fused = 0)."""
        lcfg = LayerConfig(novelty=self.cfg.layer_novelty, rules=self.cfg.layer_rules, tags=TagParams())
        spec = fit_layers(self.store, self.train_days + [self.val_day], self.reg, self.N, lcfg, log=log)
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
