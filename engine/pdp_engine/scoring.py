"""Node scores, thresholds and detector fusion (label-free, calibrated on the benign validation day)."""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

# A node alerts when its score exceeds the threshold (= the maximum benign score on the validation day) by more than
# this margin, in threshold units. Scores are float32: a node behaving exactly like the validation-day maximum lands
# within a few ulps of 1.0 on either side (observed: +5e-7..+1e-6), and must not alert. 1e-4 is far below any
# meaningful score difference (alerting attack nodes score >= 1.4x in the benchmarks).
ALERT_MARGIN = 1e-4


def above(ratio: np.ndarray | float, margin: float = ALERT_MARGIN):
    """ratio (score / threshold) strictly above the threshold, beyond float32 rounding."""
    return ratio > 1.0 + margin


def node_scores(num_nodes: int, src: np.ndarray, dst: np.ndarray, loss: np.ndarray, out: np.ndarray | None = None) -> np.ndarray:
    """Max per-edge loss over edges where the node is src or dst (PIDSMaker node evaluation, use_dst_node_loss)."""
    if out is None:
        out = np.full(num_nodes, -np.inf, dtype=np.float32)
    np.maximum.at(out, src, loss)
    np.maximum.at(out, dst, loss)
    return out


@dataclass
class Calibration:
    """Per-detector thresholds derived from validation node scores."""
    threshold: float                       # max validation node score (framework rule)
    percentiles: dict[str, float] = field(default_factory=dict)  # e.g. {"99.9": ..} for FP-budget modes
    val_count: int = 0

    @staticmethod
    def from_validation(scores: np.ndarray) -> "Calibration":
        s = scores[np.isfinite(scores)]
        pct = {p: float(np.percentile(s, float(p))) for p in ("99", "99.9", "99.99")}
        return Calibration(float(s.max()), pct, int(len(s)))

    def ratio(self, scores: np.ndarray) -> np.ndarray:
        return scores / self.threshold


@dataclass
class FusionCalibration:
    """How the two detectors' threshold ratios become one learned score. mode "max" (0.5 default): a node scores
    as high as the more confident detector - no weights to choose, and right whichever detector is the stronger one
    on an endpoint (on the development sets detector-1 is on THEIA, detector-2 on CADETS; ranking ADP mean over
    CADETS / THEIA / H201: max 0.65, 1:2 0.60, 1:1 0.58, 2:1 0.52 - artifacts/lab_v05). mode "weighted": the weighted
    mean (0.2-0.4 default 2:1; the simulation calibration chooses weights)."""
    weights: tuple[float, float]           # (detector-1, detector-2) e.g. (2, 1); used by mode "weighted"
    threshold: float                       # max fused validation score
    percentiles: dict[str, float] = field(default_factory=dict)
    mode: str = "weighted"

    def fuse(self, r1: np.ndarray, r2: np.ndarray) -> np.ndarray:
        return fuse_ratios(r1, r2, self.weights, self.mode)

    @staticmethod
    def from_validation(r1: np.ndarray, r2: np.ndarray, weights=(2.0, 1.0), mode: str = "weighted") -> "FusionCalibration":
        f = fuse_ratios(r1, r2, weights, mode)
        f = f[np.isfinite(f)]
        return FusionCalibration(weights, float(f.max()), {p: float(np.percentile(f, float(p))) for p in ("99", "99.9", "99.99")}, mode)


FUSION_MODES = ("weighted", "max")


def fuse_ratios(r1: np.ndarray, r2: np.ndarray, weights=(2.0, 1.0), mode: str = "weighted") -> np.ndarray:
    if mode == "max":
        return np.maximum(r1, r2)
    if mode != "weighted":
        raise ValueError(f"unknown fusion mode {mode!r}")
    w1, w2 = weights
    return (w1 * r1 + w2 * r2) / (w1 + w2)


def fill_missing(r: np.ndarray) -> np.ndarray:
    """Nodes a detector never scored (-inf) count as 0 (no evidence) in the fusion."""
    r = r.copy()
    r[~np.isfinite(r)] = 0.0
    return r


def aggregate_weights(mode: str, val_loss: list[float]) -> list[float]:
    """Label-free weights for combining the detector-2 seed ratios (no attack labels used, only the benign
    validation reconstruction loss of each seed). Returns weights that sum to 1, aligned with `val_loss`."""
    k = len(val_loss)
    if k == 0:
        return []
    if mode == "best_val_loss":                      # keep only the single best-fitting seed
        w = [0.0] * k
        w[int(np.argmin(val_loss))] = 1.0
        return w
    if mode == "weighted":                           # softmax of -loss (lower loss -> more weight), temperature = std
        v = np.asarray(val_loss, dtype=np.float64)
        scale = v.std() or 1.0
        e = np.exp(-(v - v.min()) / scale)
        return list(e / e.sum())
    return [1.0 / k] * k                              # "mean" (default): equal weights
