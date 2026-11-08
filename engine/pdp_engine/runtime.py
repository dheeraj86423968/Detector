"""Endpoint runtime: scores fused windows with a bundle and produces alerts with graph context.

Stateful across windows (registry growth, TGN neighbour state, information-flow tags), CPU-only by default.

Alerting (bundles with layers.json, 0.3+; docs/DETECTION_LAYERS.md):
  layer 1  novelty     a process runs a program that never ran during the baseline (and was not approved since)
  layer 2  rules       information-flow alarms (untrusted exec, exfiltration, untrusted-code network); the
                       dependency-prone rules (tainted spawn / modify) are evidence and alert only when corroborated
  layer 3  learned     the fused detector score ranks everything; on its own it alerts
             - "corroborated": a node marked by an evidence rule, or next to a layer-1/2 alert in the same window,
               whose score is above the validation-day percentile `corroboration_percentile`, and
             - "learned": a node above the fusion threshold, at most `daily_budget` per day (highest score first),
           so a learned-model false-positive storm is bounded by construction.
Older bundles (no layers.json) alert exactly as before: fused score above the fusion threshold.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import numpy as np
import torch

from .behaviour import BehaviourModel, Breadth, breadth_node_scores, propagate
from .bundle import check_requires, detector1_file, load_state_dict, verify_digests
from .featurizer import Word2VecFeaturizer
from .layers import ALWAYS_EVIDENCE, EVIDENCE_RULES, DeterministicLayers, Hit
from .models import OrthrusModel, TGNState, VeloxModel, load_tgn_state, make_tgn_batch, velox_input_dim, velox_window_inputs
from .schema import EDGE_TYPES, Registry
from .scoring import ALERT_MARGIN, Calibration, FusionCalibration, above, aggregate_weights, fill_missing, node_scores
from .windows import Window, batches


@dataclass
class WindowResult:
    start_ns: int
    end_ns: int
    num_edges: int
    node_ids: np.ndarray           # nodes seen in the window
    fused: np.ndarray              # fused score / fusion threshold per node (> 1 + ALERT_MARGIN = alert)
    r1: np.ndarray                 # detector-1 ratio
    r2: np.ndarray                 # detector-2 mean ratio over seeds
    alerts: np.ndarray             # alerted node ids (all layers)
    edge_loss: dict = field(default_factory=dict)   # optional per-edge losses for context (detector-1)
    reasons: dict = field(default_factory=dict)     # node id -> [{"layer", "rule", "detail", ...}] for alerted nodes
    hits: list = field(default_factory=list)        # layer 1/2 hits of this window (pdp_engine.layers.Hit)
    r3: np.ndarray = field(default_factory=lambda: np.zeros(0))   # 0.7: detector-3 ratio (behavioural likelihood)

    def layer_of(self, n: int) -> str:
        """Primary layer of an alerted node: novelty > rules > corroborated > learned."""
        rs = self.reasons.get(int(n)) or [{"layer": "learned"}]
        order = {"novelty": 0, "rules": 1, "corroborated": 2, "learned": 3}
        return min((r["layer"] for r in rs), key=lambda x: order.get(x, 9))

    def summary(self) -> dict:
        by = {}
        for n in self.alerts.tolist():
            k = self.layer_of(n)
            by[k] = by.get(k, 0) + 1
        return {"start_ns": self.start_ns, "end_ns": self.end_ns, "edges": self.num_edges, "nodes": int(len(self.node_ids)),
                "alerts": int(len(self.alerts)), "max_fused": float(self.fused.max()) if len(self.fused) else 0.0,
                "max_r1": float(self.r1.max()) if len(self.r1) else 0.0, "max_r2": float(self.r2.max()) if len(self.r2) else 0.0,
                "alerts_by_layer": by}


NOT_YET = np.iinfo(np.int64).max


def localize_snapshot(st: dict, reg: Registry, ensure_entities=None) -> dict:
    """A bundle's neighbour-state snapshot (rows indexed by global id) mapped to the positions of a compacted
    registry. Global ids the held rows point to but the registry lacks are passed to `ensure_entities` first;
    pointers that still cannot be resolved become empty slots."""
    nb_all, ei_all = st["neighbors"], st["e_id"]
    Nb = nb_all.shape[0]
    if st.get("slot_etype") is not None:
        se_all = st["slot_etype"].to(torch.int8)
    else:
        hist = st["etype"].to(torch.int8)
        se_all = hist[ei_all.clamp(min=0)] if hist.numel() else torch.zeros_like(ei_all, dtype=torch.int8)
        se_all[ei_all < 0] = 0
    g = torch.as_tensor(reg.gid_array())
    held = g < Nb
    gg = g[held]
    ref = torch.unique(nb_all[gg][ei_all[gg] >= 0])
    if ensure_entities is not None and ref.numel():
        missing = [int(x) for x in ref.tolist() if reg.local(int(x)) is None]
        if missing:
            ensure_entities(missing)
            g = torch.as_tensor(reg.gid_array())
            held = g < Nb
            gg = g[held]
    n, size = len(reg), nb_all.shape[1]
    g2l = torch.full((Nb,), -1, dtype=torch.long)
    pos = torch.nonzero(held).flatten()
    g2l[gg] = pos
    nbv, eiv, sev = nb_all[gg], ei_all[gg].clone(), se_all[gg]
    mapped = g2l[nbv.clamp(min=0, max=Nb - 1)]
    eiv[(eiv >= 0) & (mapped < 0)] = -1
    out = {"neighbors": torch.zeros((n, size), dtype=torch.long), "e_id": torch.full((n, size), -1, dtype=torch.long),
           "slot_etype": torch.zeros((n, size), dtype=torch.int8), "cur_e_id": st["cur_e_id"], "n": st.get("n", 0)}
    out["neighbors"][pos] = mapped.clamp(min=0)
    out["e_id"][pos] = eiv
    out["slot_etype"][pos] = sev
    return out


class NodeFeatures:
    """Static node features, stored once per distinct (label, type): every instance of a program is its own process
    node but shares its label (on a busy host ~500 k process nodes have ~45 k labels). Indexing returns the dense
    (len(idx), dim) float32 rows, like the plain matrix it replaces."""

    def __init__(self, dim: int, device):
        self.dim, self.device = int(dim), torch.device(device) if not isinstance(device, torch.device) else device
        self.table = torch.zeros((1, self.dim), dtype=torch.float32, device=self.device)   # row 0: zeros (unset)
        self.rows = 1
        self.index = torch.zeros(0, dtype=torch.long, device=self.device)
        self.key_row: dict[tuple[str, str], int] = {}

    @property
    def shape(self):
        return (int(self.index.shape[0]), self.dim)

    def __getitem__(self, idx):
        return self.table[self.index[idx]]

    def resize(self, n: int) -> None:
        """Grow with zero rows, or truncate (reset to the bundle's nodes)."""
        cur = int(self.index.shape[0])
        if n > cur:
            self.index = torch.cat([self.index, torch.zeros(n - cur, dtype=torch.long, device=self.device)])
        elif n < cur:
            self.index = self.index[:n].clone()

    def compact(self, keep: torch.Tensor) -> None:
        """Keep node rows `keep` (old ids, ascending) and only the label rows they still use."""
        idx = self.index[keep.to(self.device)]
        used, inv = torch.unique(idx, return_inverse=True)
        if used.numel() == 0 or int(used[0]) != 0:
            used = torch.cat([torch.zeros(1, dtype=torch.long, device=self.device), used])
            inv = inv + 1
        self.table = self.table[used].clone()
        self.rows = int(used.numel())
        self.index = inv
        keep_rows = {int(r): k for k, r in enumerate(used.tolist())}
        self.key_row = {key: keep_rows[r] for key, r in self.key_row.items() if r in keep_rows}

    def assign(self, items, featurizer) -> None:
        """items: (node id, label, ntype); featurises each distinct new (label, ntype) once."""
        new_keys, ids, rows = [], [], []
        for i, lab, nt in items:
            k = (lab, nt)
            r = self.key_row.get(k)
            if r is None:
                r = self.rows + len(new_keys)
                self.key_row[k] = r
                new_keys.append(k)
            ids.append(i); rows.append(r)
        if new_keys:
            need = self.rows + len(new_keys)
            if need > self.table.shape[0]:
                t = torch.zeros((max(need, int(self.table.shape[0] * 1.25) + 1024), self.dim), dtype=torch.float32, device=self.device)
                t[: self.rows] = self.table[: self.rows]
                self.table = t
            for a in range(0, len(new_keys), 50_000):
                part = new_keys[a:a + 50_000]
                f = featurizer.features([k[0] for k in part], [k[1] for k in part])
                self.table[self.rows + a: self.rows + a + len(part)] = torch.from_numpy(f).to(self.device)
            self.rows = need
        if ids:
            self.index[torch.as_tensor(ids, dtype=torch.long, device=self.device)] = torch.as_tensor(rows, dtype=torch.long, device=self.device)


class Runtime:
    @property
    def daily_budget(self) -> int:
        return self._daily_budget

    @daily_budget.setter
    def daily_budget(self, v: int):
        self._daily_budget = int(v)
        if getattr(self, "policy", None) is not None:
            self.policy.daily_budget = int(v)

    def __init__(self, bundle_dir: str, registry: Registry, device: str = "cpu", fp_budget: str | None = None,
                 feat_device: str | None = None, approved_executables=None, daily_budget: int | None = None,
                 layers: bool = True, keep_reset_state: bool = True, ensure_entities=None, seen_at_load_ns: int = 0):
        """keep_reset_state=False (endpoint agents): only the live state is kept; reset() / replaying the validation
        day (the server's simulator) are not available, which spares two copies of the neighbour state.

        A compacted registry (registry.gids set: positions are not global ids) gets the bundle's neighbour state
        mapped to its positions; `ensure_entities(gids)` is called first with the global ids the held entities'
        neighbour lists point to but the registry no longer holds, so the caller can add them back.
        seen_at_load_ns: "last seen" time given to the entities held at load (compaction measures age from it)."""
        verify_digests(bundle_dir)
        self.m = json.load(open(os.path.join(bundle_dir, "manifest.json")))
        check_requires(self.m)
        self.dev = torch.device(device)
        # the node-feature matrix can live on a different device than the models; keeping it on CPU while the
        # models run on the GPU spares ~N*(emb+3)*4 bytes of GPU memory (large registries OOM'd otherwise)
        self.featdev = torch.device(feat_device) if feat_device else self.dev
        self.reg = registry
        self.bm = self.bk = self.prop = None     # 0.7 detector-3 / propagation (set below for bundles that have them)
        self.thr3g = None
        self.breadth = None                      # 0.8: per-process breadth state (behaviour.Breadth)
        self.thr3b = None
        self.susp = np.zeros(0)
        self.final_thr = 1.0
        self.layers_only = bool(self.m.get("layers_only"))
        if self.layers_only:       # early model below one day: layers 1-2 only, nothing learned to load
            self._init_layers_only(bundle_dir, registry, approved_executables, daily_budget, seen_at_load_ns)
            return
        self.feat = Word2VecFeaturizer.load(os.path.join(bundle_dir, "featurizer"))
        d1, d2 = self.m["detectors"]["detector-1"], self.m["detectors"]["detector-2"]
        # detector-1 structural input: "input" from 0.5 on; earlier bundles: window degrees or none
        self.in1 = d1.get("input") or ("window_degrees" if d1.get("degree_features") else "none")
        self.velox = []
        for k in range(int(d1.get("seeds", 0)) or 1):
            v = VeloxModel(d1["in_dim"], d1["out_dim"]).to(self.dev).eval()
            f = os.path.join(bundle_dir, detector1_file(self.in1, k))
            v.load_state_dict(load_state_dict(f if os.path.exists(f) else os.path.join(bundle_dir, "detector-1.npz")))
            self.velox.append(v)
        self.orthrus = []
        for k in range(d2["seeds"]):
            m = OrthrusModel(d2["in_dim"], hid_dim=d2["hid_dim"], out_dim=d2["out_dim"], dropout=d2["dropout"]).to(self.dev).eval()
            m.load_state_dict(load_state_dict(os.path.join(bundle_dir, f"detector-2-s{k}.npz")))
            self.orthrus.append(m)
        cal = self.m["calibration"]
        key = "threshold" if fp_budget is None else None
        pick = (lambda c: c["threshold"]) if fp_budget is None else (lambda c: c["percentiles"][fp_budget])
        self.cal1 = [Calibration(pick(c), c["percentiles"]) for c in (cal.get("detector-1-seeds") or [cal["detector-1"]])]
        self.cal2 = [Calibration(pick(c), c["percentiles"]) for c in cal["detector-2"]]
        agg = cal.get("detector-2-aggregate")   # label-free seed weights (older bundles: plain mean)
        self.agg2 = np.asarray(agg["weights"] if agg else aggregate_weights("mean", [0.0] * len(self.cal2)), dtype=np.float64)
        self.fcal = FusionCalibration(tuple(cal["fusion"]["weights"]), pick(cal["fusion"]), cal["fusion"]["percentiles"],
                                      cal["fusion"].get("mode", "weighted"))
        # 0.7: detector-3 (behavioural likelihood) and learned-seeded propagation; the learned score is then
        # max(detector-1/2 fusion, detector-3) in validation-budget units, propagated, over the final threshold
        d3 = (self.m.get("detectors") or {}).get("detector-3")
        if d3:
            self.bm = BehaviourModel.load(bundle_dir)
            self.bk = self.bm.keys(registry)
            c3 = cal["detector-3"]
            self.thr3 = (float(c3["proc"]), float(c3["obj"]))
            self.thr3g = np.asarray(c3["groups"], dtype=np.float64) if c3.get("groups") else None   # 0.7b
            if c3.get("breadth"):                                                                     # 0.8
                b3 = c3["breadth"]
                self.breadth = Breadth(float(b3["cap"]), float(b3["floor"]), int(float(b3["horizon_s"]) * 1e9))
                self.thr3b = float(b3["threshold"])
            self.learned_unit = float(cal["fusion"].get("budget_threshold", 1.0))
        self.prop = cal.get("propagation") if d3 else None
        self.final_thr = float((cal.get("final") or {}).get("threshold", 1.0)) if d3 else 1.0
        # deterministic layers + learned alerting policy (absent in pre-0.3 bundles)
        self.layers = DeterministicLayers.load(bundle_dir, self.m["num_nodes"], set(approved_executables or ())) if layers else None
        pol = self.m.get("learned_policy") or {}
        if daily_budget is None:      # bundles before 0.9 recorded 20 learned-only alerts a day: the 0.9 default applies
            daily_budget = pol.get("daily_budget", 20) if (not d3 or pol.get("policy") == POLICY_VERSION) else LEARNED_DAILY_BUDGET
        self.daily_budget = int(daily_budget)
        cp = pol.get("corroboration_percentile", "99.9")
        self.corroboration = float(cal["fusion"]["percentiles"].get(cp, self.fcal.threshold)) / self.fcal.threshold
        if d3 and (cal.get("final") or {}).get("percentiles", {}).get(cp) is not None:   # 0.7: on the final scale
            self.corroboration = float(cal["final"]["percentiles"][cp]) / self.final_thr
        if d3 and pol.get("corroboration") == "threshold":     # 0.7 default: only above the learned threshold itself
            self.corroboration = 1.0 + ALERT_MARGIN
        ev = (self.layers.spec.get("config", {}).get("evidence_rules", EVIDENCE_RULES) if self.layers is not None else ())
        self.policy = AlertPolicy(self.layers, self.daily_budget, self.corroboration, cp, ev) if self.layers is not None else None
        if self.policy is not None and pol.get("alert_layers") is not None:
            self.policy.alert_layers = set(pol["alert_layers"])
        if self.policy is not None:     # 0.8.1 defaults apply to older bundles too (artifacts/lab_v09)
            self.policy.near_alert_score = str(pol.get("near_alert_score", NEAR_ALERT_SCORE))
            self.policy.repeat_corroborations = int(pol.get("repeat_corroborations", REPEAT_CORROBORATIONS))
        # learned-layer alerts by default (an endpoint setting overrides it): bundles from 0.4 on rank only
        self.default_learned_alerts = bool(pol.get("learned_alerts", True))
        self.set_learned_alerts(self.default_learned_alerts)
        # node features for the baseline registry + TGN state continuing from the end of the validation day
        self.N = self.m["num_nodes"]
        feat_dim = d1["in_dim"] - (velox_input_dim(0, self.in1))   # node features; window degrees add columns
        self._tgn_init = load_tgn_state(os.path.join(bundle_dir, "tgn_state.npz"))
        compacted = registry.gids is not None
        if compacted:
            self._tgn_init = localize_snapshot(self._tgn_init, registry, ensure_entities)
        n0 = len(registry) if compacted else max(self.N, len(registry))
        self.x = NodeFeatures(feat_dim, self.featdev)
        self.x.resize(n0)
        self._featurize(range(len(registry)))
        self._neighbor_size = d2["neighbor_size"]
        self._tgn_init_val = None
        self.keep_reset_state = keep_reset_state and not compacted
        pv = os.path.join(bundle_dir, "tgn_state_val_start.npz")
        if self.keep_reset_state and os.path.exists(pv):   # state at the start of the validation day (for simulations on that day)
            self._tgn_init_val = load_tgn_state(pv)
        self._load_tgn(n0)
        # end of the last window each node appeared in (compaction); NOT_YET for entities registered after loading
        # whose events have not been scored yet (never stale)
        self.last_seen = np.full(n0, int(seen_at_load_ns), dtype=np.int64)
        if not keep_reset_state:
            self._tgn_init = None
        self.N0 = self.x.shape[0]   # base feature rows (bundle registry) kept across reset()
        self.susp = np.zeros(n0)

    def _load_tgn(self, n: int, at: str = "end"):
        init = self._tgn_init_val if (at == "validation" and self._tgn_init_val is not None) else self._tgn_init
        self.state = TGNState(n, self._neighbor_size, self.dev)
        self.state.load_state(init)       # copies into the loader's own tensors

    @property
    def has_validation_state(self) -> bool:
        return self._tgn_init_val is not None

    def reset(self, registry: Registry | None = None, at: str = "end"):
        """Return to a bundle state ("end": neighbours at the end of the validation day, as deployed; "validation":
        at its start, to replay the validation day itself) and drop features of entities registered since loading;
        used by the simulator to score independent passes."""
        if not self.keep_reset_state:
            raise RuntimeError("this runtime was loaded without its reset state (keep_reset_state=False)")
        if registry is not None:
            self.reg = registry
        self.x.resize(self.N0)
        self._load_tgn(self.N0, at)
        if self.layers is not None:
            self.layers.reset()
            self.policy.reset()
        self.susp = np.zeros(0)
        self.grow()
        self.susp = np.zeros(max(len(self.reg), self.x.shape[0]))
        if self.bk is not None:
            self.bk = self.bm.keys(self.reg)
        if self.breadth is not None:
            self.breadth.reset()

    def set_learned_alerts(self, on: bool) -> None:
        """False: layer 3 only ranks; alerts come from layers 1-2 alone (deterministic mode)."""
        if self.policy is not None:
            self.policy.learned_alerts = bool(on)

    def set_approved_executables(self, approved) -> None:
        """Programs approved from the console since the bundle was built (layer 1 stops alerting on them)."""
        if self.layers is not None:
            self.layers.set_approved(approved)

    def set_allowlist(self, addresses=(), suppressed=()) -> None:
        """Console allow list: trusted addresses / networks and (rule, key) detections that must not alert."""
        if self.layers is not None:
            self.layers.set_allowlist(addresses, suppressed)

    def _featurize(self, ids):
        """Features for registry rows `ids` (label cache inside the featuriser: many entities share a label)."""
        ents = self.reg.entities
        self.x.assign([(i, ents[i].label, ents[i].ntype) for i in ids], self.feat)

    def _init_layers_only(self, bundle_dir, registry, approved_executables, daily_budget, seen_at_load_ns):
        self.feat, self.velox, self.orthrus, self.in1, self.x, self.state = None, [], [], "none", None, None
        self.keep_reset_state, self._tgn_init, self._tgn_init_val = False, None, None
        self.N = self.m["num_nodes"]
        self.layers = DeterministicLayers.load(bundle_dir, self.N, set(approved_executables or ()))
        pol = self.m.get("learned_policy") or {}
        self.daily_budget = int(daily_budget if daily_budget is not None else pol.get("daily_budget", 0))
        self.corroboration = float("inf")
        ev = self.layers.spec.get("config", {}).get("evidence_rules", EVIDENCE_RULES) if self.layers is not None else ()
        self.policy = AlertPolicy(self.layers, self.daily_budget, self.corroboration, pol.get("corroboration_percentile", "99.9"), ev) if self.layers else None
        if self.policy is not None:
            self.policy.alert_layers = set(pol.get("alert_layers") or ("novelty", "rules"))
        self.default_learned_alerts = bool(pol.get("learned_alerts", True))
        self.N0 = len(registry)
        self.last_seen = np.full(len(registry), int(seen_at_load_ns), dtype=np.int64)

    def grow(self):
        """Call after new entities were added to the registry."""
        n = len(self.reg)
        if self.layers_only:
            if n > len(self.last_seen):
                self.last_seen = np.concatenate([self.last_seen, np.full(n - len(self.last_seen), NOT_YET, dtype=np.int64)])
            return
        if n > self.x.shape[0]:
            old = self.x.shape[0]
            self.x.resize(n)
            self._featurize(range(old, n))
            self.state.grow(n)
            self.last_seen = np.concatenate([self.last_seen, np.full(n - len(self.last_seen), NOT_YET, dtype=np.int64)])
        if len(self.susp) < self.x.shape[0]:
            self.susp = np.concatenate([self.susp, np.zeros(self.x.shape[0] - len(self.susp))])

    def rules(self, w: Window) -> list[Hit]:
        """Layers 1-2 on a slice of the stream (real-time path): call with consecutive slices of the open window in
        time order, then pass all their hits to score() for that window, which then does not run the layers again.
        Gives the same hits as running the layers on the whole window."""
        if self.layers is None:
            return []
        self.grow()
        return self.layers.process(w, self.reg, w.nodes())

    def immediate_alerts(self, hits: list[Hit]) -> dict[int, list[dict]]:
        """Alerts the deterministic layers raise on their own (no learned score needed), node -> reasons; what
        score() will report for these nodes in layers 1-2 anyway, available as soon as the events are seen."""
        if self.policy is None:
            return {}
        reasons, _ = self.policy.split(hits)
        return self.policy.allowed(reasons)

    @torch.no_grad()
    def score(self, w: Window, keep_edge_losses: bool = False, hits: list[Hit] | None = None) -> WindowResult:
        """hits: the layers' hits for this window from rules() (real-time path); None runs the layers here."""
        self.grow()
        if self.layers_only:
            ids = w.nodes()
            self.last_seen[ids] = int(w.end_ns or w.start_ns)
            z = np.zeros(len(ids), dtype=np.float64)
            if self.policy is None:
                alerts, reasons, hits = np.zeros(0, dtype=np.int64), {}, []
            else:
                alerts, reasons, hits = self.policy.apply(w, self.reg, ids, z, hits)
            res = WindowResult(w.start_ns, w.end_ns, w.num_edges, ids, z, z, z, alerts, reasons=reasons, hits=hits)
            if keep_edge_losses:
                res.edge_loss = {}
            return res
        n = self.x.shape[0]
        src, dst, et = (torch.from_numpy(a).to(self.dev) for a in (w.src, w.dst, w.etype))
        x = self.x
        def xg(idx):   # gather features for a batch to the compute device (features may live on CPU)
            return x[idx.to(self.featdev)].to(self.dev)
        parts = [[] for _ in self.velox]
        for a, b, xs, xd in velox_window_inputs(src, dst, et, xg, self.in1):   # inputs built once, shared by the seeds
            for k, v in enumerate(self.velox):
                parts[k].append(v.losses(xs, xd, et[a:b]))
        l1s = [torch.cat(p).cpu().numpy() for p in parts]
        l2 = [[] for _ in self.orthrus]
        for a, b in batches(w):
            tb = make_tgn_batch(src[a:b], dst[a:b], x, self.state)
            for k, m in enumerate(self.orthrus):
                l2[k].append(m.losses(tb, et[a:b]).cpu().numpy())
            self.state.insert(src[a:b], dst[a:b], et[a:b])
        ids = w.nodes()
        self.last_seen[ids] = int(w.end_ns or w.start_ns)
        r1 = np.mean([fill_missing(c.ratio(node_scores(n, w.src, w.dst, l)[ids])) for c, l in zip(self.cal1, l1s)], axis=0)
        s2 = [node_scores(n, w.src, w.dst, np.concatenate(l)) for l in l2]
        r2 = np.average([fill_missing(c.ratio(s[ids])) for c, s in zip(self.cal2, s2)], axis=0, weights=self.agg2)
        fused = self.fcal.fuse(r1, r2) / self.fcal.threshold   # ratio units like r1/r2: > 1 = above the threshold
        r3 = np.zeros(0)
        self._own = None
        if self.bm is not None:
            fused, r3 = self._learned_07(w, ids, fused)
        if self.layers is None:
            alerts, reasons, hits = ids[above(fused)], {}, []
        else:
            alerts, reasons, hits = self._alert_policy(w, ids, fused, hits)
        res = WindowResult(w.start_ns, w.end_ns, w.num_edges, ids, fused, r1, r2, alerts, reasons=reasons, hits=hits, r3=r3)
        if keep_edge_losses:
            res.edge_loss = {"detector-1": np.mean(l1s, axis=0), "detector-2": np.mean([np.concatenate(l) for l in l2], axis=0)}
        return res

    def _learned_07(self, w: Window, ids: np.ndarray, fused: np.ndarray):
        """0.7 learned score of the window's nodes: max(detector-1/2 fusion, detector-3), each in units of its
        validation-budget threshold, propagated along unusual data-flow edges (carried across windows), over the
        final threshold calibrated on the validation day after propagation. Returns (final, r3) aligned with ids."""
        n = len(self.reg)
        if len(self.susp) < n:
            self.susp = np.concatenate([self.susp, np.zeros(n - len(self.susp))])
        self.bk.grow()
        if self.breadth is not None:                # 0.8: breadth evidence (processes), capped maxima (objects)
            own, es = breadth_node_scores(self.bm, w, self.bk, n, self.breadth)
            r3_all, er = own / self.thr3b, es / self.thr3[0]
        elif self.thr3g is not None:                # 0.7b: per-activity thresholds (already ratios)
            from .behaviour import grouped_node_scores
            r3_all, er = grouped_node_scores(self.bm, w, self.bk, n, self.thr3g)
        else:
            own, es = self.bm.node_scores(w, self.bk, n)
            tn = np.where(self.bk.isproc[:n], self.thr3[0], self.thr3[1])
            r3_all, er = own / tn, es / self.thr3[0]
        base = r3_all.copy()
        np.maximum.at(base, ids, fill_missing(fused) / self.learned_unit)
        self._own = base[ids] / self.final_thr      # this window's own evidence, before propagation (alert policy)
        if self.prop:
            p = self.prop
            propagate(self.susp[:n], base, w, er, float(p["delta"]), float(p["gate"]), float(p["clip"]),
                      float(p["seed"]), int(p["passes"]))
            final = self.susp[ids] / self.final_thr
        else:
            final = base[ids] / self.final_thr
        return final, r3_all[ids]

    # ---- registry compaction (long-running endpoints) -----------------------------------------------------
    def compaction_keep(self, now_ns: int, max_age_ns: int, extra=()) -> np.ndarray:
        """Which registry positions to keep: seen within `max_age_ns`, in `extra` (the caller's pending work),
        holding rule state (lowered integrity and its origin), and every node a kept node's neighbour list
        points to (detector-2 reads those neighbours' features)."""
        self.grow()
        n = len(self.reg)
        keep = self.last_seen[:n] >= now_ns - max_age_ns
        ex = np.fromiter((int(i) for i in extra), dtype=np.int64)
        if ex.size:
            keep[ex[(ex >= 0) & (ex < n)]] = True
        if self.layers is not None:
            st = np.fromiter(self.layers.keep_nodes(now_ns), dtype=np.int64)
            if st.size:
                keep[st[(st >= 0) & (st < n)]] = True
        if self.state is not None:
            L = self.state.loader
            rows = torch.as_tensor(np.nonzero(keep)[0], device=L.neighbors.device)
            nb, ei = L.neighbors[rows], L.e_id[rows]
            ref = torch.unique(nb[ei >= 0]).cpu().numpy()
            keep[ref[ref < n]] = True
        return keep

    def compact(self, keep: np.ndarray) -> list[int]:
        """Drop registry positions where keep is false and renumber everything that refers to positions
        (registry, node features, neighbour state, rule state). Returns old -> new position (-1 dropped); the
        caller renumbers its own references (window buffer). Not available with a reset state (simulator)."""
        if self.keep_reset_state:
            raise RuntimeError("compaction needs a runtime without reset state (keep_reset_state=False)")
        self.grow()
        old2new = self.reg.compact(keep)
        if not self.layers_only:
            kidx = torch.as_tensor(np.nonzero(keep)[0], dtype=torch.long)
            o2n = torch.as_tensor(old2new, dtype=torch.long)
            self.x.compact(kidx)
            self.state.compact(kidx, o2n)
        if self.layers is not None:
            self.layers.remap(old2new)
        self.last_seen = self.last_seen[keep]
        if len(self.susp):
            self.susp = self.susp[:len(keep)][keep]
        if self.bk is not None:
            self.bk.remap(old2new)
        if self.breadth is not None:
            self.breadth.remap(keep)
        self.N0 = len(self.reg)
        return old2new

    def _alert_policy(self, w: Window, ids: np.ndarray, fused: np.ndarray, hits=None):
        return self.policy.apply(w, self.reg, ids, fused, hits, own=getattr(self, "_own", None))


# 0.8.1 (artifacts/lab_v09): a learned score corroborates a neighbouring layer-1/2 alert only on the neighbour's own
# evidence in the window ("own"), not on suspicion propagated to it - on CARBANAKv2 h1 one alerted Windows Update
# process propagated its suspicion to ~3,500 files it wrote, which then "corroborated" that same alert. "final" = 0.7.
NEAR_ALERT_SCORE = "own"
REPEAT_CORROBORATIONS = 1     # 0.9: corroborated repeat runs of a new program per program and UTC day (0 = no cap);
                              # the first runs already alerted through layer 1, more instances are the same finding
# 0.9 (artifacts/lab_v09 grid 2): alerts on the learned score alone were 0.6 % precise (779 alerts, 5 true, no attack
# found only by them on 16 sets); by default the learned layer corroborates and ranks but raises no alert of its own.
# Bundles trained from 0.9 on record their own budget (learned_policy.policy = "0.9"); an endpoint setting overrides.
LEARNED_DAILY_BUDGET = 0
POLICY_VERSION = "0.9"

CRITICAL_RULES = ("exfiltration", "untrusted_code_network")


def alert_tier(reasons: list[dict]) -> int:
    """Triage severity of an alerted node, graded like the console grades incidents (pdp_server.incidents.summarise):
    4 critical (exfiltration, untrusted-code network), 3 high (untrusted exec, or a new program that also breaks a
    data-flow rule), 2 medium (new program, other rules, corroborated), 1 low (learned score alone), 0 not alerted."""
    if not reasons:
        return 0
    layers = {x["layer"] for x in reasons}
    rules = {x["rule"] for x in reasons if x["layer"] == "rules"}
    if rules & set(CRITICAL_RULES):
        return 4
    if "untrusted_exec" in rules or ("novelty" in layers and rules):
        return 3
    if layers & {"novelty", "rules", "corroborated"}:
        return 2
    return 1 if "learned" in layers else 0


class AlertPolicy:
    """How the layers' outputs become alerts (one call per window, in stream order; state = the daily budget)."""

    def __init__(self, layers: DeterministicLayers, daily_budget: int, corroboration: float, corroboration_label: str = "99.9",
                 evidence_rules=EVIDENCE_RULES):
        self.layers, self.daily_budget, self.corroboration = layers, int(daily_budget), float(corroboration)
        self.learned_alerts = True        # False: the learned layer only ranks (no corroborated / learned alerts)
        # layers allowed to raise alerts (None = all). Early models, trained on hours or days of activity instead of the
        # full baseline, alert only from the layers that stay precise on so little data (manifest learned_policy)
        self.alert_layers: set | None = None
        self.label = corroboration_label
        self.evidence_rules = set(evidence_rules or ()) | set(ALWAYS_EVIDENCE)
        self.corroboration_scope = "window"   # learned_near_alert candidates: "window" neighbours | "forward" data flow
        self.near_alert = True                # False: the learned score corroborates evidence rules only
        self.near_alert_score = NEAR_ALERT_SCORE   # "own": the neighbour's own (pre-propagation) score; "final": 0.7
        self.repeat_corroborations = REPEAT_CORROBORATIONS
        self.learned_floor = 0.0              # > 0: learned-only alerts need a score above this many thresholds too
        self.reset()

    def reset(self):
        self._day, self._day_learned = None, 0
        self._repeats: dict = {}

    def split(self, hits: list[Hit]) -> tuple[dict, dict]:
        """Hits -> (reasons of alerting rules, evidence of corroboration-only rules), per node."""
        reasons: dict[int, list[dict]] = {}
        evidence: dict[int, list[dict]] = {}
        for h in hits:
            dest = evidence if h.rule in self.evidence_rules else reasons
            for k, n in enumerate(h.nodes):
                dest.setdefault(int(n), []).append({"layer": h.layer, "rule": h.rule, "detail": h.detail, "key": h.key,
                                                    "value": h.value, "ts_ns": h.ts, "role": "actor" if k == 0 else "object"})
        return reasons, evidence

    def allowed(self, reasons: dict) -> dict:
        if self.alert_layers is not None:
            reasons = {n: rs for n, rs in reasons.items() if any(x["layer"] in self.alert_layers for x in rs)}
        return reasons

    def apply(self, w: Window, reg: Registry, ids: np.ndarray, fused: np.ndarray, hits: list[Hit] | None = None,
              own: np.ndarray | None = None):
        """own: each node's own score in this window before propagation (0.7+ runtimes), aligned with ids."""
        if hits is None:
            hits = self.layers.process(w, reg, ids)
        pos = {int(n): i for i, n in enumerate(ids.tolist())}
        reasons, evidence = self.split(hits)
        reasons = self.allowed(reasons)
        det = [n for n in reasons if n in pos]
        if not self.learned_alerts or (self.alert_layers is not None and not ({"corroborated", "learned"} & self.alert_layers)):
            return np.array(sorted(reasons), dtype=np.int64), reasons, hits
        day = int(w.start_ns // 86_400_000_000_000)
        if day != self._day:
            self._day, self._day_learned, self._repeats = day, 0, {}
        # evidence rules: alert when the learned score corroborates them
        for n, ev in evidence.items():
            if n in reasons or n not in pos:
                continue
            f = float(fused[pos[n]])
            if f > self.corroboration and self.repeat_corroborations > 0 and ev[0]["rule"] == "novel_executable_repeat":
                nov = getattr(self.layers, "novelty", None)
                k = nov.key(ev[0]["key"]) if nov is not None else ev[0]["key"]   # any spelling of the same program
                if self._repeats.get(k, 0) >= self.repeat_corroborations:
                    continue        # more runs of the same new program are the same finding
                self._repeats[k] = self._repeats.get(k, 0) + 1
            if f > self.corroboration:
                reasons[n] = [{"layer": "corroborated", "rule": ev[0]["rule"], "value": round(f, 3), "key": ev[0]["key"],
                               "detail": f"{ev[0]['detail']}; learned score {f:.2f} corroborates"}] + [dict(x, layer="evidence") for x in ev]
        # corroborated: window neighbours of deterministic alerts with a high learned score
        if det and self.near_alert:
            dset = np.array(det, dtype=np.int64)
            if self.corroboration_scope == "forward":   # what the alerted nodes affected (data flows out of them)
                nb = np.setdiff1d(np.unique(w.dst[np.isin(w.src, dset)]), dset)
            else:                                        # "window": any neighbour in the window, either direction
                m = np.isin(w.src, dset) | np.isin(w.dst, dset)
                nb = np.setdiff1d(np.unique(np.concatenate([w.src[m], w.dst[m]])), dset)
            score = own if (own is not None and self.near_alert_score == "own") else fused
            for n in nb.tolist():
                if n in reasons:
                    continue
                f = float(score[pos[n]])
                if f > self.corroboration:
                    reasons[n] = [{"layer": "corroborated", "rule": "learned_near_alert", "value": round(f, 3),
                                   "detail": f"own learned score {f:.2f} (above the validation {self.label}th percentile) next to a layer-1/2 alert"
                                   if score is own else f"learned score {f:.2f} (above the validation {self.label}th percentile) next to a layer-1/2 alert"}]
        # learned-only: above the fusion threshold, within the daily budget, highest first
        cand = [i for i in np.where(above(fused) & (fused > self.learned_floor))[0].tolist() if int(ids[i]) not in reasons]
        cand.sort(key=lambda i: -float(fused[i]))
        room = max(0, self.daily_budget - self._day_learned)
        for i in cand[:room]:
            reasons[int(ids[i])] = [{"layer": "learned", "rule": "learned_score", "value": round(float(fused[i]), 3),
                                     "detail": f"learned score {float(fused[i]):.2f}x the benign maximum"}]
        self._day_learned += min(room, len(cand))
        alerts = np.array(sorted(reasons), dtype=np.int64)
        return alerts, reasons, hits
