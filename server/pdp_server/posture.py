"""Control-plane misuse resistance (0.6): someone with console or API access (an insider, or an attacker holding a
stolen session) must not be able to weaken detection silently, and the product resists uses it was not built for.

  settings schema   every endpoint configuration key and every `train` key is typed and range-checked
                    (validate_config); keys the server or the training worker control are refused; the learned
                    layer or the data-flow rules must keep alerting (check_floor)
  weakening         a change that lowers detection (weakenings(): a layer turned off, alerting dropped for a layer,
                    a shorter baseline, periodic retraining off, an allow-list entry, a lower retention ...) is
                    allowed for admins but needs a non-empty reason (require_reason), is written to the audit log
                    with a redacted before/after diff (audit_change) and becomes a `detection_weakened` security
                    event that the organisation's notification channels receive (security_messages)
  programs          allow-list program entries are full paths, compared the way the agent's layer 1 compares them
                    (pdp_engine.layers.program_key); no wildcards or folders; interpreters, shells, loaders and
                    system binaries that run other code need force + a reason (check_program)
  posture           per-endpoint detection posture from the model manifest and the settings (compute): no model,
                    stuck on an early model, stale model with retraining off, layers off, a learned-alert flood,
                    risky allow-list entries; shown with the endpoint's health problems, and a worsening is a
                    security event (refresh_all, run by the notifier)
  resources         per-user token buckets for expensive calls (take: export, hunt, sim; table rate_buckets, shared
                    by all API workers) and a per-organisation daily cap on simulation runs (check_sim_quota)
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from . import db
from .access import admin, require_endpoint, session

router = APIRouter()

LAYERS = ("novelty", "rules", "corroborated", "learned")
LAYER_TEXT = {"novelty": "layer 1 (new programs)", "rules": "layer 2 (data-flow rules)",
              "corroborated": "corroborated alerts", "learned": "unusual-behaviour (learned) alerts"}
FP_BUDGETS = (None, "99", "99.9", "99.99")
FP_RANK = {"99": 0, "99.9": 1, "99.99": 2, None: 3}         # higher = stricter threshold = fewer learned alerts
PERCENTILES = ("99", "99.9", "99.99")
LEARNED_FLOOD = int(os.environ.get("PDP_LEARNED_BUDGET_WARN", "100"))   # learned alerts / day above this flood analysts
REASON_MAX = 500
# pdp_engine.trainer.TrainConfig defaults of the 0.8 detector-3 breadth settings (tests/unit/test_posture.py checks them)
D3_BREADTH_CAP, D3_BREADTH_FLOOR, D3_BREADTH_HORIZON_S = 10.0, 4.0, 4 * 3600.0


def _engine_path() -> None:
    p = os.environ.get("PDP_ENGINE_PATH", "/opt/pdp/engine")
    if p not in sys.path:
        sys.path.insert(0, p)


# ================================================================================================ settings schema
# ("int", lo, hi) | ("num", lo, hi) | ("bool",) | ("enum", values) | ("tz",) | ("train",) | ("intlist", n_lo, n_hi, lo, hi)
# | ("numpair", lo, hi) | ("layers",)
CONFIG_SCHEMA = {
    "baseline_days": ("int", 1, 60),
    "tz": ("tz",),
    "retain_baseline_events": ("bool",),
    "train": ("train",),
    "window_minutes": ("num", 1, 240),
    "fp_budget": ("enum", FP_BUDGETS),
    "learned_daily_budget": ("int", 0, 1000),
    "learned_alerts": ("bool",),
    "periodic_retrain": ("bool",),
    "early_models": ("bool",),
}
REJECTED_CONFIG = {
    "approved_executables": "approved_executables is no longer an endpoint setting: approve programs through the allow list "
                            "(POST /api/allowlist {\"kind\": \"program\", \"value\": \"<full path>\", \"endpoints\": [\"<endpoint id>\"], "
                            "\"note\": \"<reason>\"}), where every approval is visible, attributed and audited",
}
SERVER_CONFIG = ("kind", "dataset", "dataset_host", "cluster", "refresh_days", "refresh_queued", "refresh_reason",
                 "trusted_addresses", "suppressed_detections")
# Every configurable pdp_engine.trainer.TrainConfig field with its type and a sane range (tests/unit/test_posture.py
# checks this table against the dataclass: a new TrainConfig field is not configurable until it is listed here).
TRAIN_SCHEMA = {
    "emb_dim": ("int", 8, 1024),
    "w2v_epochs": ("int", 1, 100),
    "velox_out_dim": ("int", 8, 1024),
    "velox_lr": ("num", 1e-6, 0.1),
    "velox_epochs": ("int", 1, 100),
    "velox_seed": ("int", 0, 2**31 - 1),
    "velox_runs": ("int", 1, 10),
    "velox_input": ("enum", ("none", "window_degrees", "batch_scale")),       # pdp_engine.models.VELOX_INPUTS
    "velox_degree_features": ("bool",),
    "velox_average_top": ("int", 1, 20),
    "orthrus_seeds": ("intlist", 1, 10, 0, 2**31 - 1),
    "orthrus_hid_dim": ("int", 8, 1024),
    "orthrus_out_dim": ("int", 8, 1024),
    "orthrus_lr": ("num", 1e-6, 0.1),
    "orthrus_dropout": ("num", 0.0, 0.9),
    "orthrus_epochs": ("int", 1, 100),
    "neighbor_size": ("int", 1, 200),
    "weight_decay": ("num", 0.0, 0.1),
    "batch_size": ("int", 16, 65536),
    "patience": ("int", 1, 100),
    "fusion_weights": ("numpair", 0.0, 100.0),
    "fusion_mode": ("enum", ("max", "weighted")),                              # pdp_engine.scoring.fuse_ratios
    "orthrus_aggregate": ("enum", ("best_val_loss", "mean", "weighted")),      # pdp_engine.scoring.aggregate_weights
    "detector3": ("bool",),                     # 0.7 behavioural-likelihood detector (pdp_engine.behaviour)
    "calibration_budget": ("int", 0, 200),      # benign validation nodes allowed over the learned thresholds
    "d3_grouped": ("bool",),                    # detector-3 thresholds per kind of activity
    "d3_breadth": ("bool",),                    # 0.8: detector-3 evidence summed over kinds of activity (behaviour.Breadth)
    "d3_breadth_cap": ("num", 1.0, 100.0),      # nats one event counts at most (d3_breadth_floor must stay below it)
    "d3_breadth_floor": ("num", 0.0, 50.0),     # nats below which an event counts nothing
    "d3_breadth_horizon_s": ("num", 60.0, 7 * 86400.0),    # how long a process's unusual activity keeps counting
    "propagation": ("bool",),
    "propagation_delta": ("num", 0.0, 1.0),
    "propagation_gate": ("num", 0.0, 10.0),
    "propagation_clip": ("num", 1.0, 100.0),
    "propagation_seed": ("num", 0.0, 10.0),
    "propagation_passes": ("int", 1, 5),
    "layer_novelty": ("bool",),                 # 0.8: an optional extra rule (off by default; detector-3 covers it)
    "novelty_as_evidence": ("bool",),
    "corroboration_at_threshold": ("bool",),           # 0.7: new programs alert only when the learned score corroborates
    "layer_rules": ("bool",),
    "learned_daily_budget": ("int", 0, 1000),
    "learned_alerts": ("bool",),
    "corroboration_percentile": ("enum", PERCENTILES),
    "alert_layers": ("layers",),
    "layers_only": ("bool",),
    "fusion_calibration": ("enum", ("fixed", "simulation")),                   # server-side (worker.job_train)
}
WORKER_TRAIN = {"device": "train.device is chosen by the server's training worker and cannot be set"}


def _bad(msg: str):
    raise HTTPException(400, msg)


def _check_value(name: str, spec: tuple, v) -> None:
    kind = spec[0]
    if kind == "int":
        if not (isinstance(v, int) and not isinstance(v, bool) and spec[1] <= v <= spec[2]):
            _bad(f"{name} must be an integer between {spec[1]} and {spec[2]}")
    elif kind == "num":
        if not (isinstance(v, (int, float)) and not isinstance(v, bool) and spec[1] <= v <= spec[2]):
            _bad(f"{name} must be a number between {spec[1]:g} and {spec[2]:g}")
    elif kind == "bool":
        if not isinstance(v, bool):
            _bad(f"{name} must be true or false")
    elif kind == "enum":
        if v not in spec[1]:
            _bad(f"{name} must be one of {list(spec[1])}")
    elif kind == "tz":
        try:
            from zoneinfo import ZoneInfo
            if not isinstance(v, str) or not v or len(v) > 64:
                raise ValueError
            ZoneInfo(v)
        except Exception:  # noqa
            _bad(f"unknown timezone {v!r}")
    elif kind == "intlist":
        if not (isinstance(v, list) and spec[1] <= len(v) <= spec[2] and len(set(map(repr, v))) == len(v)
                and all(isinstance(x, int) and not isinstance(x, bool) and spec[3] <= x <= spec[4] for x in v)):
            _bad(f"{name} must be a list of {spec[1]} to {spec[2]} different integers between {spec[3]} and {spec[4]}")
    elif kind == "numpair":
        if not (isinstance(v, list) and len(v) == 2 and all(isinstance(x, (int, float)) and not isinstance(x, bool)
                                                              and spec[1] <= x <= spec[2] for x in v) and sum(v) > 0):
            _bad(f"{name} must be two numbers between {spec[1]:g} and {spec[2]:g}, not both 0")
    elif kind == "layers":
        if v is None:
            return
        if not (isinstance(v, list) and v and all(x in LAYERS for x in v) and len(set(v)) == len(v)):
            _bad(f"{name} must be null (all layers) or a non-empty list of different layers among {list(LAYERS)}")
    else:  # pragma: no cover
        _bad(f"{name}: not configurable")


def train_fields() -> set[str] | None:
    """Field names of pdp_engine.trainer.TrainConfig (None when the engine cannot be imported here)."""
    try:
        import dataclasses
        _engine_path()
        from pdp_engine.trainer import TrainConfig
        return {f.name for f in dataclasses.fields(TrainConfig)}
    except Exception:  # noqa
        return None


def validate_train(t, engine_check: bool = True) -> None:
    if not isinstance(t, dict):
        _bad("train must be an object of training settings")
    fields = train_fields() if engine_check else None
    for k, v in t.items():
        if k in WORKER_TRAIN:
            _bad(WORKER_TRAIN[k])
        spec = TRAIN_SCHEMA.get(k)
        if spec is None or (fields is not None and k != "fusion_calibration" and k not in fields):
            _bad(f"train: unknown or not configurable key {k!r} (configurable: {sorted(TRAIN_SCHEMA)})")
        _check_value(f"train.{k}", spec, v)
    # (the stored train object is replaced as a whole by a settings change, so the defaults fill what it leaves out)
    if t.get("d3_breadth_floor", D3_BREADTH_FLOOR) >= t.get("d3_breadth_cap", D3_BREADTH_CAP):
        _bad(f"train.d3_breadth_floor ({t.get('d3_breadth_floor', D3_BREADTH_FLOOR):g}) must be below train.d3_breadth_cap "
             f"({t.get('d3_breadth_cap', D3_BREADTH_CAP):g}): otherwise no activity counts as detector-3 evidence")


def validate_config(cfg, engine_check: bool = True) -> None:
    """Types and ranges of an endpoint configuration patch; 400 with a clear message on the first problem."""
    if not isinstance(cfg, dict):
        _bad("config must be an object")
    for k, v in cfg.items():
        if k in REJECTED_CONFIG:
            _bad(REJECTED_CONFIG[k])
        if k in SERVER_CONFIG:
            _bad(f"{k} is managed by the server and cannot be set")
        spec = CONFIG_SCHEMA.get(k)
        if spec is None:
            _bad(f"unknown config keys: {[k]} (configurable: {sorted(CONFIG_SCHEMA)})")
        if spec[0] == "train":
            validate_train(v, engine_check)
        else:
            _check_value(k, spec, v)


# ================================================================================================ weakening
def detection_settings(cfg: dict | None) -> dict:
    """The detection-relevant settings of a stored endpoint configuration, defaults filled in (TrainConfig and
    worker defaults). learned_alerts None = the model's default."""
    cfg = cfg or {}
    t = cfg.get("train") if isinstance(cfg.get("train"), dict) else {}
    al = t.get("alert_layers")
    # defaults = TrainConfig's (0.8: layer 1 off - an optional extra rule -, the learned layer alerts, detector-3 with
    # breadth evidence and propagation on, thresholds at a validation budget of 10)
    return {"layer_novelty": t.get("layer_novelty", False) is True, "layer_rules": t.get("layer_rules", True) is not False,
            "detector3": t.get("detector3", True) is not False, "propagation": t.get("propagation", True) is not False,
            "calibration_budget": t.get("calibration_budget", 10),
            "d3_breadth": t.get("d3_breadth", True) is not False, "d3_breadth_cap": t.get("d3_breadth_cap", D3_BREADTH_CAP),
            "d3_breadth_floor": t.get("d3_breadth_floor", D3_BREADTH_FLOOR),
            "d3_breadth_horizon_s": t.get("d3_breadth_horizon_s", D3_BREADTH_HORIZON_S),
            "alert_layers": set(LAYERS) if al is None else set(al) if isinstance(al, list) else set(LAYERS),
            "layers_only": t.get("layers_only") is True,
            "corroboration_percentile": t.get("corroboration_percentile", "99.9"),
            "train_learned_alerts": t.get("learned_alerts"), "train_budget": t.get("learned_daily_budget", 20),
            "learned_alerts": cfg.get("learned_alerts"), "learned_daily_budget": cfg.get("learned_daily_budget"),
            "periodic_retrain": cfg.get("periodic_retrain") is not False, "early_models": cfg.get("early_models") is not False,
            "fp_budget": cfg.get("fp_budget"), "baseline_days": cfg.get("baseline_days", 7),
            "retain_baseline_events": cfg.get("retain_baseline_events") is True}


def alerting_layers(cfg: dict | None) -> set[str]:
    """Layers that can raise alerts with these settings (learned only when its alerts are turned on explicitly)."""
    d = detection_settings(cfg)
    out = set(d["alert_layers"])
    if not d["layer_novelty"]:
        out.discard("novelty")
    if not d["layer_rules"]:
        out.discard("rules")
    if not ({"novelty", "rules"} & out):
        out.discard("corroborated")
    if d["learned_alerts"] is False or (d["learned_alerts"] is None and d["train_learned_alerts"] is False) or d["layers_only"]:
        out.discard("learned")
    return out


def check_floor(cfg: dict) -> None:
    """A configuration in which neither the learned layer nor the data-flow rules can alert is refused outright (not
    even with a reason): it would leave the endpoint enrolled and looking protected while nothing could ever alert."""
    if not ({"rules", "learned"} & alerting_layers(cfg)):
        _bad("this would stop both the learned detection and the data-flow rules from alerting on the endpoint; "
             "at least one of them must stay on (retire the endpoint instead if it should not be protected)")


def weakenings(before: dict | None, after: dict | None) -> list[str]:
    """Human-readable list of the ways `after` detects less than `before` (both full stored configurations)."""
    b, a = detection_settings(before), detection_settings(after)
    out = []
    # 0.8: layer 1 (new programs) is an optional extra rule, off by default (detector-3 covers it): turning it on or
    # off, or dropping it from alert_layers, is not weakening; the floor is the learned layer or the data-flow rules
    if b["layer_rules"] and not a["layer_rules"]:
        out.append(f"{LAYER_TEXT['rules']} turned off")
    dropped = [x for x in LAYERS if x != "novelty" and x in b["alert_layers"] and x not in a["alert_layers"]]
    if dropped:
        out.append("alerting turned off for " + ", ".join(LAYER_TEXT[x] for x in dropped))
    if a["layers_only"] and not b["layers_only"]:
        out.append("learned detectors no longer trained (layers_only)")
    if b["detector3"] and not a["detector3"]:
        out.append("behavioural-likelihood detector (detector-3) turned off")
    if b["propagation"] and not a["propagation"]:
        out.append("propagation of learned suspicion turned off")
    if isinstance(a["calibration_budget"], int) and isinstance(b["calibration_budget"], int) and a["calibration_budget"] < b["calibration_budget"]:
        out.append(f"learned thresholds raised (calibration budget {b['calibration_budget']} -> {a['calibration_budget']})")
    if a["detector3"]:      # (detector-3 off is reported above; its breadth settings do not matter then)
        num = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)  # noqa: E731
        if b["d3_breadth"] and not a["d3_breadth"]:
            out.append("detector-3 breadth evidence turned off (unusual activity of several kinds no longer adds up)")
        elif a["d3_breadth"]:
            for k, what in (("d3_breadth_cap", "cap"), ("d3_breadth_floor", "floor")):
                if num(a[k]) and num(b[k]) and a[k] > b[k]:
                    out.append(f"detector-3 breadth {what} raised ({b[k]:g} -> {a[k]:g} nats: the learned layer is less sensitive)")
            hb, ha = b["d3_breadth_horizon_s"], a["d3_breadth_horizon_s"]
            if num(ha) and num(hb) and ha < hb:
                out.append(f"detector-3 breadth horizon shortened ({hb:g} -> {ha:g} s)")
    cb, ca = b["corroboration_percentile"], a["corroboration_percentile"]
    if cb in PERCENTILES and ca in PERCENTILES and PERCENTILES.index(ca) > PERCENTILES.index(cb):
        out.append(f"corroboration threshold raised from the {cb}th to the {ca}th percentile")
    if b["learned_alerts"] is True and a["learned_alerts"] is not True:
        out.append(f"{LAYER_TEXT['learned']} turned off")
    if b["train_learned_alerts"] is not False and a["train_learned_alerts"] is False:
        out.append(f"{LAYER_TEXT['learned']} turned off in the model's training settings")
    for key, label, bv, av in (("learned_daily_budget", "daily limit of unusual-behaviour alerts", b["learned_daily_budget"], a["learned_daily_budget"]),
                               ("train_budget", "daily limit of unusual-behaviour alerts (training settings)", b["train_budget"], a["train_budget"])):
        if isinstance(av, int) and av > LEARNED_FLOOD and (not isinstance(bv, int) or av > bv):
            out.append(f"{label} raised to {av} per day (a flood that buries real alerts)")
        if av == 0 and bv != 0 and (a["learned_alerts"] is True or a["train_learned_alerts"] is True):
            out.append(f"{label} set to 0 while those alerts are on")
    if b["periodic_retrain"] and not a["periodic_retrain"]:
        out.append("periodic retraining turned off (the model goes stale)")
    if b["early_models"] and not a["early_models"]:
        out.append("early models turned off (no detection while the endpoint learns)")
    if a["fp_budget"] in FP_RANK and b["fp_budget"] in FP_RANK and FP_RANK[a["fp_budget"]] > FP_RANK[b["fp_budget"]]:
        out.append(f"learned-alert threshold raised (fp_budget {b['fp_budget']} -> {a['fp_budget']})")
    if isinstance(a["baseline_days"], int) and isinstance(b["baseline_days"], int) and a["baseline_days"] < b["baseline_days"]:
        out.append(f"baseline shortened from {b['baseline_days']} to {a['baseline_days']} days")
    if a["retain_baseline_events"] and not b["retain_baseline_events"]:
        out.append("raw activity kept after training (privacy: every recorded process, file and connection is retained)")
    return out


def org_weakenings(before: dict, after: dict) -> list[str]:
    """Organisation settings: data retention lowered, two-factor sign-in no longer required."""
    out = []
    if after.get("retention_days") is not None and before.get("retention_days") is not None and after["retention_days"] < before["retention_days"]:
        out.append(f"retention lowered from {before['retention_days']} to {after['retention_days']} days (older alerts and incidents are deleted)")
    if before.get("require_mfa") and after.get("require_mfa") is False:
        out.append("two-factor sign-in no longer required")
    return out


def require_reason(changes: list[str], reason: str | None) -> str | None:
    r = (reason or "").strip()
    if len(r) > REASON_MAX:
        _bad(f"reason: at most {REASON_MAX} characters")
    if changes and not r:
        _bad("Reason required: this change weakens detection (" + "; ".join(changes) + "). Send it again with a reason "
             "(field 'reason'); the reason is recorded in the audit log and your organisation's admins are notified")
    return r or None


# ================================================================================================ audit details
SECRET_KEY = re.compile(r"secret|password|passwd|token|totp|recovery|private|credential|api_?key|signature|cookie", re.I)
URL_KEY = re.compile(r"^(target|url|webhook|endpoint_url)$", re.I)


def redact_value(key: str, v):
    if v is None or v == "" or v == [] or v == {}:
        return v
    if SECRET_KEY.search(key or ""):
        return "[redacted]"
    if isinstance(v, str) and URL_KEY.search((key or "").rsplit(".", 1)[-1]) and "://" in v:
        scheme, rest = v.split("://", 1)
        host = re.split(r"[/?#]", rest.split("@")[-1], maxsplit=1)[0]
        return f"{scheme}://{host}/..." if len(rest) > len(host) else f"{scheme}://{host}"
    if isinstance(v, dict):
        return {k: redact_value(f"{key}.{k}" if key else k, x) for k, x in v.items()}
    if isinstance(v, str) and len(v) > 300:
        return v[:300] + "..."
    if isinstance(v, list) and len(v) > 50:
        return [redact_value(key, x) for x in v[:50]] + [f"... {len(v) - 50} more"]
    return v


def _flat(d, prefix="") -> dict:
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict) and v and not SECRET_KEY.search(str(k)):
                out.update(_flat(v, key))
            else:
                out[key] = v
    return out


def diff(before, after) -> dict:
    """{dotted key: {"before", "after"}} for the keys that differ, secrets redacted (never their values)."""
    fb, fa = _flat(before or {}), _flat(after or {})
    out = {}
    for k in sorted(set(fb) | set(fa)):
        if fb.get(k) != fa.get(k):
            if SECRET_KEY.search(k):
                out[k] = {"before": "[redacted]" if fb.get(k) else None, "after": "[redacted]" if fa.get(k) else None,
                          "changed": True}
            else:
                out[k] = {"before": redact_value(k, fb.get(k)), "after": redact_value(k, fa.get(k))}
    return out


def _who(c, s: dict | None):
    if not s or s.get("u") is None:
        return None, None
    u = db.q(c, "SELECT username FROM users WHERE id=%s", (s["u"],), one=True)
    return s["u"], (u["username"] if u else None)


def audit_change(c, s: dict, action: str, target: str | None = None, *, before=None, after=None, reason: str | None = None,
                 extra: dict | None = None, status: int = 200) -> None:
    """One audit-log row with details, in the caller's transaction (so it commits or rolls back with the change)."""
    uid, name = _who(c, s)
    detail = {}
    if before is not None or after is not None:
        detail["changes"] = diff(before, after)
    if reason:
        detail["reason"] = reason[:REASON_MAX]
    for k, v in (extra or {}).items():
        detail[k] = redact_value(k, v)
    db.q(c, "INSERT INTO audit_log (org_id, user_id, username, action, target, status, detail) VALUES (%s,%s,%s,%s,%s,%s,%s)",
         (s.get("org"), uid, name, action[:200], (target or "")[:300] or None, status, json.dumps(detail, default=str)))


# ================================================================================================ security events
EVENT_KINDS = ("detection_weakened", "response_action")


def security_event(c, org_id, kind: str, title: str, *, severity: str = "high", s: dict | None = None, endpoint_id=None,
                   detail: dict | None = None) -> None:
    uid, name = _who(c, s)
    db.q(c, "INSERT INTO security_events (org_id, kind, severity, endpoint_id, user_id, username, title, detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
         (org_id, kind, severity, endpoint_id, uid, name, title[:300], json.dumps(detail or {}, default=str)))


def weakened(c, s: dict, changes: list[str], reason: str | None, *, subject: str, endpoint_id=None, before=None, after=None,
             extra: dict | None = None) -> None:
    """A weakening change was made: the security event the admins are notified of (the audit row is the caller's)."""
    if not changes:
        return
    title = f"Detection weakened ({subject}): {changes[0]}" + (f" (+{len(changes) - 1} more)" if len(changes) > 1 else "")
    security_event(c, s["org"], "detection_weakened", title, severity="high", s=s, endpoint_id=endpoint_id,
                   detail={"type": "detection_weakened", "subject": subject, "changes": changes, "reason": reason,
                           "diff": diff(before, after) if (before is not None or after is not None) else None, **(extra or {})})


def message(r: dict, console: str) -> dict:
    """A security event as a notification message (notify.deliver formats)."""
    d = r.get("detail") or {}
    link = f"{console}/#/endpoints/{r['endpoint_id']}" if r.get("endpoint_id") else f"{console}/#/security"
    who = r.get("username") or "the system"
    lines = [r["title"], "", f"By: {who}", f"When: {r['at']:%Y-%m-%d %H:%M} UTC" if isinstance(r.get("at"), datetime) else ""]
    if d.get("reason"):
        lines.append(f"Reason given: {d['reason']}")
    for ch in d.get("changes") or []:
        lines.append(f"- {ch}")
    lines += ["", f"Open in the console: {link}"]
    ep = {"id": str(r["endpoint_id"]), "name": d.get("endpoint_name") or "", "hostname": None} if r.get("endpoint_id") else None
    return {"event": r["kind"], "subject": f"[M.D Lab] {r['title']}", "text": "\n".join(x for x in lines if x is not None),
            "title": r["title"], "severity": r.get("severity") or "high", "link": link,
            "data": {"type": r["kind"], "id": r["id"], "by": r.get("username"), "reason": d.get("reason"), "changes": d.get("changes"),
                     "detail": {k: v for k, v in d.items() if k not in ("reason", "changes")}, "endpoint": ep, "link": link,
                     "at": r["at"].isoformat() if isinstance(r.get("at"), datetime) else r.get("at")}}


def channel_kinds(events) -> list[str]:
    """Security events a channel receives: its own subscription, and every channel that receives incidents gets them
    too (an admin cannot keep incident notifications while silencing the ones about weakened detection)."""
    ev = set(events or [])
    return [k for k in EVENT_KINDS if k in ev or "incident" in ev]


def security_messages(c, ch: dict, console: str) -> list[tuple[str, dict]]:
    kinds = channel_kinds(ch.get("events"))
    if not kinds:
        return []
    rows = db.q(c, "SELECT * FROM security_events WHERE org_id=%s AND kind = ANY(%s) AND at >= %s AND at > now() - interval '7 days' "
                   "ORDER BY id LIMIT 200", (ch["org_id"], kinds, ch["created_at"]))
    return [(f"sec:{r['id']}", message(r, console)) for r in rows]


SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def channel_silenced(c, s: dict, before: dict, after: dict | None) -> None:
    """Audit a notification channel change (before/after as the channel API shows them, the URL reduced to its host).
    Removing or disabling a channel, dropping events from it, raising its minimum severity or pointing it elsewhere
    is a security event: an insider would silence the admins' channels before weakening detection."""
    audit_change(c, s, "notification channel removed" if after is None else "notification channel changed",
                 f"channel_id={before['id']}", before=before, after=after)
    name, out = before.get("name") or f"#{before['id']}", []
    if after is None:
        out.append(f"notification channel {name} removed")
    else:
        if before.get("enabled") and not after.get("enabled"):
            out.append(f"notification channel {name} disabled")
        dropped = [e for e in before.get("events") or [] if e not in (after.get("events") or [])]
        if dropped:
            out.append(f"notification channel {name} no longer receives {', '.join(dropped)}")
        if SEV_RANK.get(after.get("min_severity"), 0) > SEV_RANK.get(before.get("min_severity"), 0):
            out.append(f"notification channel {name} now only receives {after['min_severity']} incidents and above")
        if after.get("target") != before.get("target"):
            out.append(f"notification channel {name} sends to a new destination")
        if before.get("every_alert") and not after.get("every_alert"):
            out.append(f"notification channel {name} no longer receives every alert (SIEM feed)")
    if out:
        security_event(c, s["org"], "detection_weakened", f"Notifications reduced: {out[0]}" + (f" (+{len(out) - 1} more)" if len(out) > 1 else ""),
                       severity="high", s=s, detail={"type": "notifications_reduced", "changes": out, "diff": diff(before, after)})


# ================================================================================================ programs
_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "pdksh", "csh", "tcsh", "fish", "ash", "rbash", "yash", "busybox", "toybox",
           "env", "xargs", "nohup", "setsid", "timeout", "nice", "ionice", "stdbuf", "chrt", "taskset", "script", "expect", "flock",
           "watch", "find", "awk", "gawk", "mawk", "nawk", "sudo", "su", "doas", "runuser", "pkexec", "chroot", "unshare", "nsenter",
           "systemd-run", "at", "crontab", "screen", "tmux", "socat", "ncat", "nc", "netcat", "gdb", "strace", "ltrace", "make",
           "ssh", "scp", "rsync", "openssl", "curl", "wget", "docker", "kubectl", "vi", "vim", "nvim", "emacs", "less", "more", "man",
           "tclsh", "wish", "osascript", "rscript", "r", "jrunscript", "jjs", "dotnet", "mono", "wine",
           # Windows (program_name strips .exe / .com)
           "cmd", "powershell", "powershell_ise", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec", "wmic",
           "certutil", "bitsadmin", "installutil", "regasm", "regsvcs", "msbuild", "cmstp", "forfiles", "schtasks", "wsl", "msxsl",
           "odbcconf", "pcalua", "ieexec", "mavinject", "control", "hh", "infdefaultinstall", "presentationhost", "xwizard",
           "syncappvpublishingserver", "scriptrunner", "conhost", "explorer", "dllhost", "svchost", "taskeng", "taskhostw",
           "csc", "vbc", "jsc", "ftp", "tftp", "winrm", "winrs", "psexec", "psexesvc", "sc", "reg", "runas", "appinstaller"}
_INTERP = re.compile(r"^(python|pypy|perl|php|php-cgi|ruby|irb|lua|luajit|node|nodejs|deno|bun|java|javaw|julia|guile|racket|"
                     r"sbcl|ocaml|erl|escript|elixir|groovy|scala|kotlin|swift|tclsh|wish|pwsh)[\d.]*[wm]?$")
_LOADER = re.compile(r"^(ld([-.].*)?\.so(\.\d+)*|ld-musl.*|ld64.*)$")


def _layers():
    _engine_path()
    from pdp_engine import layers
    return layers


def program_key(value: str) -> str:
    """The agent's program identity (pdp_engine.layers.program_key): the allow list compares programs the same way."""
    return _layers().program_key(value)


def program_name(key: str) -> str:
    return _layers().program_name(key)


def is_interpreter(value: str) -> bool:
    """An interpreter, shell, loader or system binary that runs other code: approving it as normal hides whatever is
    run through it."""
    n = program_name(program_key(value))
    return n in _SHELLS or bool(_INTERP.match(n)) or bool(_LOADER.match(n))


def program_matches(value: str, exe: str | None) -> bool:
    """An allow-list program value covers the program `exe` exactly when the agent's layer 1 treats it as approved:
    the same program key (no basename matching: approving python3 does not approve /dev/shm/x/python3)."""
    if not exe or not value:
        return False
    return exe == value or program_key(exe) == program_key(value)


def check_program(value: str, *, name_only_ok: bool, force: bool, reason: str | None) -> dict:
    """Validate a program for the allow list -> {value, key, interpreter}; 400 with a clear message otherwise."""
    v = (value or "").strip()
    if not v:
        _bad("enter a program")
    if any(ch in v for ch in "*?") or re.search(r"\[[^\]]*\]", v):
        _bad("wildcards are not accepted: name one program by its full path (e.g. /usr/local/bin/backup-agent)")
    if v.endswith(("/", "\\")) or v in (".", "..", "~") or v.rstrip("/\\") == "":
        _bad("a folder is not a program: name one program by its full path (e.g. /usr/local/bin/backup-agent)")
    k = program_key(v)
    if "/" not in k:
        if not name_only_ok:
            _bad(f"name the program by its full path (e.g. /usr/bin/{v}): a bare name is accepted only for endpoints whose "
                 "collector records programs without paths, and the allow list compares programs exactly as the agent does")
    elif not k.startswith("/"):
        _bad("a program path must be absolute (e.g. /usr/bin/links or C:\\Program Files\\App\\app.exe)")
    risky = is_interpreter(v)
    if risky and not (force and (reason or "").strip()):
        _bad(f"Confirmation required: {v} is an interpreter, shell or system tool that runs other code; allowing it hides "
             "new programs and behaviour run through it. To allow it anyway send \"force\": true with a reason (note)")
    return {"value": v, "key": k, "interpreter": risky}


def entry_risks(e: dict) -> list[str]:
    """Why an existing allow-list entry deserves a second look (shown in the allow list and the endpoint posture)."""
    out = []
    if e.get("kind") == "program" or (e.get("kind") == "detection" and e.get("rule") in ("learned", "novel_executable")):
        v = e.get("value") or ""
        try:
            k = program_key(v)
            if "/" not in k:
                out.append("name_only")
            if is_interpreter(v):
                out.append("interpreter")
        except Exception:  # noqa - engine unavailable
            pass
        if "*" in v or "?" in v:
            out.append("wildcard")
    if e.get("kind") == "address":
        v = e.get("value") or ""
        if "/" in v:
            try:
                bits = int(v.rsplit("/", 1)[1])
                if (":" not in v and bits <= 20) or (":" in v and bits <= 56):
                    out.append("large_network")
            except ValueError:
                pass
    return out


def endpoint_records_paths(c, endpoint_id: str) -> bool | None:
    """Whether the endpoint's recorded programs carry paths (from its model's known programs); None when unknown."""
    b = db.q(c, "SELECT b.path FROM endpoints e JOIN bundles b ON b.id=e.current_bundle WHERE e.id=%s", (endpoint_id,), one=True)
    if not b:
        return None
    try:
        spec = json.load(open(os.path.join(b["path"], "layers.json")))
    except (OSError, ValueError):
        return None
    known = [k for k in spec.get("known_executables") or [] if k not in ("None", "", "null")]
    if not known:
        return None
    return any("/" in program_key(k) for k in known)


# ================================================================================================ posture
STALE_DAYS = float(os.environ.get("PDP_POSTURE_STALE_DAYS", "60"))      # retraining off and the model older than this
OLD_DAYS = float(os.environ.get("PDP_POSTURE_OLD_DAYS", "120"))         # any model older than this
LEVEL_RANK = {"ok": 0, "warning": 1, "error": 2}


def compute(ep: dict, bundle: dict | None, entries: list[dict] | None = None, now: float | None = None) -> dict:
    """Detection posture of one endpoint -> {level: ok|warning|error, problems: [{key, level, text}]}.
    ep: id, phase, kind, config, enrolled_at, current_bundle; bundle: manifest, created_at (or None)."""
    now = time.time() if now is None else now
    cfg = ep.get("config") or {}
    man = (bundle or {}).get("manifest") or {}
    out = []

    def add(key, level, text):
        out.append({"key": f"posture:{key}", "level": level, "text": text})

    if ep.get("kind", "live") != "live" or ep.get("phase") == "retired":
        return {"level": "ok", "problems": []}
    need = int(cfg.get("baseline_days", 7) if isinstance(cfg.get("baseline_days", 7), int) else 7) + 1
    enrolled = ep.get("enrolled_at")
    age_d = (now - enrolled.timestamp()) / 86400 if isinstance(enrolled, datetime) else None
    has_model = bool(ep.get("current_bundle")) and bundle is not None
    mat = man.get("maturity") or {}
    early = bool(mat.get("early"))
    if ep.get("phase") == "degraded":
        add("degraded", "error", "Detection is degraded: the last model build failed"
            + (", so the endpoint is still protected by an older model" if has_model else " and the endpoint has no model"))
    if not has_model:
        if ep.get("phase") in ("protected", "degraded") or (age_d is not None and age_d > need + 2):
            add("no_model", "error", "The endpoint has no detection model" + (f" {age_d:.0f} days after it was enrolled" if age_d else ""))
    elif early and (ep.get("phase") in ("protected", "degraded") or (age_d is not None and age_d > need + 3)):
        add("early_model", "warning", "Detection still runs on an early model (trained on "
            f"{mat.get('baseline_hours', '?')} hours of activity): the final model was never built")
    if has_model and not early:
        created = (bundle or {}).get("created_at")
        model_d = (now - created.timestamp()) / 86400 if isinstance(created, datetime) else None
        if model_d is not None and cfg.get("periodic_retrain") is False and model_d > STALE_DAYS:
            add("stale_model", "warning", f"The model is {model_d:.0f} days old and periodic retraining is turned off")
        elif model_d is not None and model_d > OLD_DAYS:
            add("old_model", "warning", f"The model is {model_d:.0f} days old (periodic retraining has not replaced it)")
        lay = man.get("layers")
        if man and lay is None:
            add("no_layers", "warning", "The model predates the deterministic layers (new programs, data-flow rules): retrain it")
        elif isinstance(lay, dict):
            if lay.get("rules") is False:     # (0.8: layer 1 off is the default, not a problem)
                add("model_rules_off", "error", f"{LAYER_TEXT['rules'].capitalize()} is turned off in the current model")
            cov = lay.get("coverage") or {}
            if cov:   # 0.6: telemetry the rule layers need (pdp_engine.layers.telemetry_coverage)
                P, F = int(cov.get("processes") or 0), int(cov.get("flows") or 0)
                if P >= 20 and cov.get("processes_with_path", 0) < 0.5 * P:
                    add("telemetry_paths", "warning", f"Only {100 * cov.get('processes_with_path', 0) / P:.0f} % of processes were recorded with a "
                        "program path: new-program detection cannot tell programs apart (check the collector)")
                # (no exec events is normal on Windows - process starts carry the image path, image_exec - so not a problem)
                if F >= 20 and cov.get("flows_with_address", 0) < 0.05 * F:
                    add("telemetry_addresses", "warning", "Network connections were recorded without remote addresses: the data-flow "
                        "rules cannot tell untrusted sources (check the collector)")
        pol = man.get("learned_policy") or {}
        al = pol.get("alert_layers")
        if isinstance(al, list):
            missing = [x for x in ("rules", "corroborated") if x not in al]
            if missing:
                add("model_alert_layers", "error", "The current model does not alert on " + ", ".join(LAYER_TEXT[x] for x in missing))
        if man.get("layers_only"):
            add("model_layers_only", "warning", "The current model has no learned detectors (rules-only model)")
        learned_on = cfg.get("learned_alerts") if isinstance(cfg.get("learned_alerts"), bool) else bool(pol.get("learned_alerts", True) if pol else False)
        budget = cfg.get("learned_daily_budget") if isinstance(cfg.get("learned_daily_budget"), int) else pol.get("daily_budget", 20)
        if learned_on and isinstance(budget, int) and budget > LEARNED_FLOOD:
            add("learned_flood", "warning", f"Unusual-behaviour alerts are on with a limit of {budget} per day: a flood of them buries real detections")
    # settings that take effect at the next training (or now, on the agent)
    try:
        if isinstance(cfg.get("train"), dict):
            validate_train(cfg["train"], engine_check=False)
    except HTTPException as e:
        add("invalid_train", "error", f"The endpoint's training settings are invalid, so its next training fails: {e.detail}")
    for w in weakenings({}, cfg):
        if w.startswith("raw activity"):
            continue
        lvl = "error" if (" turned off" in w and ("layer" in w or "alerting" in w)) else "warning"
        add("setting:" + re.sub(r"[^a-z_]+", "_", w.split(" (")[0].lower())[:60].strip("_"), lvl, f"Setting: {w}")
    risky = sorted({e["value"] for e in entries or [] if {"interpreter", "name_only", "wildcard"} & set(entry_risks(e))})
    if risky:
        add("allowlist", "warning", "The allow list approves programs that hide what runs through them or match by name only: "
            + ", ".join(risky[:5]) + (f" and {len(risky) - 5} more" if len(risky) > 5 else ""))
    level = max((p["level"] for p in out), key=lambda x: LEVEL_RANK[x], default="ok")
    return {"level": level, "problems": out}


def for_endpoint(c, endpoint_id: str) -> dict:
    ep = db.q(c, "SELECT id, name, phase, kind, config, enrolled_at, current_bundle FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
    if not ep:
        return {"level": "ok", "problems": []}
    b = db.q(c, "SELECT manifest, created_at FROM bundles WHERE id=%s", (ep["current_bundle"],), one=True) if ep["current_bundle"] else None
    from .allowlist import entries_for
    return compute(ep, b, entries_for(c, endpoint_id))


def worsened(old: dict | None, problems: list[dict]) -> list[dict]:
    """Problems that are new or more severe than in the last recorded state {key: level}."""
    old = old or {}
    return [p for p in problems if LEVEL_RANK[p["level"]] > LEVEL_RANK.get(old.get(p["key"], "ok"), 0)]


_last_refresh = 0.0
REFRESH_S = float(os.environ.get("PDP_POSTURE_REFRESH_S", "300"))


def refresh_all(force: bool = False) -> int:
    """Recompute every live endpoint's posture; a worsening becomes a detection_weakened security event (notified).
    Run by the notifier every few minutes. -> number of events recorded."""
    global _last_refresh
    if not force and time.time() - _last_refresh < REFRESH_S:
        return 0
    _last_refresh = time.time()
    n = 0
    with db.conn() as c:
        eps = db.q(c, "SELECT e.id, e.name, e.org_id, e.phase, e.kind, e.config, e.enrolled_at, e.current_bundle, b.manifest, "
                      "b.created_at AS bundle_created_at FROM endpoints e LEFT JOIN bundles b ON b.id=e.current_bundle "
                      "WHERE e.kind='live' AND e.phase <> 'retired'")
        prev = {r["k"][8:]: r["v"] for r in db.q(c, "SELECT k, v FROM kv WHERE k LIKE 'posture:%%'")}
        allow: dict = {}
        for e in db.q(c, "SELECT kind, value, rule, endpoint_ids, org_id FROM allowlist"):
            allow.setdefault(str(e["org_id"]), []).append(e)
        for ep in eps:
            eid = str(ep["id"])
            entries = [e for e in allow.get(str(ep["org_id"]), []) if e["endpoint_ids"] is None or eid in set(e["endpoint_ids"])]
            b = {"manifest": ep["manifest"], "created_at": ep["bundle_created_at"]} if ep["current_bundle"] else None
            p = compute(ep, b, entries)
            state = {x["key"]: x["level"] for x in p["problems"]}
            for x in worsened(prev.get(eid), p["problems"]):
                security_event(c, ep["org_id"], "detection_weakened", f"{ep['name']}: {x['text']}",
                               severity="high" if x["level"] == "error" else "medium", endpoint_id=eid,
                               detail={"type": "detection_posture", "problem": x["key"], "level": x["level"], "endpoint_name": ep["name"]})
                n += 1
            if state != (prev.get(eid) or {}) or eid not in prev:
                db.q(c, "INSERT INTO kv (k, v, updated_at) VALUES (%s,%s,now()) ON CONFLICT (k) DO UPDATE SET v=excluded.v, updated_at=now()",
                     (f"posture:{eid}", json.dumps(state)))
    return n


# ================================================================================================ resource limits
def _rate(var: str, default: str) -> tuple[float, float]:
    try:
        cap, per_h = (float(x) for x in os.environ.get(var, default).split("/"))
        return max(1.0, cap), max(0.0, per_h)
    except ValueError:
        cap, per_h = (float(x) for x in default.split("/"))
        return cap, per_h


# burst / per hour, per user (PDP_RATE_EXPORT=10/30 etc.)
RATES = {"export": _rate("PDP_RATE_EXPORT", "10/30"), "hunt": _rate("PDP_RATE_HUNT", "20/120"), "sim": _rate("PDP_RATE_SIM", "5/20")}
RATE_TEXT = {"export": "alert exports", "hunt": "hunts", "sim": "simulation campaigns and detection checks"}
SIM_RUNS_PER_DAY = int(os.environ.get("PDP_SIM_RUNS_PER_DAY", "20000"))


def bucket(tokens: float | None, elapsed_s: float, cap: float, per_hour: float) -> tuple[bool, float]:
    """Token bucket step (what the SQL in take() computes): -> (allowed, tokens left)."""
    have = cap if tokens is None else min(cap, tokens + elapsed_s * per_hour / 3600.0)
    return (True, have - 1) if have >= 1 else (False, have)


def take(c, user_id: int, kind: str) -> None:
    """Spend one token of the user's bucket for `kind`, or 429 with Retry-After. Atomic across API workers (the row lock
    of the upsert); call inside the request's transaction."""
    cap, per_h = RATES[kind]
    ref = per_h / 3600.0
    row = db.q(c, "INSERT INTO rate_buckets (user_id, kind, tokens, at) VALUES (%s,%s,%s,clock_timestamp()) "
                  "ON CONFLICT (user_id, kind) DO UPDATE SET "
                  "tokens = LEAST(%s, rate_buckets.tokens + extract(epoch FROM clock_timestamp() - rate_buckets.at) * %s) - 1, at = clock_timestamp() "
                  "WHERE LEAST(%s, rate_buckets.tokens + extract(epoch FROM clock_timestamp() - rate_buckets.at) * %s) >= 1 RETURNING tokens",
               (user_id, kind, cap - 1, cap, ref, cap, ref), one=True)
    if row:
        return
    cur = db.q(c, "SELECT LEAST(%s, tokens + extract(epoch FROM clock_timestamp() - at) * %s) AS have FROM rate_buckets WHERE user_id=%s AND kind=%s",
               (cap, ref, user_id, kind), one=True)
    have = float(cur["have"]) if cur else 0.0
    wait = int((1 - have) / ref) + 1 if ref > 0 else 3600
    raise HTTPException(429, f"too many {RATE_TEXT[kind]}: at most {cap:g} at once and {per_h:g} per hour per user; try again in {wait} s",
                        headers={"Retry-After": str(wait)})


def check_sim_quota(c, org_id: str, runs: int) -> None:
    """Simulation runs (attack replays against a model, on the shared GPU workers) per organisation and 24 hours."""
    used = int(db.q(c, "SELECT coalesce(sum(coalesce((sc.spec->>'runs')::int, 40)), 0) AS n FROM sim_campaigns sc "
                       "JOIN endpoints e ON e.id=sc.endpoint_id WHERE e.org_id=%s AND sc.created_at > now() - interval '1 day'",
                    (org_id,), one=True)["n"])
    if used + int(runs) > SIM_RUNS_PER_DAY:
        raise HTTPException(429, f"your organisation may run at most {SIM_RUNS_PER_DAY} simulated attacks per 24 hours "
                                 f"({used} used, {int(runs)} requested); try again later or ask for fewer runs")


# ================================================================================================ API
@router.get("/api/endpoints/{endpoint_id}/posture")
def endpoint_posture(endpoint_id: str, s=Depends(session)):
    require_endpoint(s, endpoint_id)
    with db.conn() as c:
        return {"ok": True, "posture": for_endpoint(c, endpoint_id)}


@router.get("/api/security-events")
def list_security_events(limit: int = 100, s=Depends(admin)):
    """What the organisation's admins are told about: weakened detection (with who and why), posture worsening,
    silenced notification channels, response actions."""
    with db.conn() as c:
        rows = db.q(c, "SELECT se.id, se.kind, se.severity, se.endpoint_id, e.name AS endpoint, se.username AS who, se.title, se.detail, se.at "
                       "FROM security_events se LEFT JOIN endpoints e ON e.id=se.endpoint_id WHERE se.org_id=%s ORDER BY se.at DESC, se.id DESC LIMIT %s",
                    (s["org"], max(1, min(int(limit), 1000))))
    return {"ok": True, "events": [dict(r, endpoint_id=str(r["endpoint_id"]) if r["endpoint_id"] else None) for r in rows]}
