"""Control-plane misuse resistance (pdp_server.posture, 0.6): the typed settings schema, what counts as weakening
detection, reasons, redacted audit diffs, allow-list program rules (matched like the agent's layer 1), detection
posture, security-event messages, token buckets. Pure functions; the SQL paths run against a database in
tests/e2e. Run: PYTHONPATH=server:engine python tests/unit/test_posture.py"""
import dataclasses
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

os.environ["PDP_SESSION_SECRET"] = os.path.join(tempfile.mkdtemp(), "session.secret")
os.environ["PDP_CONSOLE_URL"] = "https://pdp.example"
from fastapi import HTTPException  # noqa: E402

from pdp_server import posture as P  # noqa: E402
from pdp_server import allowlist as A  # noqa: E402
from pdp_server.health import problems  # noqa: E402

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


def refused(fn, *a, **kw):
    """The 400 message, or None when accepted."""
    try:
        fn(*a, **kw)
    except HTTPException as e:
        return str(e.detail) if e.status_code == 400 else f"status {e.status_code}"
    return None


# ---- 1. settings schema: types, ranges, keys the server or the worker control
ok_cfg = {"baseline_days": 7, "tz": "Europe/Paris", "window_minutes": 15, "fp_budget": "99.9", "learned_daily_budget": 20,
          "learned_alerts": True, "periodic_retrain": True, "early_models": False, "retain_baseline_events": False,
          "train": {"orthrus_epochs": 12, "orthrus_seeds": [0, 1, 2], "fusion_weights": [2, 1], "alert_layers": ["novelty", "rules"],
                    "corroboration_percentile": "99.99", "fusion_calibration": "simulation", "velox_lr": 0.001,
                    "d3_breadth": True, "d3_breadth_cap": 12.0, "d3_breadth_floor": 3, "d3_breadth_horizon_s": 7200}}
check(refused(P.validate_config, ok_cfg) is None, "a valid configuration (all keys) is accepted")
bad = {
    "train.device collides with the worker's device argument": {"train": {"device": "cuda"}},
    "train.layer_novelty must be a boolean": {"train": {"layer_novelty": "false"}},
    "train.alert_layers [] (no alerting at all)": {"train": {"alert_layers": []}},
    "train.alert_layers with an unknown layer": {"train": {"alert_layers": ["novelty", "everything"]}},
    "train.corroboration_percentile '0'": {"train": {"corroboration_percentile": "0"}},
    "train.orthrus_epochs 10**9 (GPU denial of service)": {"train": {"orthrus_epochs": 10**9}},
    "train.velox_runs 0": {"train": {"velox_runs": 0}},
    "train.orthrus_seeds with 1000 seeds": {"train": {"orthrus_seeds": list(range(1000))}},
    "train.batch_size as a string": {"train": {"batch_size": "1024"}},
    "train.fusion_weights not a pair": {"train": {"fusion_weights": [1, 2, 3]}},
    "train.layers_only 1 (not a boolean)": {"train": {"layers_only": 1}},
    "an unknown train key": {"train": {"lr_everything": 1}},
    "train not an object": {"train": ["x"]},
    "learned_daily_budget 100000": {"learned_daily_budget": 100000},
    "learned_daily_budget true (bool is not an int)": {"learned_daily_budget": True},
    "periodic_retrain 'no'": {"periodic_retrain": "no"},
    "early_models 0": {"early_models": 0},
    "baseline_days 0": {"baseline_days": 0},
    "window_minutes 0.5": {"window_minutes": 0.5},
    "an unknown timezone": {"tz": "Mars/Olympus"},
    "fp_budget '50'": {"fp_budget": "50"},
    "a server-managed key (refresh_days)": {"refresh_days": ["2026-11-07"]},
    "a server-managed key (kind)": {"kind": "benchmark"},
    "an unknown key": {"whatever": 1},
    "train.d3_breadth 'yes'": {"train": {"d3_breadth": "yes"}},
    "train.d3_breadth_cap 1000 (out of range)": {"train": {"d3_breadth_cap": 1000}},
    "train.d3_breadth_horizon_s 1 (out of range)": {"train": {"d3_breadth_horizon_s": 1}},
    "train.d3_breadth_floor at the cap (no activity would count)": {"train": {"d3_breadth_floor": 6.0, "d3_breadth_cap": 6.0}},
    "train.d3_breadth_floor above the default cap": {"train": {"d3_breadth_floor": 12.0}},
    "train.d3_breadth_cap below the default floor": {"train": {"d3_breadth_cap": 3.0}},
}
for what, cfg in bad.items():
    check(refused(P.validate_config, cfg) is not None, f"refused: {what}")
msg = refused(P.validate_config, {"approved_executables": ["/usr/bin/python3"]})
check(msg is not None and "allow list" in msg and "/api/allowlist" in msg, "approved_executables refused, pointing to the allow list")
check("device" in (refused(P.validate_config, {"train": {"device": "cpu"}}) or ""), "the device refusal says why")

# the schema follows pdp_engine.trainer.TrainConfig: every field configurable except device, with matching types
from pdp_engine.trainer import TrainConfig  # noqa: E402
fields = {f.name: f for f in dataclasses.fields(TrainConfig)}
check(set(P.TRAIN_SCHEMA) - {"fusion_calibration"} == set(fields) - {"device"},
      f"TRAIN_SCHEMA covers TrainConfig (missing {sorted(set(fields) - set(P.TRAIN_SCHEMA) - {'device'})}, extra {sorted(set(P.TRAIN_SCHEMA) - set(fields) - {'fusion_calibration'})})")
KIND_OF = {bool: "bool", int: "int", float: "num", str: "enum", tuple: ("intlist", "numpair", "layers"), type(None): ("layers",)}
mism = []
for name, f in fields.items():
    if name == "device":
        continue
    d = f.default if f.default is not dataclasses.MISSING else f.default_factory()
    want = KIND_OF[type(d)]
    if P.TRAIN_SCHEMA[name][0] not in (want if isinstance(want, tuple) else (want,)):
        mism.append(name)
    elif P.TRAIN_SCHEMA[name][0] != "layers":    # every default must itself be valid
        v = list(d) if isinstance(d, tuple) else d
        if refused(P.validate_train, {name: v}, engine_check=False):
            mism.append(name + "=default")
check(not mism, f"TRAIN_SCHEMA types match the TrainConfig defaults, and the defaults validate ({mism})")
tc = TrainConfig()
check((P.D3_BREADTH_CAP, P.D3_BREADTH_FLOOR, P.D3_BREADTH_HORIZON_S) == (tc.d3_breadth_cap, tc.d3_breadth_floor, tc.d3_breadth_horizon_s),
      "posture's detector-3 breadth defaults = TrainConfig's")
ds = P.detection_settings({})
check(ds["layer_novelty"] is tc.layer_novelty is False and ds["d3_breadth"] is tc.d3_breadth is True and ds["detector3"] is True,
      "detection_settings defaults = TrainConfig's (0.8: layer 1 off, detector-3 breadth on)")
check(P.detection_settings({"train": {"layer_novelty": True}})["layer_novelty"] is True, "layer 1 turned on explicitly")
from pdp_engine.models import VELOX_INPUTS  # noqa: E402
check(tuple(P.TRAIN_SCHEMA["velox_input"][1]) == tuple(VELOX_INPUTS), "velox_input values = pdp_engine.models.VELOX_INPUTS")

# ---- 2. floor: no configuration without a deterministic layer that alerts
# 0.7: the learned layer alerts on its own; the floor is "the learned layer or the data-flow rules can alert"
check(refused(P.check_floor, {"train": {"layer_rules": False, "learned_alerts": False}}) is not None, "data-flow rules off and learned alerts off: refused")
check(refused(P.check_floor, {"train": {"layer_rules": False}, "learned_alerts": False}) is not None, "rules off, learned alerts off by the endpoint setting: refused")
check(refused(P.check_floor, {"train": {"alert_layers": ["novelty", "corroborated"]}, "learned_alerts": False}) is not None,
      "alerting only from layer 1 / corroborated with learned alerts off: refused")
check(refused(P.check_floor, {"train": {"layer_rules": False}}) is None, "rules off, learned layer still alerting: allowed (with a reason)")
check(refused(P.check_floor, {"train": {"alert_layers": ["learned", "corroborated"]}}) is None, "alerting from the learned layer only: allowed (with a reason)")
check(refused(P.check_floor, {}) is None, "defaults pass the floor")
check(refused(P.check_floor, {"train": {"layer_novelty": True, "layer_rules": False, "learned_alerts": False}}) is not None,
      "0.8: layer 1 alone (rules and learned alerts off) does not pass the floor")
check(refused(P.check_floor, {"train": {"layer_novelty": False}}) is None, "0.8: layer 1 off passes the floor (the default)")

# ---- 3. what weakens detection
W = P.weakenings
cases = [
    ({}, {"train": {"detector3": False}}, "detector-3"),
    ({}, {"train": {"propagation": False}}, "propagation"),
    ({}, {"train": {"calibration_budget": 0}}, "calibration budget"),
    ({}, {"train": {"d3_breadth": False}}, "breadth evidence turned off"),
    ({}, {"train": {"d3_breadth_cap": 20.0}}, "breadth cap raised (10 -> 20"),
    ({}, {"train": {"d3_breadth_floor": 6}}, "breadth floor raised (4 -> 6"),
    ({"train": {"d3_breadth_cap": 8.0}}, {"train": {"d3_breadth_cap": 9.0}}, "breadth cap raised"),
    ({}, {"train": {"d3_breadth_horizon_s": 600}}, "breadth horizon shortened"),
    ({}, {"train": {"learned_alerts": False}}, "training settings"),
    ({}, {"train": {"layer_rules": False}}, "layer 2"),
    ({}, {"train": {"alert_layers": ["novelty", "rules"]}}, "alerting turned off"),
    ({}, {"train": {"layers_only": True}}, "layers_only"),
    ({}, {"train": {"corroboration_percentile": "99.99"}}, "corroboration"),
    ({"learned_alerts": True}, {"learned_alerts": False}, "turned off"),
    ({}, {"learned_daily_budget": 500}, "raised to 500"),
    ({}, {"periodic_retrain": False}, "periodic retraining"),
    ({}, {"early_models": False}, "early models"),
    ({"fp_budget": "99"}, {"fp_budget": None}, "threshold raised"),
    ({"baseline_days": 7}, {"baseline_days": 2}, "baseline shortened"),
    ({}, {"retain_baseline_events": True}, "privacy"),
]
for before, after, needle in cases:
    w = W(before, after)
    check(len(w) == 1 and needle in w[0], f"weakening: {after} -> {w}")
check(W({}, {"learned_daily_budget": 50, "learned_alerts": True, "baseline_days": 10, "periodic_retrain": True,
             "train": {"orthrus_epochs": 20, "layer_novelty": True}}) == [], "tuning and strengthening are not weakening")
check(W({"train": {"layer_rules": False}}, {}) == [], "turning a layer back on is not weakening")
# 0.8: layer 1 is an optional extra rule (off by default): neither turning it on nor off weakens detection
check(W({"train": {"layer_novelty": True}}, {"train": {"layer_novelty": False}}) == [], "0.8: turning layer 1 off is not weakening")
check(W({}, {"train": {"layer_novelty": True}}) == [] and W({"train": {"layer_novelty": True}}, {}) == [],
      "0.8: turning layer 1 on, or back to its default (off), is not weakening")
check(W({}, {"train": {"alert_layers": ["rules", "corroborated", "learned"]}}) == [], "0.8: dropping layer 1 from alert_layers is not weakening")
check(W({}, {"train": {"d3_breadth_cap": 8.0, "d3_breadth_floor": 2.0, "d3_breadth_horizon_s": 86400}}) == [],
      "lowering the breadth cap / floor or a longer horizon is not weakening")
check(W({"train": {"d3_breadth": False}}, {}) == [], "turning breadth back on is not weakening")
w = W({}, {"train": {"detector3": False, "d3_breadth": False, "d3_breadth_cap": 50.0}})
check(len(w) == 1 and "detector-3" in w[0], f"detector-3 off: its breadth settings are not reported on top ({w})")
check(W({}, {"train": {"d3_breadth": False, "d3_breadth_cap": 50.0}}) == [W({}, {"train": {"d3_breadth": False}})[0]],
      "breadth off: its cap does not matter any more")
check(W({"learned_daily_budget": 500}, {"learned_daily_budget": 400}) == [], "lowering a flood budget is not weakening")
check(P.org_weakenings({"retention_days": 365, "require_mfa": True}, {"retention_days": 90, "require_mfa": False}) ==
      ["retention lowered from 365 to 90 days (older alerts and incidents are deleted)", "two-factor sign-in no longer required"],
      "organisation: lower retention and optional 2FA are weakening")
check(P.org_weakenings({"retention_days": 90}, {"retention_days": 400}) == [], "raising retention is not weakening")
m = refused(P.require_reason, ["layer 1 (new programs) turned off"], "  ")
check(m is not None and m.startswith("Reason required") and "layer 1" in m, "weakening without a reason: 400 'Reason required: ...'")
check(P.require_reason(["x"], " planned maintenance ") == "planned maintenance", "reason accepted (trimmed)")
check(P.require_reason([], None) is None, "no weakening: no reason needed")
check(refused(P.require_reason, [], "x" * 501) is not None, "reason at most 500 characters")

# ---- 4. audit diffs never carry secrets
d = P.diff({"name": "SOC", "secret": "s3cret", "target": "https://hooks.slack.com/services/T0/B0/XYZ", "train": {"layer_rules": True}},
           {"name": "SOC", "secret": "other", "target": "https://hooks.slack.com/services/T0/B0/ABC", "train": {"layer_rules": False}})
check(d["secret"] == {"before": "[redacted]", "after": "[redacted]", "changed": True}, "secret changes recorded, values redacted")
check(d["target"]["after"] == "https://hooks.slack.com/..." and "XYZ" not in str(d), "webhook URLs reduced to their host")
check(d["train.layer_rules"] == {"before": True, "after": False} and "name" not in d, "nested keys flattened; unchanged keys left out")
check(P.diff({"sso": {"client_secret": "a"}}, {"sso": {"client_secret": "b"}})["sso.client_secret"]["after"] == "[redacted]", "nested secrets redacted")
check(P.diff({}, {"credentials": {"user": "u", "pw": "x"}})["credentials"]["after"] == "[redacted]", "secret-named sub-objects redacted whole")
check(P.redact_value("password", "hunter22") == "[redacted]" and P.redact_value("note", "x" * 400).endswith("..."), "redact_value")

# ---- 5. allow-list programs: full paths, matched like the agent's layer 1, no wildcards, interpreters forced
CP = P.check_program
check(CP("/usr/local/bin/links", name_only_ok=False, force=False, reason=None)["key"] == "/usr/local/bin/links", "full path accepted")
check("full path" in (refused(CP, "links", name_only_ok=False, force=False, reason=None) or ""), "bare name refused (paths recorded / unknown)")
check(refused(CP, "links", name_only_ok=True, force=False, reason=None) is None, "bare name accepted for an endpoint without paths")
for v in ("*", "/usr/bin/*", "/opt/app?/run", "/usr/bin/", "C:\\Windows\\", "/", "bin/python", "[ab]x"):
    check(refused(CP, v, name_only_ok=True, force=True, reason="r") is not None, f"refused: {v!r}")
for v in ("/usr/bin/python3", "/usr/bin/python3.12", "/bin/bash", "/bin/sh", "/usr/bin/perl", "/usr/bin/node", "/lib64/ld-linux-x86-64.so.2",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\System32\\cmd.exe", "C:/Windows/System32/rundll32.exe",
          "C:\\Windows\\System32\\mshta.exe", "C:\\Windows\\System32\\wscript.exe", "/usr/bin/env", "/usr/bin/sudo"):
    m = refused(CP, v, name_only_ok=False, force=False, reason=None)
    check(m is not None and m.startswith("Confirmation required"), f"interpreter / LOLBin needs force: {v}")
    check(refused(CP, v, name_only_ok=False, force=True, reason=None) is not None, f"... and a reason: {v}")
    r = CP(v, name_only_ok=False, force=True, reason="build agent runs scripts")
    check(r["interpreter"] is True, f"... allowed with force + reason, recorded as interpreter: {v}")
check(CP("C:\\Program Files\\Backup\\agent.exe", name_only_ok=False, force=False, reason=None)["key"] == "/program files/backup/agent.exe",
      "Windows path normalised like the agent")
check(P.is_interpreter("/usr/local/bin/links") is False and P.is_interpreter("/opt/app/bin/server") is False, "ordinary programs are not interpreters")

PM = P.program_matches
check(not PM("python3", "/dev/shm/x/python3"), "a bare name no longer covers any path (python3 vs /dev/shm/x/python3)")
check(PM("python3", "python3"), "a bare name covers the same bare name (collector without paths)")
check(PM("C:\\Windows\\System32\\ping.exe", "/Device/HarddiskVolume3/Windows/system32/PING.EXE"), "Windows spellings of one program match")
check(not PM("/usr/bin/links", "/tmp/usr/bin/links") and not PM("/usr/bin/links", None), "different paths do not match")
# parity with the agent: layer 1 (NoveltyLayer.is_known) approves exactly what the allow list matches
from pdp_engine.layers import NoveltyLayer  # noqa: E402
approved = ["/usr/bin/python3", "links", "C:\\Program Files\\App\\{12345678-1234-1234-1234-123456789abc}\\app.exe", "/opt/tool/1.2.3/bin/tool"]
nl = NoveltyLayer(set(), approved, normalize=True)
exes = ["/usr/bin/python3", "/dev/shm/x/python3", "python3", "links", "/usr/bin/links", "/program files/app/{aaaaaaaa-1234-1234-1234-123456789abc}/APP.EXE",
        "/opt/tool/2.0.1/bin/tool", "/opt/tool/bin/tool", "/USR/BIN/PYTHON3"]
par = [(x, nl.is_known(x), any(PM(a, x) for a in approved)) for x in exes]
check(all(k == m for _, k, m in par), f"allow-list matching = the agent's layer-1 approval for {len(exes)} programs ({[p for p in par if p[1] != p[2]]})")

# server-side marking (allowlist.matches) uses the same rule
alert = {"endpoint_id": "e1", "layer": "novelty", "label": "subject /dev/shm/x/python3 python3 -c ...",
         "reasons": [{"rule": "novel_executable", "key": "/dev/shm/x/python3"}]}
check(not A.matches({"kind": "program", "value": "python3", "endpoint_ids": None}, alert), "allowlist.matches: python3 does not cover /dev/shm/x/python3")
check(A.matches({"kind": "program", "value": "/dev/shm/x/python3", "endpoint_ids": ["e1"]}, alert), "allowlist.matches: the exact path does")
check(not A.matches({"kind": "program", "value": "/dev/shm/x/python3", "endpoint_ids": ["e2"]}, alert), "allowlist.matches: other endpoints' entries do not")
la = {"endpoint_id": "e1", "layer": "learned", "label": "subject /opt/x/python3 python3 run.py", "reasons": []}
check(not A.matches({"kind": "detection", "rule": "learned", "value": "python3", "endpoint_ids": None}, la), "learned suppression by bare name no longer covers paths")
check(P.entry_risks({"kind": "program", "value": "bash"}) == ["name_only", "interpreter"], "entry risks: name only + interpreter")
check(P.entry_risks({"kind": "address", "value": "10.0.0.0/16"}) == ["large_network"] and P.entry_risks({"kind": "address", "value": "10.0.0.0/24"}) == [],
      "entry risks: large networks")

# ---- 6. detection posture
now = time.time()
ago = lambda d: datetime.fromtimestamp(now - d * 86400, tz=timezone.utc)  # noqa: E731
full = {"manifest": {"layers": {"novelty": True, "rules": True}, "learned_policy": {"daily_budget": 20, "learned_alerts": False}, "maturity": {"early": False}},
        "created_at": ago(5)}
ep = {"id": "e1", "phase": "protected", "kind": "live", "config": {}, "enrolled_at": ago(20), "current_bundle": "b1"}
check(P.compute(ep, full, [], now) == {"level": "ok", "problems": []}, "a protected endpoint with a fresh full model: ok")
keys = lambda p: [x["key"] for x in p["problems"]]  # noqa: E731
p = P.compute(dict(ep, current_bundle=None), None, [], now)
check(p["level"] == "error" and "posture:no_model" in keys(p), "protected without a model: error")
p = P.compute(dict(ep, phase="baseline", current_bundle=None, enrolled_at=ago(2)), None, [], now)
check(p["level"] == "ok", "a learning endpoint without a model yet: ok")
p = P.compute(dict(ep, phase="baseline", current_bundle=None, enrolled_at=ago(30)), None, [], now)
check("posture:no_model" in keys(p), "never trained 30 days after enrolment: flagged")
early = {"manifest": {"maturity": {"early": True, "baseline_hours": 24}, "layers": {"novelty": True, "rules": True},
                      "learned_policy": {"alert_layers": ["rules"]}}, "created_at": ago(1)}
check(P.compute(dict(ep, phase="baseline", enrolled_at=ago(2)), early, [], now)["level"] == "ok", "early model while learning: ok (rules-only alerting expected)")
p = P.compute(dict(ep, phase="protected", enrolled_at=ago(40)), early, [], now)
check("posture:early_model" in keys(p) and "posture:model_alert_layers" not in keys(p), "stuck on an early model: warning")
p = P.compute(dict(ep, phase="degraded"), full, [], now)
check(p["level"] == "error" and "posture:degraded" in keys(p), "degraded: error")
p = P.compute(dict(ep, config={"periodic_retrain": False}), dict(full, created_at=ago(90)), [], now)
check("posture:stale_model" in keys(p), "stale model with periodic retraining off: flagged")
check("posture:old_model" in keys(P.compute(ep, dict(full, created_at=ago(200)), [], now)), "a very old model: flagged")
off = {"manifest": {**full["manifest"], "layers": {"novelty": False, "rules": True}}, "created_at": ago(1)}
check(P.compute(ep, off, [], now) == {"level": "ok", "problems": []}, "0.8: layer 1 off in the model (the default): ok")
off2 = {"manifest": {**full["manifest"], "layers": {"novelty": True, "rules": False}}, "created_at": ago(1)}
p = P.compute(ep, off2, [], now)
check(p["level"] == "error" and "posture:model_rules_off" in keys(p), "layer 2 off in the model: error")
pol1 = {"manifest": {**full["manifest"], "learned_policy": {"alert_layers": ["rules", "corroborated", "learned"]}}, "created_at": ago(1)}
check("posture:model_alert_layers" not in keys(P.compute(ep, pol1, [], now)), "0.8: a model not alerting on layer 1: not a problem")
p = P.compute(dict(ep, config={"train": {"d3_breadth_floor": 11.0}}), full, [], now)
check("posture:invalid_train" in keys(p), "stored breadth floor above the cap flagged: training would fail")
p = P.compute(dict(ep, config={"train": {"d3_breadth": False}}), full, [], now)
check(p["level"] == "warning" and any(k.startswith("posture:setting:detector_") for k in keys(p)), f"breadth turned off in the settings: warning ({keys(p)})")
pol = {"manifest": {**full["manifest"], "learned_policy": {"alert_layers": ["learned", "corroborated"]}}, "created_at": ago(1)}
check("posture:model_alert_layers" in keys(P.compute(ep, pol, [], now)), "model not alerting on the deterministic layers: error")
p = P.compute(dict(ep, config={"learned_alerts": True, "learned_daily_budget": 900}), full, [], now)
check("posture:learned_flood" in keys(p), "learned alerts on with a huge budget: flagged")
p = P.compute(dict(ep, config={"train": {"layer_rules": False}}), full, [], now)
check(p["level"] == "error" and any(k.startswith("posture:setting:") for k in keys(p)), "layer 2 turned off in the settings: error")
p = P.compute(dict(ep, config={"train": {"device": "cuda"}}), full, [], now)
check("posture:invalid_train" in keys(p), "stored invalid training settings (train.device) flagged: training would fail")
p = P.compute(ep, full, [{"kind": "program", "value": "/bin/bash"}, {"kind": "program", "value": "/usr/bin/links"}], now)
check("posture:allowlist" in keys(p) and "/bin/bash" in p["problems"][-1]["text"] and "links" not in p["problems"][-1]["text"], "risky allow-list entries: flagged")
check(P.compute(dict(ep, phase="retired"), None, [], now)["level"] == "ok", "retired endpoints have no posture")
# shown with the endpoint's health problems
row = {"health": {}, "phase": "protected", "kind": "live", "posture": P.compute(dict(ep, current_bundle=None), None, [], now)}
check(any(x["key"] == "posture:no_model" for x in problems(row)), "health.problems includes the posture problems")
check(problems({"health": {}}) == [], "health.problems without posture unchanged")
# notification on worsening only
pr = [{"key": "posture:a", "level": "warning", "text": ""}, {"key": "posture:b", "level": "error", "text": ""}]
check([x["key"] for x in P.worsened(None, pr)] == ["posture:a", "posture:b"], "first observation: every problem is new")
check(P.worsened({"posture:a": "warning", "posture:b": "error"}, pr) == [], "unchanged: nothing to notify")
check([x["key"] for x in P.worsened({"posture:a": "warning", "posture:b": "warning"}, pr)] == ["posture:b"], "warning -> error: notified")

# ---- 7. security events as notifications
r = {"id": 7, "kind": "detection_weakened", "severity": "high", "endpoint_id": "e1", "username": "mallory", "at": datetime.now(timezone.utc),
     "title": "Detection weakened (web-01): layer 2 (data-flow rules) turned off",
     "detail": {"reason": "too noisy", "changes": ["layer 2 (data-flow rules) turned off"], "endpoint_name": "web-01"}}
m = P.message(r, "https://pdp.example")
check(m["event"] == "detection_weakened" and m["severity"] == "high" and "mallory" in m["text"] and "too noisy" in m["text"]
      and m["link"] == "https://pdp.example/#/endpoints/e1" and m["data"]["endpoint"]["name"] == "web-01", "message: who, why, what, link")
from pdp_server import notify as N  # noqa: E402
check("detection_weakened" in N.EVENTS and "response_action" in N.EVENTS, "notify: new event types")
check(N._cef_event(m).startswith("CEF:0|M.D Lab|") and "pdp-detection_weakened" in N._cef_event(m), "message renders as CEF for syslog channels")
check(P.channel_kinds(["incident"]) == ["detection_weakened", "response_action"], "channels receiving incidents also get security events")
check(P.channel_kinds(["agent_offline"]) == [] and P.channel_kinds(["response_action"]) == ["response_action"], "explicit subscription")

# ---- 8. token bucket (the SQL in posture.take computes the same)
B = P.bucket
ok, t = B(None, 0, 10, 30)
check(ok and t == 9, "a new bucket starts full")
t = 0.5
check(B(t, 0, 10, 30) == (False, 0.5), "empty bucket refuses")
check(B(t, 60, 10, 30)[0] is True, "refills at the hourly rate (30/h: one token per 2 minutes)")
check(B(5, 10**6, 10, 30) == (True, 9), "never more than the burst")
check(set(P.RATES) == {"export", "hunt", "sim"} and all(cap >= 1 for cap, _ in P.RATES.values()), "buckets for export, hunt, sim")

# 0.6: telemetry coverage of the model's baseline
from datetime import datetime as _dt, timezone as _tz
_ep = {"id": "e", "phase": "protected", "kind": "live", "config": {}, "enrolled_at": _dt.now(_tz.utc), "current_bundle": "b"}
def _cov(c):
    return [p["key"] for p in P.compute(_ep, {"manifest": {"layers": {"novelty": True, "rules": True, "coverage": c}, "learned_policy": {}},
                                                     "created_at": _dt.now(_tz.utc)}, [])["problems"]]
thin = _cov({"processes": 800, "processes_with_path": 0, "flows": 1000, "flows_with_address": 0, "exec_events": 0})
check("posture:telemetry_paths" in thin and "posture:telemetry_addresses" in thin, f"thin telemetry (no paths, no addresses) is a posture warning ({thin})")
ok_ = _cov({"processes": 800, "processes_with_path": 790, "flows": 1000, "flows_with_address": 950, "exec_events": 0})
check(not any(k.startswith("posture:telemetry") for k in ok_), "full telemetry without exec events (Windows) raises nothing")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
