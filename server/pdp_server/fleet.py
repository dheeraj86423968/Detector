"""Fleet prevalence (0.10, artifacts/lab_v10): a program that is new on one endpoint but ran during the baselines of
other endpoints of the same organisation is not new to the organisation.

The server sends each agent, with its configuration, the program keys (pdp_engine.layers.program_key) that ran during
the baseline of at least `fleet_min_endpoints` *other* endpoints of its fleet, with the number of those endpoints.
A baseline = the known_executables of an endpoint's current bundle (its training days), never live activity: a tool an
attacker runs on several endpoints after their baselines does not become "known". Layer 1 then treats such a program as
no new-program alert (fleet_prevalence "drop", the default - lab_v10 P2), or as evidence ("evidence": it alerts only when
the learned score corroborates it), or ignores the list ("off").

Fleet: live endpoints of an organisation form one fleet. Benchmark and simulation endpoints replay unrelated datasets
and are alone, unless their configuration names a fleet (`fleet`: any label; endpoints of an organisation with the
same label form a fleet - also usable to split an organisation, e.g. servers vs workstations).

Poisoning: an attacker present during one endpoint's baseline adds programs to that endpoint's known set; with
fleet_min_endpoints >= 2 (the default) one endpoint alone cannot make a program fleet-known; the data-flow rules still
see everything such a program does, and "evidence" mode also alerts on a fleet-known program that behaves unusually.
"""
from __future__ import annotations

import json
import os
import threading
from collections import Counter

from . import db

DEFAULT_MODE = "drop"          # artifacts/lab_v10: P2 chosen (drop, >= 2 other endpoints)
DEFAULT_MIN_ENDPOINTS = 2
MODES = ("evidence", "drop", "off")

_lock = threading.Lock()
_BUNDLE_KEYS: dict[str, frozenset] = {}          # bundle id -> program keys of its baseline
_FLEET: dict[tuple, tuple] = {}                   # (org, fleet label) -> (members signature, Counter, {eid: keys})


def _engine():
    from .posture import _engine_path
    _engine_path()
    from pdp_engine.layers import UNKNOWN_PROGRAM, program_key
    return UNKNOWN_PROGRAM, program_key


def fleet_label(kind: str | None, cfg: dict | None) -> str | None:
    lab = (cfg or {}).get("fleet")
    if isinstance(lab, str) and lab.strip():
        return lab.strip()[:64]
    return "org" if (kind or "live") == "live" else None


def baseline_programs(bundle_id: str, path: str) -> frozenset:
    """Program keys of a bundle's baseline (cached: bundles are immutable)."""
    bid = str(bundle_id)
    with _lock:
        hit = _BUNDLE_KEYS.get(bid)
    if hit is not None:
        return hit
    unknown, program_key = _engine()
    try:
        known = json.load(open(os.path.join(path, "layers.json"))).get("known_executables") or []
    except (OSError, ValueError):
        known = []
    keys = frozenset(program_key(str(k), strict=True) for k in known if str(k) not in unknown)
    with _lock:
        if len(_BUNDLE_KEYS) > 20000:
            _BUNDLE_KEYS.clear()
        _BUNDLE_KEYS[bid] = keys
    return keys


def settings(cfg: dict | None) -> tuple[str, int]:
    cfg = cfg or {}
    mode = cfg.get("fleet_prevalence") if cfg.get("fleet_prevalence") in MODES else DEFAULT_MODE
    k = cfg.get("fleet_min_endpoints")
    k = int(k) if isinstance(k, int) and not isinstance(k, bool) and k >= 1 else DEFAULT_MIN_ENDPOINTS
    return mode, k


def programs_for(c, ep: dict) -> dict[str, int]:
    """{program key: other endpoints of the fleet whose baseline ran it} for one endpoint, limited to keys run by at
    least fleet_min_endpoints of them; {} when the endpoint is alone, the setting is off or nothing qualifies."""
    cfg = ep.get("config") or {}
    mode, k = settings(cfg)
    label = fleet_label(ep.get("kind"), cfg)
    if mode == "off" or label is None or not ep.get("org_id"):
        return {}
    rows = db.q(c, "SELECT e.id, e.kind, e.config, b.id AS bid, b.path FROM endpoints e JOIN bundles b ON b.id = e.current_bundle "
                   "WHERE e.org_id = %s AND e.phase <> 'retired'", (ep["org_id"],))
    members = sorted((str(r["id"]), str(r["bid"]), r["path"]) for r in rows if fleet_label(r["kind"], r["config"]) == label)
    sig = tuple((e, b) for e, b, _ in members)
    key = (str(ep["org_id"]), label)
    with _lock:
        hit = _FLEET.get(key)
    if hit is None or hit[0] != sig:
        per = {e: baseline_programs(b, p) for e, b, p in members}
        total = Counter()
        for ks in per.values():
            total.update(ks)
        hit = (sig, total, per)
        with _lock:
            _FLEET[key] = hit
    _, total, per = hit
    own = per.get(str(ep["id"]), frozenset())
    out = {}
    for prog, n in total.items():
        n -= prog in own
        if n >= k:
            out[prog] = n
    return out


def summary(c, ep: dict) -> dict:
    """What the console shows for one endpoint (0.10.1): its fleet (the effective label, or None when it is alone), the
    settings in force and their defaults, the other members, and how many programs the agent currently treats as
    known to the fleet."""
    cfg = ep.get("config") or {}
    mode, k = settings(cfg)
    label = fleet_label(ep.get("kind"), cfg)
    named = cfg.get("fleet") if isinstance(cfg.get("fleet"), str) and cfg.get("fleet").strip() else None
    members = []
    if label is not None and ep.get("org_id"):
        rows = db.q(c, "SELECT id, name, kind, config, current_bundle FROM endpoints WHERE org_id = %s AND phase <> 'retired' "
                       "ORDER BY name", (ep["org_id"],))
        members = [{"id": str(r["id"]), "name": r.get("name") or str(r["id"]), "trained": bool(r.get("current_bundle"))}
                   for r in rows if str(r["id"]) != str(ep["id"]) and fleet_label(r.get("kind"), r.get("config")) == label]
    return {"label": label, "named": named, "default_label": fleet_label(ep.get("kind"), {}),
            "mode": mode, "min_endpoints": k, "defaults": {"mode": DEFAULT_MODE, "min_endpoints": DEFAULT_MIN_ENDPOINTS},
            "members": members[:200], "member_count": len(members), "trained_members": sum(m["trained"] for m in members),
            "known_programs": len(programs_for(c, ep))}
