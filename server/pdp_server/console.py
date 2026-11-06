"""Console views built for the analyst (docs/CONSOLE_API.md): overview, incidents, endpoint health and detection
checks. Every query honours the user's endpoint scope (pdp_server.access)."""
from __future__ import annotations

import json
import os
import secrets
import time
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import db, incidents, pki
from .access import require_endpoint, scope_list, session, triager

router = APIRouter()
OFFLINE_AFTER_S = 600

FAMILY_LABEL = {"web_backdoor": "Web shell / backdoor", "browser_dropper": "Malicious download (dropper)",
                "lotl_recon": "Living-off-the-land reconnaissance", "priv_esc_lateral": "Privilege escalation and lateral movement",
                "exfiltration": "Data exfiltration", "ransomware": "Ransomware", "script_c2": "Script-based command and control"}
CHECK_FAMILIES = list(FAMILY_LABEL)
CHECK_LEVELS = ["none", "medium"]


# ---------------------------------------------------------------------------------------------- endpoints
def _needed(cfg: dict) -> int:
    return int((cfg or {}).get("baseline_days", 7)) + 1


def endpoint_state(r: dict) -> dict:
    phase, kind, cfg = r["phase"], r.get("kind", "live"), r.get("config") or {}
    done, need = int(r.get("baseline_days_done") or 0), _needed(cfg)
    last = r.get("last_seen")
    online = bool(last and (datetime.now(timezone.utc) - last).total_seconds() < OFFLINE_AFTER_S)
    if phase == "retired":
        state, text = "retired", "Retired"
    elif kind != "live":
        state = {"baseline": "learning", "training": "training"}.get(phase, "protected")
        what = "Dataset replay" if kind == "benchmark" else "Attack-suite test run"
        text = {"learning": f"{what}: building the baseline", "training": "Training the detection model"}.get(
            state, f"{what} ({'benchmark' if kind == 'benchmark' else 'running' if online else 'finished'})")
    elif phase in ("baseline", "pending"):
        early = " · early detection on" if r.get("current_bundle") else ""
        state, text = ("learning", f"Learning normal behaviour (day {min(done + 1, need)} of {need}){early}") if online else ("offline", "Offline while learning")
    elif phase == "training":
        state, text = "training", "Training the detection model"
    else:
        state, text = ("protected", "Protected") if online else ("offline", "Offline - not reporting")
        if phase == "degraded" and online:
            text = "Protected (degraded)"
    return {"state": state, "state_text": text, "baseline": {"done": min(done, need), "needed": need}, "online": online}


def _integrity_posture(row: dict) -> str:
    from .integrity import posture
    return posture(row)


def endpoint_rows(s: dict, endpoint_id: str | None = None) -> list[dict]:
    ids = scope_list(s)
    with db.conn() as c:
        rows = db.q(c, "SELECT e.id, e.name, e.hostname, e.os, e.arch, e.kind, e.phase, e.config, e.agent_version, e.last_seen, e.enrolled_at, "
                       "e.baseline_days_done, e.current_bundle, e.health FROM endpoints e "
                       "WHERE (%s::uuid[] IS NULL OR e.id = ANY(%s::uuid[])) AND (%s::uuid IS NULL OR e.id=%s) ORDER BY lower(e.name)",
                    (ids, ids, endpoint_id, endpoint_id))
        incs = incidents.list_incidents(c, ids, endpoint_id)
    by_ep: dict[str, list] = {}
    for i in incs:
        by_ep.setdefault(i["endpoint_id"], []).append(i)
    out = []
    for r in rows:
        eid = str(r["id"])
        mine = by_ep.get(eid, [])
        h = r["health"] or {}
        out.append({"id": eid, "name": r["name"], "hostname": r["hostname"], "os": r["os"], "arch": r["arch"], "kind": r["kind"],
                    "phase": r["phase"], "last_seen": r["last_seen"], "enrolled_at": r["enrolled_at"],
                    "agent_version": h.get("agent_version") or r["agent_version"], "current_bundle": str(r["current_bundle"]) if r["current_bundle"] else None,
                    **endpoint_state(r),
                    "open_incidents": sum(1 for i in mine if i["status"] in ("open", "investigating", "true_positive")),
                    "last_incident_ns": max((i["last_ns"] for i in mine), default=None)})
    return out


def _one_endpoint(s: dict, endpoint_id: str) -> dict:
    require_endpoint(s, endpoint_id)
    try:
        rows = endpoint_rows(s, endpoint_id)
    except Exception:  # noqa - malformed id
        rows = []
    if not rows:
        raise HTTPException(404, "not found")
    return rows[0]


# ---------------------------------------------------------------------------------------------- overview
def _day(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc).date().isoformat()


def _per_day(items, key, days=14, today: date | None = None) -> list[dict]:
    today = today or datetime.now(timezone.utc).date()
    dates = [(today - timedelta(days=d)).isoformat() for d in range(days - 1, -1, -1)]
    counts = {d: 0 for d in dates}
    for it in items:
        d = _day(key(it))
        if d in counts:
            counts[d] += 1
    return [{"date": d, "n": counts[d]} for d in dates]


@router.get("/api/overview")
def overview(s=Depends(session)):
    eps = endpoint_rows(s)
    live = [e for e in eps if e["state"] != "retired"]
    with db.conn() as c:
        incs = incidents.list_incidents(c, scope_list(s))
        checks = {str(r["endpoint_id"]): r for r in db.q(c, "SELECT DISTINCT ON (endpoint_id) endpoint_id, state, spec, created_at FROM sim_campaigns "
                                                           "ORDER BY endpoint_id, created_at DESC")}
    active = [i for i in incs if i["status"] in ("open", "investigating", "true_positive")]
    week = time.time_ns() - 7 * 86400 * 10**9
    attention = []
    for e in live:
        if e["state"] == "offline":
            attention.append({"kind": "offline", "endpoint_id": e["id"], "endpoint_name": e["name"],
                              "text": f"{e['name']} has not reported since {e['last_seen'].strftime('%Y-%m-%d %H:%M UTC') if e['last_seen'] else 'enrolment'}"})
    for e in live:
        if e["kind"] == "live" and e["state"] == "protected":
            ck = checks.get(e["id"])
            if not ck:
                attention.append({"kind": "no_check", "endpoint_id": e["id"], "endpoint_name": e["name"],
                                  "text": f"Run a detection check on {e['name']} to confirm detection works on its data"})
            else:
                summ = check_summary(ck)
                if summ["verdict"] == "fail":
                    attention.append({"kind": "check_failed", "endpoint_id": e["id"], "endpoint_name": e["name"], "text": f"{e['name']}: {summ['verdict_text']}"})
    with db.conn() as c:
        for r in db.q(c, "SELECT id, name, health FROM endpoints WHERE phase<>'retired' AND coalesce((health->>'collector_lost_1h')::bigint, "
                         "(health->>'collector_lost')::bigint, 0) + coalesce((health->>'collector_behind_1h')::bigint, 0) > 0"):
            if any(str(r["id"]) == e["id"] for e in live):
                h = r["health"]
                n = (h.get("collector_lost_1h", h.get("collector_lost")) or 0) + (h.get("collector_behind_1h") or 0)
                attention.append({"kind": "dropping_events", "endpoint_id": str(r["id"]), "endpoint_name": r["name"],
                                  "text": f"{r['name']}: the collector missed {n:,} events{' in the last hour' if 'collector_lost_1h' in h else ''} (host too busy during a burst)"})
    sev = {k: sum(1 for i in active if i["severity"] == k) for k in ("critical", "high", "medium", "low")}
    return {"ok": True,
            "endpoints": {"total": len(live), "protected": sum(e["state"] == "protected" for e in live),
                          "learning": sum(e["state"] in ("learning", "training") for e in live), "offline": sum(e["state"] == "offline" for e in live)},
            "incidents": {"open": len(active), "last_7d": sum(1 for i in incs if i["last_ns"] >= week), "by_severity": sev},
            "per_day": [{"date": d["date"], "incidents": d["n"]} for d in _per_day(incs, lambda i: i["first_ns"])],
            "recent_incidents": sorted(incs, key=lambda i: i["last_ns"], reverse=True)[:6],
            "attention": attention}


# ---------------------------------------------------------------------------------------------- incidents
ACTIVE = ("open", "investigating", "true_positive")


@router.get("/api/incidents")
def get_incidents(s=Depends(session), status: str = "all", endpoint_id: str | None = None, severity: str | None = None, limit: int = 100,
                  assignee: str | None = None):
    if endpoint_id:
        require_endpoint(s, endpoint_id)
    with db.conn() as c:
        incs = incidents.list_incidents(c, scope_list(s), endpoint_id)
    if status == "open":
        incs = [i for i in incs if i["status"] in ACTIVE]
    elif status != "all":
        incs = [i for i in incs if i["status"] == status]
    if severity:
        incs = [i for i in incs if i["severity"] in severity.split(",")]
    with db.conn() as c:
        meta = _meta(c, s["org"], [i["id"] for i in incs])
    for i in incs:
        i["assignee"] = meta.get(i["id"])
    if assignee == "me":
        incs = [i for i in incs if i["assignee"] and i["assignee"]["id"] == s["u"]]
    elif assignee == "none":
        incs = [i for i in incs if not i["assignee"]]
    incs.sort(key=lambda i: i["last_ns"], reverse=True)
    return {"ok": True, "incidents": incs[:max(1, min(int(limit), 5000))]}


def _meta(c, org, ids) -> dict:
    if not ids:
        return {}
    rows = db.q(c, "SELECT m.incident_id, u.id, coalesce(u.display_name, u.username) AS name FROM incident_meta m JOIN users u ON u.id=m.assignee "
                   "WHERE m.org_id=%s AND m.incident_id = ANY(%s)", (org, list(ids)))
    return {r["incident_id"]: {"id": r["id"], "name": r["name"]} for r in rows}


def _history(c, org, incident_id) -> list[dict]:
    return db.q(c, "SELECT e.id, e.kind, e.text, e.value, e.at, coalesce(u.display_name, u.username) AS by FROM incident_events e "
                   "LEFT JOIN users u ON u.id=e.user_id WHERE e.org_id=%s AND e.incident_id=%s ORDER BY e.at, e.id", (org, incident_id))


def _event(c, s, incident_id, kind, text=None, value=None):
    db.q(c, "INSERT INTO incident_events (incident_id, org_id, user_id, kind, text, value) VALUES (%s,%s,%s,%s,%s,%s)",
         (incident_id, s["org"], s["u"], kind, text, value))


@router.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int, s=Depends(session)):
    with db.conn() as c:
        alerts = incidents.find(c, scope_list(s), incident_id, with_context=True)
        if not alerts:
            raise HTTPException(404, "not found")
        meta = _meta(c, s["org"], [incident_id]).get(incident_id)
        hist = _history(c, s["org"], incident_id)
        team = db.q(c, "SELECT id, coalesce(display_name, username) AS name FROM users WHERE org_id=%s AND NOT disabled AND role IN ('admin','analyst') ORDER BY 2", (s["org"],))
    return {"ok": True, **incidents.detail(alerts), "assignee": meta, "history": hist, "assignable": team}


class Assign(BaseModel):
    user_id: int | None = None


class Note(BaseModel):
    text: str


@router.post("/api/incidents/{incident_id}/assign")
def assign_incident(incident_id: int, req: Assign, s=Depends(triager)):
    with db.conn() as c:
        if not incidents.find(c, scope_list(s), incident_id):
            raise HTTPException(404, "not found")
        name = None
        if req.user_id is not None:
            u = db.q(c, "SELECT coalesce(display_name, username) AS name FROM users WHERE id=%s AND org_id=%s AND NOT disabled AND role IN ('admin','analyst')",
                     (req.user_id, s["org"]), one=True)
            if not u:
                raise HTTPException(400, "assign to an admin or analyst of your organisation")
            name = u["name"]
        db.q(c, "INSERT INTO incident_meta (incident_id, org_id, assignee, updated_at) VALUES (%s,%s,%s,now()) "
                "ON CONFLICT (incident_id) DO UPDATE SET assignee=excluded.assignee, updated_at=now()", (incident_id, s["org"], req.user_id))
        _event(c, s, incident_id, "assign", name or "unassigned", str(req.user_id) if req.user_id else None)
    return {"ok": True}


@router.post("/api/incidents/{incident_id}/notes")
def add_note(incident_id: int, req: Note, s=Depends(triager)):
    t = (req.text or "").strip()
    if not t or len(t) > 5000:
        raise HTTPException(400, "a note has 1 to 5000 characters")
    with db.conn() as c:
        if not incidents.find(c, scope_list(s), incident_id):
            raise HTTPException(404, "not found")
        _event(c, s, incident_id, "note", t)
        hist = _history(c, s["org"], incident_id)
    return {"ok": True, "history": hist}


class IncidentStatus(BaseModel):
    status: str
    note: str | None = None


@router.post("/api/incidents/{incident_id}/status")
def set_incident_status(incident_id: int, req: IncidentStatus, s=Depends(triager)):
    if req.status not in incidents.STATUS_OF_ACTION:
        raise HTTPException(400, f"status must be one of {list(incidents.STATUS_OF_ACTION)}")
    with db.conn() as c:
        alerts = incidents.find(c, scope_list(s), incident_id)
        if not alerts:
            raise HTTPException(404, "not found")
        db.q(c, "UPDATE alerts SET status=%s WHERE id = ANY(%s)", (incidents.STATUS_OF_ACTION[req.status], [a["id"] for a in alerts]))
        _event(c, s, incident_id, "status", (req.note or "").strip()[:5000] or None, req.status)
    return {"ok": True}


# ---------------------------------------------------------------------------------------------- endpoint overview
def learning_progress(row: dict, done: int, need: int, bundle: dict | None, h: dict, up: dict) -> dict:
    """What a learning endpoint has done and will need: day N of need, data uploaded (compressed, as the client's
    network carried it) and the expected total, local disk use, the early model in use and the next one."""
    from .early import EARLY_MILESTONES_H, EARLY_RULES_ONLY_BELOW_H
    mat = ((bundle or {}).get("manifest") or {}).get("maturity") or {}
    hours = None
    if up["first"] is not None:
        hours = (time.time() - up["first"].timestamp()) / 3600
    per_day = float(up["bytes24"]) if hours and hours >= 24 else (float(up["bytes"]) / hours * 24 if hours and hours > 0.5 else None)
    remaining_days = max(0, need - done)
    expected = float(up["bytes"]) + per_day * remaining_days if per_day is not None else None
    have_h = float(mat.get("milestone_h") or mat.get("baseline_hours") or 0) if mat.get("early") else None
    nxt = next((m for m in EARLY_MILESTONES_H if have_h is None or m > have_h), None)
    return {"day": min(done + 1, need), "days_needed": need, "days_done": done,
            "uploaded_bytes": int(up["bytes"]), "uploaded_events": int(up["events"]), "bytes_per_day": per_day, "expected_total_bytes": expected,
            "events_per_day": float(up["events24"]) if hours and hours >= 24 else (float(up["events"]) / hours * 24 if hours and hours > 0.5 else None),
            "local_mb": h.get("spool_mb"), "disk_free_pct": h.get("disk_free_pct"),
            "early_model": {"hours": mat.get("baseline_hours"), "rules_only": bool(have_h is not None and have_h < EARLY_RULES_ONLY_BELOW_H),
                            "since": bundle.get("created_at") if bundle else None} if mat.get("early") else None,
            "next_model_hours": nxt if row["phase"] == "baseline" else None, "hours_recorded": round(hours, 1) if hours else None}
def check_summary(r: dict) -> dict:
    spec = r.get("spec") or {}
    summ = spec.get("summary") or {}
    fams: dict[str, dict] = {}
    for m in summ.get("matrix", []):
        f = fams.setdefault(m["family"], {"family": m["family"], "label": FAMILY_LABEL.get(m["family"], m["family"].replace("_", " ").replace("transplant:", "Recorded attack: ")),
                                          "attacks": 0, "detected": 0})
        f["attacks"] += int(m.get("fused", {}).get("n", m.get("runs", 0)))
        f["detected"] += int(m.get("fused", {}).get("k", 0))
    attacks, detected = sum(f["attacks"] for f in fams.values()), sum(f["detected"] for f in fams.values())
    clean = sum(int(v.get("alert_nodes", 0)) for v in (spec.get("clean") or {}).values())
    rate = detected / attacks if attacks else None
    state = r.get("state")
    if state != "done":
        verdict, text = None, {"queued": "Queued", "running": "Running"}.get(state, "Failed" if state == "failed" else state)
    elif not attacks:
        verdict, text = "warn", "The check produced no results"
    else:
        verdict = "pass" if rate >= 0.9 and clean == 0 else "warn" if rate >= 0.7 else "fail"
        text = f"{detected} of {attacks} simulated attacks detected; " + ("no false alarms on clean data" if clean == 0 else f"{clean} false alarms on clean data")
    return {"id": str(r["id"]) if r.get("id") else None, "state": state, "created_at": r.get("created_at"), "finished_at": r.get("finished_at"),
            "attacks": attacks, "detected": detected, "rate": round(rate, 3) if rate is not None else None,
            "false_alarms_on_clean_data": clean, "by_family": sorted(fams.values(), key=lambda f: f["label"]),
            "verdict": verdict, "verdict_text": text}


def row_phase(c, endpoint_id: str) -> str | None:
    r = db.q(c, "SELECT phase FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
    return r["phase"] if r else None


def _checks(c, endpoint_id: str) -> list[dict]:
    rows = db.q(c, "SELECT id, state, spec, created_at, finished_at FROM sim_campaigns WHERE endpoint_id=%s ORDER BY created_at DESC LIMIT 50", (endpoint_id,))
    return [check_summary(r) for r in rows]


@router.get("/api/endpoints/{endpoint_id}/overview")
def endpoint_overview(endpoint_id: str, s=Depends(session)):
    require_endpoint(s, endpoint_id)
    ep = _one_endpoint(s, endpoint_id)
    with db.conn() as c:
        row = db.q(c, "SELECT * FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
        days = list(db.q(c, "SELECT date, events, complete FROM baseline_days WHERE endpoint_id=%s ORDER BY date", (endpoint_id,)))
        if row_phase(c, endpoint_id) in ("pending", "baseline"):   # days still being collected (recorded when complete)
            have = {d["date"] for d in days}
            for r in db.q(c, "SELECT (received_at AT TIME ZONE 'UTC')::date AS date, sum(rows) AS events FROM upload_batches "
                             "WHERE endpoint_id=%s AND kind='events' GROUP BY 1 ORDER BY 1", (endpoint_id,)):
                if r["date"] not in have:
                    days.append({"date": r["date"], "events": int(r["events"]), "complete": False})
            days.sort(key=lambda d: d["date"])
        bundle = db.q(c, "SELECT id, path, manifest, created_at FROM bundles WHERE id=%s", (row["current_bundle"],), one=True) if row["current_bundle"] else None
        first_bundle = db.q(c, "SELECT min(created_at) AS at FROM bundles WHERE endpoint_id=%s", (endpoint_id,), one=True)["at"]
        ev24 = db.q(c, "SELECT coalesce(sum(rows), 0) AS n FROM upload_batches WHERE endpoint_id=%s AND kind='events' AND received_at > now() - interval '24 hours'",
                    (endpoint_id,), one=True)["n"]
        day_ns = time.time_ns() - 86400 * 10**9
        w24 = db.q(c, "SELECT coalesce(sum(edges), 0) AS n FROM windows WHERE endpoint_id=%s AND start_ns > %s", (endpoint_id, day_ns), one=True)["n"]
        alerts = db.q(c, "SELECT window_start_ns, coalesce(layer, 'learned') AS layer, status FROM alerts WHERE endpoint_id=%s", (endpoint_id,))
        incs = incidents.list_incidents(c, None, endpoint_id)
        checks = _checks(c, endpoint_id)
        training = db.q(c, "SELECT state, created_at, started_at FROM jobs WHERE endpoint_id=%s AND kind IN ('train','train_rules') ORDER BY created_at DESC LIMIT 1", (endpoint_id,), one=True)
        # model builds failing again and again (the scheduler keeps retrying): say so instead of "learning" in silence
        recent_builds = db.q(c, "SELECT state, error FROM jobs WHERE endpoint_id=%s AND kind IN ('train','train_rules') "
                                "AND state IN ('done','failed') ORDER BY created_at DESC LIMIT 3", (endpoint_id,))
        org = db.q(c, "SELECT agent_update FROM orgs WHERE id=%s", (row["org_id"],), one=True)
        # uploads before server 0.6 have no recorded size: estimated from this endpoint's measured bytes per event,
        # else 11 bytes (measured on the L40S host and client-vm-02, gzip NDJSON)
        up = db.q(c, "WITH b AS (SELECT rows, bytes, received_at FROM upload_batches WHERE endpoint_id=%s AND kind='events'), "
                     "r AS (SELECT coalesce(sum(bytes)::float / nullif(sum(rows) FILTER (WHERE bytes IS NOT NULL), 0), 11.0) AS bpe FROM b) "
                     "SELECT coalesce(sum(coalesce(bytes, rows * r.bpe)), 0) AS bytes, coalesce(sum(rows), 0) AS events, "
                     "coalesce(sum(coalesce(bytes, rows * r.bpe)) FILTER (WHERE received_at > now() - interval '24 hours'), 0) AS bytes24, "
                     "coalesce(sum(rows) FILTER (WHERE received_at > now() - interval '24 hours'), 0) AS events24, min(received_at) AS first "
                     "FROM b, r GROUP BY r.bpe", (endpoint_id,), one=True) or {"bytes": 0, "events": 0, "bytes24": 0, "events24": 0, "first": None}
    need, done = _needed(row["config"]), int(row["baseline_days_done"])
    has_model = bundle is not None
    # ---- lifecycle
    details = {}
    if bundle:
        lay = (bundle["manifest"] or {}).get("layers") or {}
        details["known_programs"] = lay.get("known_executables")
        details["benign_rules"] = sum((lay.get("benign_alarm_keys") or {}).values()) if isinstance(lay.get("benign_alarm_keys"), dict) else None
        try:
            spec = json.load(open(os.path.join(bundle["path"], "layers.json")))
            details["trusted_addresses"] = len(spec.get("trusted_ips") or [])
        except (OSError, ValueError):
            pass
        details["trained_on_days"] = len((bundle["manifest"] or {}).get("train_days") or []) + (1 if (bundle["manifest"] or {}).get("val_day") else 0)
    learning = row["phase"] in ("pending", "baseline")
    mat = ((bundle or {}).get("manifest") or {}).get("maturity") or {}
    early = bool(has_model and learning and mat.get("early"))
    early_h = mat.get("baseline_hours")
    early_txt = (f"{early_h:g} hours" if early_h is not None and early_h < 48 else f"{early_h / 24:.0f} days") if early_h is not None else "the activity so far"
    lifecycle = [
        {"step": "enrolled", "status": "done", "at": row["enrolled_at"], "text": "Agent installed and enrolled"},
        {"step": "baseline", "status": "active" if learning else "done",
         "text": f"Learning normal behaviour: {need - 1} days of activity plus 1 day to validate the model",
         "done": min(done, need), "needed": need,
         "days": [{"date": str(d["date"]), "events": int(d["events"]), "complete": d["complete"]} for d in days]},
        {"step": "model", "status": "active" if early else "done" if has_model else "active" if row["phase"] == "training" else "pending",
         "at": bundle["created_at"] if bundle else None,
         "text": (f"Early model trained on {early_txt} of activity; retrained as the endpoint learns, final model after day {need}" if early else
                  f"Detection model trained on {details.get('trained_on_days')} days" if has_model else
                  "Training the detection model" if row["phase"] == "training" else "Detection model is trained after the baseline"),
         "details": details},
        {"step": "protecting", "status": "active" if has_model and (row["phase"] in ("protected", "degraded") or early) else "done" if row["phase"] == "retired" else "pending",
         "at": first_bundle, "text": (f"Detecting with an early model since {first_bundle.strftime('%d %b %Y %H:%M')} UTC; expect more alerts on new but normal activity until the baseline is complete"
                                      if early and first_bundle else f"Protecting since {first_bundle.strftime('%d %b %Y')}" if has_model and first_bundle
                                      else "Detection starts after the first hour of activity (early model), and is final after the baseline")},
    ]
    # ---- health
    h = row["health"] or {}
    issues = []
    if not ep["online"] and row["phase"] != "retired" and row["kind"] == "live":
        issues.append("The agent is not reporting")
    from .health import problems
    from .updates import target_version
    tgt = target_version(org["agent_update"] if org else "auto")
    probs = problems(row, tgt) if row["kind"] == "live" else []
    issues += [p["text"] for p in probs if p["level"] != "info"]      # info (0.6 posture events) do not make it unhealthy
    if learning and days and not any(d["events"] for d in days) and ep["online"]:
        issues.append("No events have been received yet")
    build_failing = len(recent_builds) == 3 and all(b["state"] == "failed" for b in recent_builds)
    if build_failing:
        issues.append(f"Its detection model cannot be built (the last 3 attempts failed: {str(recent_builds[0]['error'] or 'unknown error')[:200]})")
    status = ("error" if (not ep["online"] and row["kind"] == "live" and row["phase"] != "retired") or any(p["level"] == "error" for p in probs)
              or build_failing
              else "warning" if issues else "ok")
    health = {"online": ep["online"], "last_seen": row["last_seen"], "agent_version": h.get("agent_version") or row["agent_version"],
              "collector": "Not running" if h.get("collector_error") else "eBPF (CO-RE)" if h.get("collector_lost") is not None else "Dataset replay" if row["kind"] == "benchmark"
                           else f"{(row['os'] or 'endpoint').capitalize()} agent {h.get('agent_version') or row['agent_version'] or ''}".strip(),
              "events_dropped": h.get("collector_lost"), "queue_depth": h.get("queue_depth"), "cpu_pct": h.get("cpu_pct"), "rss_mb": h.get("rss_mb"),
              "events_24h": int(ev24) + int(w24), "status": status, "issues": issues,
              "disk_free_pct": h.get("disk_free_pct"), "disk_free_mb": h.get("disk_free_mb"), "spool_mb": h.get("spool_mb"),
              "entities": h.get("entities"), "data_mb": h.get("data_mb"), "update": {**(h.get("update") or {}), "target": tgt},
              "integrity": _integrity_posture(row), "notes": [p["text"] for p in probs if p["level"] == "info"]}
    # ---- detection
    week = time.time_ns() - 7 * 86400 * 10**9
    a7 = [a for a in alerts if a["window_start_ns"] >= week]
    by_type = {k: sum(1 for a in a7 if a["layer"] == k) for k in ("novelty", "rules", "corroborated", "learned")}
    triaged = {"true_positive": sum(a["status"] == "true_positive" for a in alerts), "false_positive": sum(a["status"] == "false_positive" for a in alerts),
               "open": sum(a["status"] in ("open", "ack") for a in alerts)}
    pa = {d["date"]: d["n"] for d in _per_day(alerts, lambda a: a["window_start_ns"])}
    pi = {d["date"]: d["n"] for d in _per_day(incs, lambda i: i["first_ns"])}
    detection = {"incidents_open": sum(1 for i in incs if i["status"] in ACTIVE), "incidents_total": len(incs), "alerts_7d": len(a7),
                 "by_type_7d": by_type, "triaged": triaged, "per_day": [{"date": d, "alerts": pa[d], "incidents": pi[d]} for d in pa]}
    blocked = None
    if not has_model:
        blocked = f"the endpoint is still learning (day {min(done + 1, need)} of {need})" if learning else "the endpoint has no detection model yet"
    elif any(ck["state"] in ("queued", "running") for ck in checks):
        blocked = "a detection check is already running"
    elif row["phase"] == "retired":
        blocked = "the endpoint is retired"
    learning_info = learning_progress(row, done, need, bundle, h, up) if row["phase"] in ("pending", "baseline", "training") else None
    return {"ok": True, "endpoint": ep, "lifecycle": lifecycle, "health": health, "detection": detection, "learning": learning_info,
            "check": checks[0] if checks else None, "can_run_check": blocked is None and s["r"] in ("admin", "analyst"),
            "check_blocked_reason": blocked if blocked else (None if s["r"] in ("admin", "analyst") else "your role is read-only")}


@router.get("/api/endpoints/{endpoint_id}/checks")
def endpoint_checks(endpoint_id: str, s=Depends(session)):
    require_endpoint(s, endpoint_id)
    _one_endpoint(s, endpoint_id)
    with db.conn() as c:
        return {"ok": True, "checks": _checks(c, endpoint_id)}


@router.post("/api/endpoints/{endpoint_id}/checks")
def run_check(endpoint_id: str, s=Depends(triager)):
    require_endpoint(s, endpoint_id)
    _one_endpoint(s, endpoint_id)
    with db.conn() as c:
        ep = db.q(c, "SELECT current_bundle, phase FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
        if not ep["current_bundle"]:
            raise HTTPException(409, "the endpoint has no detection model yet")
        if ep["phase"] == "retired":
            raise HTTPException(409, "the endpoint is retired")
        if db.q(c, "SELECT 1 FROM sim_campaigns WHERE endpoint_id=%s AND state IN ('queued','running')", (endpoint_id,), one=True):
            raise HTTPException(409, "a detection check is already running")
        spec = {"days": ["validation"], "families": CHECK_FAMILIES, "evasion_levels": CHECK_LEVELS,
                "runs": len(CHECK_FAMILIES) * len(CHECK_LEVELS) * 6, "attacks_per_pass": 3, "seed": secrets.randbits(31)}
        cid = pki.new_id()
        db.q(c, "INSERT INTO sim_campaigns (id, name, endpoint_id, bundle_id, spec, seed, state) VALUES (%s,%s,%s,%s,%s,%s,'queued')",
             (cid, f"Detection check {datetime.now(timezone.utc):%Y-%m-%d %H:%M}", endpoint_id, None, json.dumps(spec), spec["seed"]))
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, params) VALUES (%s,%s,'sim',%s)", (pki.new_id(), endpoint_id, json.dumps({"campaign_id": cid})))
    return {"ok": True, "id": cid}
