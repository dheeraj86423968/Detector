"""Agent updates: which version each endpoint should run, staged per organisation, and pull access for it.

Policy per organisation (orgs.agent_update): "auto" (the version the operator published, PDP_AGENT_VERSION),
"manual" (agents are never asked to update), or a pinned version such as "0.3.7".

Staged rollout ("auto" and pinned): one endpoint of the organisation goes first (the canary: the longest-enrolled
online endpoint); the others follow once an endpoint has run the target version and reported for
CANARY_MIN minutes. If any endpoint reports that the version failed on it (the host's updater rolled back), nothing
more of the organisation is moved to that version and the console shows why.

The agent receives {"update": {"version", "image"}} in its status, asks POST /v1/endpoints/{id}/pull-token for a
15-minute registry credential (the registry admits `pdp:<pull token>` like an enrolment token) and hands both to
the updater on its host (installed by install.sh: pulls, switches, rolls back if the new agent does not come up).
"""
from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import db
from .access import admin, session

router = APIRouter()
CANARY_MIN = float(os.environ.get("PDP_UPDATE_CANARY_MIN", "30"))
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def latest() -> str | None:
    v = os.environ.get("PDP_AGENT_VERSION", "").strip()
    return v or None


def vkey(v: str | None) -> tuple:
    try:
        return tuple(int(x) for x in (v or "").split("."))
    except ValueError:
        return ()


def target_version(policy: str | None) -> str | None:
    p = (policy or "auto").strip()
    if p == "manual":
        return None
    if p == "auto":
        return latest()
    return p if VERSION_RE.match(p) else None


def failed_versions(ep: dict) -> list[str]:
    return list(((ep.get("health") or {}).get("update") or {}).get("failed") or [])


def rollout(c, org_id, target: str | None) -> dict:
    """{ready: endpoints may all update, canary: endpoint id allowed first, held: reason}"""
    if not target:
        return {"ready": False, "canary": None, "held": None}
    eps = db.q(c, "SELECT id, agent_version, agent_version_since, last_seen, enrolled_at, health FROM endpoints "
                  "WHERE org_id=%s AND kind='live' AND phase <> 'retired' AND enrolled_at IS NOT NULL ORDER BY enrolled_at, id", (org_id,))
    for e in eps:
        if target in failed_versions(e):
            return {"ready": False, "canary": None, "held": f"version {target} failed to start on one endpoint and was rolled back there"}
    now = datetime.now(timezone.utc)
    proven = any(e["agent_version"] == target and e["agent_version_since"] and e["last_seen"]
                 and (now - e["agent_version_since"]).total_seconds() >= CANARY_MIN * 60
                 and (now - e["last_seen"]).total_seconds() < 300 for e in eps)
    if proven:
        return {"ready": True, "canary": None, "held": None}
    on_target = [e for e in eps if e["agent_version"] == target]
    if on_target:      # a canary is on it, not proven yet: nobody else moves
        return {"ready": False, "canary": str(on_target[0]["id"]), "held": None}
    online = [e for e in eps if e["last_seen"] and (now - e["last_seen"]).total_seconds() < 300]
    return {"ready": False, "canary": str(online[0]["id"]) if online else None, "held": None}


def update_for(c, ep: dict) -> dict | None:
    """The update to offer this endpoint now, or None."""
    org = db.q(c, "SELECT agent_update FROM orgs WHERE id=%s", (ep["org_id"],), one=True) if ep.get("org_id") else None
    target = target_version(org["agent_update"] if org else "auto")
    cur = ep.get("agent_version")
    if not target or not cur or cur == target or target in failed_versions(ep):
        return None
    if org and org["agent_update"] == "auto" and vkey(target) <= vkey(cur):
        return None                          # "auto" never downgrades; a pinned version may
    r = rollout(c, ep["org_id"], target)
    if not (r["ready"] or r["canary"] == str(ep["id"])):
        return None
    host = os.environ.get("PDP_PUBLIC_HOSTNAME")
    if not host:
        return None
    return {"version": target, "image": f"{host}/pdp/agent:{target}", "registry": host}


def pull_token(c, endpoint_id) -> str:
    t = secrets.token_urlsafe(32)
    db.q(c, "DELETE FROM pull_tokens WHERE expires_at < now()")
    db.q(c, "INSERT INTO pull_tokens (token, endpoint_id, expires_at) VALUES (%s,%s,%s)",
         (t, endpoint_id, datetime.now(timezone.utc) + timedelta(minutes=15)))
    return t


# ------------------------------------------------------------------------------------------------ console
class UpdatePolicy(BaseModel):
    agent_update: str


@router.get("/api/org/agent-updates")
def get_policy(s=Depends(session)):
    with db.conn() as c:
        org = db.q(c, "SELECT agent_update FROM orgs WHERE id=%s", (s["org"],), one=True)
        pol = org["agent_update"] if org else "auto"
        tgt = target_version(pol)
        r = rollout(c, s["org"], tgt)
        eps = db.q(c, "SELECT agent_version, count(*) AS n FROM endpoints WHERE org_id=%s AND kind='live' AND phase <> 'retired' "
                      "AND enrolled_at IS NOT NULL GROUP BY 1", (s["org"],))
    return {"ok": True, "policy": pol, "latest": latest(), "target": tgt, "held": r["held"], "staged": bool(tgt and not r["ready"]),
            "versions": {(e["agent_version"] or "unknown"): e["n"] for e in eps}, "canary_minutes": CANARY_MIN}


@router.patch("/api/org/agent-updates")
def set_policy(req: UpdatePolicy, s=Depends(admin)):
    p = req.agent_update.strip()
    if p not in ("auto", "manual") and not VERSION_RE.match(p):
        raise HTTPException(400, "agent_update must be auto, manual or a version such as 0.3.7")
    if VERSION_RE.match(p) and latest() and vkey(p) > vkey(latest()):
        raise HTTPException(400, f"version {p} is not published on this server (latest is {latest()})")
    with db.conn() as c:
        db.q(c, "UPDATE orgs SET agent_update=%s WHERE id=%s", (p, s["org"]))
    return get_policy(s)
