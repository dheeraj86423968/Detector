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

import math
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from . import db
from .access import admin, session

router = APIRouter()
CANARY_MIN = float(os.environ.get("PDP_UPDATE_CANARY_MIN", "30"))
# a version is held back for an organisation only when its failures reach both of these (security review F5: one
# compromised endpoint reporting "failed" must not veto every update for its organisation)
HOLD_MIN = int(os.environ.get("PDP_UPDATE_HOLD_MIN") or 2)                 # endpoints that reported the version failed
HOLD_PCT = float(os.environ.get("PDP_UPDATE_HOLD_PCT") or 10)              # ... and at least this share of those that tried it
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def latest() -> str | None:
    v = os.environ.get("PDP_AGENT_VERSION", "").strip()
    return v or None


def digest_for(version: str | None) -> str | None:
    """The manifest digest deploy/publish-agent.sh recorded for a published version (PDP_AGENT_DIGEST for the latest,
    PDP_AGENT_DIGESTS = "ver=sha256:...,ver=sha256:..." for every version published since digests were recorded).
    Agents and the installer pull by digest (security review F2): a version without one is not offered."""
    if not version:
        return None
    for item in os.environ.get("PDP_AGENT_DIGESTS", "").split(","):
        v, _, d = item.strip().partition("=")
        if v == version and DIGEST_RE.match(d):
            return d
    d = os.environ.get("PDP_AGENT_DIGEST", "").strip()
    if version == latest() and DIGEST_RE.match(d):
        return d
    return None


def image_ref(host: str, version: str) -> str | None:
    """<host>/pdp/agent:<version>@sha256:<digest>, or None when no digest is recorded for the version."""
    d = digest_for(version)
    return f"{host}/pdp/agent:{version}@{d}" if d else None


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


def hold(eps: list[dict], target: str) -> dict | None:
    """Whether the organisation's endpoints' failure reports hold `target` back: {held, failed_on, tried} or None.
    Held only when at least HOLD_MIN endpoints reported the version failed AND they are at least HOLD_PCT percent of
    the endpoints that tried it (run it, or reported it failed). Which endpoints reported is recorded."""
    failed = [e for e in eps if target in failed_versions(e)]
    tried = [e for e in eps if e.get("agent_version") == target or target in failed_versions(e)]
    if not failed:
        return None
    need = max(HOLD_MIN, math.ceil(len(tried) * HOLD_PCT / 100.0))
    out = {"failed_on": [{"id": str(e["id"]), "name": e.get("name")} for e in failed], "tried": len(tried), "held": None}
    if len(failed) >= need:
        out["held"] = (f"version {target} failed to start on {len(failed)} of the {len(tried)} endpoints that tried it "
                       f"({', '.join(str(e.get('name') or e['id']) for e in failed[:5])}) and was rolled back there")
    return out


def rollout(c, org_id, target: str | None) -> dict:
    """{ready: endpoints may all update, canary: endpoint id allowed first, held: reason, failed_on: [...]}"""
    if not target:
        return {"ready": False, "canary": None, "held": None, "failed_on": []}
    eps = db.q(c, "SELECT id, name, agent_version, agent_version_since, last_seen, enrolled_at, health FROM endpoints "
                  "WHERE org_id=%s AND kind='live' AND phase <> 'retired' AND enrolled_at IS NOT NULL ORDER BY enrolled_at, id", (org_id,))
    h = hold(eps, target) or {}
    if h.get("held"):
        return {"ready": False, "canary": None, "held": h["held"], "failed_on": h["failed_on"]}
    now = datetime.now(timezone.utc)
    proven = any(e["agent_version"] == target and e["agent_version_since"] and e["last_seen"]
                 and (now - e["agent_version_since"]).total_seconds() >= CANARY_MIN * 60
                 and (now - e["last_seen"]).total_seconds() < 300 for e in eps)
    failed_on = h.get("failed_on") or []
    if proven:
        return {"ready": True, "canary": None, "held": None, "failed_on": failed_on}
    on_target = [e for e in eps if e["agent_version"] == target]
    if on_target:      # a canary is on it, not proven yet: nobody else moves
        return {"ready": False, "canary": str(on_target[0]["id"]), "held": None, "failed_on": failed_on}
    online = [e for e in eps if e["last_seen"] and (now - e["last_seen"]).total_seconds() < 300
              and target not in failed_versions(e)]       # an endpoint that already failed on it is not the canary
    return {"ready": False, "canary": str(online[0]["id"]) if online else None, "held": None, "failed_on": failed_on}


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
    image = image_ref(host, target)
    if not image:                            # no recorded digest: never hand out a tag-only reference (F2)
        return None
    return {"version": target, "image": image, "registry": host}


def pull_token(c, endpoint_id) -> str:
    t = secrets.token_urlsafe(32)
    db.q(c, "DELETE FROM pull_tokens WHERE expires_at < now()")
    db.q(c, "INSERT INTO pull_tokens (token, endpoint_id, expires_at) VALUES (%s,%s,%s)",
         (t, endpoint_id, datetime.now(timezone.utc) + timedelta(minutes=15)))
    return t


# ------------------------------------------------------------------------------------------------ console
class UpdatePolicy(BaseModel):
    agent_update: str
    reason: str | None = Field(default=None, max_length=500)    # required when the pin rolls the fleet back (operator)


@router.get("/api/org/agent-updates")
def get_policy(s=Depends(session)):
    with db.conn() as c:
        org = db.q(c, "SELECT agent_update FROM orgs WHERE id=%s", (s["org"],), one=True)
        pol = org["agent_update"] if org else "auto"
        tgt = target_version(pol)
        r = rollout(c, s["org"], tgt)
        eps = db.q(c, "SELECT agent_version, count(*) AS n FROM endpoints WHERE org_id=%s AND kind='live' AND phase <> 'retired' "
                      "AND enrolled_at IS NOT NULL GROUP BY 1", (s["org"],))
    return {"ok": True, "policy": pol, "latest": latest(), "target": tgt, "held": r["held"], "failed_on": r.get("failed_on") or [],
            "staged": bool(tgt and not r["ready"]), "digest": digest_for(tgt),
            "versions": {(e["agent_version"] or "unknown"): e["n"] for e in eps}, "canary_minutes": CANARY_MIN}


def fleet_versions(c, org_id) -> list[str]:
    return [r["agent_version"] for r in db.q(c, "SELECT DISTINCT agent_version FROM endpoints WHERE org_id=%s AND kind='live' "
                                                 "AND phase <> 'retired' AND agent_version IS NOT NULL", (org_id,)) if VERSION_RE.match(r["agent_version"] or "")]


def is_downgrade(pin: str, versions: list[str]) -> bool:
    """A pinned version below any version the organisation's endpoints run now."""
    return bool(versions) and any(vkey(pin) < vkey(v) for v in versions)


@router.patch("/api/org/agent-updates")
def set_policy(req: UpdatePolicy, s=Depends(admin)):
    """Security review F4: an organisation admin may pin any version at or above what the fleet runs; rolling agents
    back (a pin below a running version) is for the platform operator, needs a reason and is recorded as a
    detection-weakening security event (older agents lack later evasion fixes)."""
    from .posture import audit_change, require_reason, weakened
    p = req.agent_update.strip()
    if p not in ("auto", "manual") and not VERSION_RE.match(p):
        raise HTTPException(400, "agent_update must be auto, manual or a version such as 0.3.7")
    if VERSION_RE.match(p) and latest() and vkey(p) > vkey(latest()):
        raise HTTPException(400, f"version {p} is not published on this server (latest is {latest()})")
    if VERSION_RE.match(p) and not digest_for(p):
        raise HTTPException(400, f"version {p} has no recorded image digest on this server; the operator must publish it (deploy/publish-agent.sh {p})")
    with db.conn() as c:
        before = (db.q(c, "SELECT agent_update FROM orgs WHERE id=%s", (s["org"],), one=True) or {}).get("agent_update") or "auto"
        down = VERSION_RE.match(p) and is_downgrade(p, fleet_versions(c, s["org"]))
        changes = [f"agent update policy pinned to {p}, below the version the organisation's agents run"] if down else []
        if down and not s.get("op"):
            raise HTTPException(403, f"version {p} is older than what this organisation's agents run; only the platform operator can roll agents back")
        reason = require_reason(changes, req.reason)
        db.q(c, "UPDATE orgs SET agent_update=%s WHERE id=%s", (p, s["org"]))
        audit_change(c, s, "agent update policy changed", None, before={"agent_update": before}, after={"agent_update": p}, reason=reason,
                     extra={"weakens": changes} if changes else None)
        weakened(c, s, changes, reason, subject="agent update policy", before={"agent_update": before}, after={"agent_update": p})
    return get_policy(s)
