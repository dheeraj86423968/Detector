"""Response actions (opt-in per organisation, admins): stop a process an alert was raised on, isolate an endpoint
from the network (only the PDP server stays reachable) and release it. Delivered as agent commands (0.3.15+); the
agent verifies a process is still the one that was alerted on before stopping it.

0.6: every action needs a reason; it is written to the audit log and the organisation's admins are notified (security
event `response_action`, pdp_server.posture), so isolating a host (or releasing one) cannot happen unnoticed."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from . import db, pki
from .access import admin, require_endpoint

router = APIRouter()
ACTIONS = ("kill_process", "isolate", "release")
ACTION_TEXT = {"kill_process": "process stopped", "isolate": "endpoint isolated from the network", "release": "endpoint released from isolation"}


class Respond(BaseModel):
    action: str
    node_uuid: str | None = None
    reason: str | None = Field(default=None, max_length=500)      # required (0.6)


@router.post("/api/endpoints/{endpoint_id}/respond")
def respond(endpoint_id: str, req: Respond, s=Depends(admin)):
    require_endpoint(s, endpoint_id)
    if req.action not in ACTIONS:
        raise HTTPException(400, f"action must be one of {list(ACTIONS)}")
    reason = (req.reason or "").strip()
    if not reason:
        raise HTTPException(400, "Reason required: give a reason for the response action (field 'reason'); it is recorded in the audit "
                                 "log and your organisation's admins are notified")
    with db.conn() as c:
        org = db.q(c, "SELECT response_actions FROM orgs WHERE id=%s", (s["org"],), one=True)
        if not org or not org["response_actions"]:
            raise HTTPException(403, "response actions are off for your organisation (Security settings)")
        ep = db.q(c, "SELECT name, phase, kind, agent_version FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
        if not ep or ep["phase"] == "retired" or ep["kind"] != "live":
            raise HTTPException(404, "not found")
        try:
            if tuple(int(x) for x in (ep["agent_version"] or "0").split(".")) < (0, 3, 15):
                raise HTTPException(409, "this endpoint's agent is too old for response actions (0.3.15 or later)")
        except ValueError:
            raise HTTPException(409, "this endpoint's agent version is unknown")
        params = {"command": req.action}
        if req.action == "kill_process":
            a = db.q(c, "SELECT display, label FROM alerts WHERE endpoint_id=%s AND node_uuid=%s AND ntype='subject' ORDER BY id DESC LIMIT 1",
                     (endpoint_id, req.node_uuid or ""), one=True)
            if not a:
                raise HTTPException(400, "only a process an alert was raised on can be stopped")
            pid = (a["display"] or {}).get("pid")
            if not isinstance(pid, int) or pid <= 1:
                raise HTTPException(400, "the alert does not record this process's id")
            params.update({"uuid": req.node_uuid, "pid": pid, "label": a["label"]})
        cid = pki.new_id()
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, params) VALUES (%s,%s,'command',%s)", (cid, endpoint_id, json.dumps(params)))
        from .posture import audit_change, security_event
        what = ACTION_TEXT[req.action] + (f" ({params.get('label')})" if req.action == "kill_process" else "")
        audit_change(c, s, f"response action: {req.action}", f"endpoint_id={endpoint_id}, command_id={cid}", reason=reason,
                     extra={"action": req.action, "process": params.get("label"), "pid": params.get("pid")})
        security_event(c, s["org"], "response_action", f"Response action on {ep['name']}: {what}", severity="high", s=s,
                       endpoint_id=endpoint_id, detail={"type": "response_action", "action": req.action, "reason": reason,
                                                        "command_id": cid, "endpoint_name": ep["name"], "changes": [what]})
    return {"ok": True, "id": cid}


@router.get("/api/endpoints/{endpoint_id}/commands/{command_id}")
def command_result(endpoint_id: str, command_id: str, s=Depends(admin)):
    require_endpoint(s, endpoint_id)
    with db.conn() as c:
        j = db.q(c, "SELECT state, result, params, created_at, finished_at FROM jobs WHERE id=%s AND endpoint_id=%s AND kind='command'",
                 (command_id, endpoint_id), one=True)
    if not j:
        raise HTTPException(404, "not found")
    return {"ok": True, **j}
