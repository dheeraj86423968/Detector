"""Threat hunting: "where did X happen?" across an organisation's endpoints. Each agent (0.3.17+) keeps a local,
de-duplicated activity index (programs run, addresses contacted in either direction, files written; first / last seen,
30 days); a hunt sends the search to every reporting agent of the organisation and collects the answers.

0.6: a hunt asks only the endpoints in the user's scope, and every user sees hunts and answers only for the endpoints
in their own scope (a user scoped to some endpoints never sees another endpoint's activity through someone else's
hunt). Every hunt is audited with its query text and rate-limited per user (pdp_server.posture)."""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from . import db, pki
from .access import scope_list, scope_sql, session, triager

router = APIRouter()
KINDS = ("exec", "net", "write")


class HuntReq(BaseModel):
    q: str = Field(min_length=2, max_length=200)
    kind: str | None = None


@router.post("/api/hunts")
def start_hunt(req: HuntReq, s=Depends(triager)):
    if req.kind not in (None, *KINDS):
        raise HTTPException(400, f"kind must be one of {list(KINDS)}")
    hid = pki.new_id()
    from .posture import audit_change, take
    with db.conn() as c:
        take(c, s["u"], "hunt")
    with db.conn() as c:
        where, args = scope_sql(s, "id")
        eps = db.q(c, f"SELECT id, agent_version FROM endpoints WHERE org_id=%s AND {where} AND kind='live' AND phase <> 'retired' "
                      "AND last_seen > now() - interval '1 day'", (s["org"], *args))
        ok = []
        for e in eps:
            try:
                if tuple(int(x) for x in (e["agent_version"] or "0").split(".")) >= (0, 3, 17):
                    ok.append(str(e["id"]))
            except ValueError:
                pass
        db.q(c, "INSERT INTO hunts (id, org_id, q, kind, created_by, endpoints) VALUES (%s,%s,%s,%s,%s,%s)",
             (hid, s["org"], req.q.strip(), req.kind, s["u"], json.dumps(ok)))
        for e in ok:
            db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, params) VALUES (%s,%s,'command',%s)",
                 (pki.new_id(), e, json.dumps({"command": "hunt", "hunt_id": hid, "q": req.q.strip(), "kind": req.kind, "limit": 200})))
        audit_change(c, s, "hunt started", f"hunt_id={hid}", extra={"query": req.q.strip(), "kind": req.kind, "endpoints": len(ok)})
    return {"ok": True, "id": hid, "endpoints": len(ok), "skipped": len(eps) - len(ok)}


@router.get("/api/hunts")
def list_hunts(s=Depends(session)):
    """The organisation's last 30 hunts that asked an endpoint in the user's scope (or that the user started), counted
    over those endpoints only."""
    scope = scope_list(s) or []
    with db.conn() as c:
        rows = db.q(c, "SELECT h.id, h.q, h.kind, h.created_at, coalesce(u.display_name, u.username) AS by, "
                       "(SELECT count(*) FROM jsonb_array_elements_text(h.endpoints) x WHERE x = ANY(%s::text[])) AS asked, "
                       "(SELECT count(*) FROM hunt_results r WHERE r.hunt_id=h.id AND r.endpoint_id = ANY(%s::uuid[])) AS answered, "
                       "(SELECT coalesce(sum(jsonb_array_length(r.rows)), 0) FROM hunt_results r WHERE r.hunt_id=h.id AND r.endpoint_id = ANY(%s::uuid[]) "
                       "AND NOT (r.rows @> '[{\"none\": true}]')) AS matches "
                       "FROM hunts h LEFT JOIN users u ON u.id=h.created_by WHERE h.org_id=%s AND (h.created_by=%s OR EXISTS "
                       "(SELECT 1 FROM jsonb_array_elements_text(h.endpoints) x WHERE x = ANY(%s::text[]))) ORDER BY h.created_at DESC LIMIT 30",
                    (scope, scope, scope, s["org"], s["u"], scope))
    return {"ok": True, "hunts": rows}


@router.get("/api/hunts/{hunt_id}")
def get_hunt(hunt_id: str, s=Depends(session)):
    with db.conn() as c:
        h = db.q(c, "SELECT * FROM hunts WHERE id=%s AND org_id=%s", (hunt_id, s["org"]), one=True) if _uuid(hunt_id) else None
        mine = [e for e in (h or {}).get("endpoints") or [] if e in set(scope_list(s) or [])]
        if not h or not (mine or h["created_by"] == s["u"]):
            raise HTTPException(404, "not found")
        res = {str(r["endpoint_id"]): r for r in db.q(c, "SELECT endpoint_id, rows, at FROM hunt_results WHERE hunt_id=%s AND endpoint_id = ANY(%s::uuid[])",
                                                      (hunt_id, mine))}
        names = {str(r["id"]): r["name"] for r in db.q(c, "SELECT id, name FROM endpoints WHERE id = ANY(%s::uuid[])", (mine,))}
    out = []
    for e in mine:
        r = res.get(e)
        rows = [x for x in (r["rows"] if r else []) if not x.get("none")]
        out.append({"id": e, "name": names.get(e, e), "answered": r is not None, "at": r["at"] if r else None, "rows": rows})
    out.sort(key=lambda x: (not x["rows"], not x["answered"], x["name"]))
    return {"ok": True, "hunt": {"id": str(h["id"]), "q": h["q"], "kind": h["kind"], "created_at": h["created_at"]}, "endpoints": out}


def _uuid(x: str) -> bool:
    import uuid
    try:
        uuid.UUID(x)
        return True
    except ValueError:
        return False


def agent_router(app, agent_endpoint, ndjson_rows):
    @app.post("/v1/endpoints/{endpoint_id}/hunts/{hunt_id}")
    async def hunt_answer(endpoint_id: str, hunt_id: str, request: Request, ep=Depends(agent_endpoint)):
        rows = [r async for r in ndjson_rows(request)][:500]
        with db.conn() as c:
            h = db.q(c, "SELECT endpoints FROM hunts WHERE id=%s", (hunt_id,), one=True)
            if not h or endpoint_id not in h["endpoints"]:
                raise HTTPException(404, "unknown hunt")
            db.q(c, "INSERT INTO hunt_results (hunt_id, endpoint_id, rows) VALUES (%s,%s,%s) ON CONFLICT (hunt_id, endpoint_id) DO UPDATE SET rows=excluded.rows, at=now()",
                 (hunt_id, endpoint_id, json.dumps(rows)))
        return {"ok": True}
