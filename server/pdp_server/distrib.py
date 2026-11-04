"""Agent distribution for hosted clients: the one-line installer and pull access to the agent image.

GET /install.sh renders install.sh.tmpl for this server (its public address, agent port and the published agent
image). The image lives in the stack's registry, which the gateway exposes read-only under /v2/; every request is
first sent to /api/registry/auth, which admits Basic credentials `pdp:<enrolment token>` (or an agent's 15-minute
update pull token, updates.py) while the token is valid
(24 hours, used or not, its organisation enabled) - so only someone who was just given a token can download the
agent, and nothing is pushed from outside (pushes go to 127.0.0.1:5000 on the server, deploy/publish-agent.sh).
"""
from __future__ import annotations

import base64
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

from . import db

router = APIRouter()
TEMPLATE = os.path.join(os.path.dirname(__file__), "install.sh.tmpl")


def public_host(request: Request) -> str:
    """The console host clients use: the configured public hostname, else the host this request came to."""
    return os.environ.get("PDP_PUBLIC_HOSTNAME") or (request.headers.get("host") or "localhost").split(":")[0]


def agent_image(host: str) -> str | None:
    ver = os.environ.get("PDP_AGENT_VERSION", "").strip()
    return f"{host}/pdp/agent:{ver}" if ver else None


@router.get("/install.sh")
def install_script(request: Request):
    host = public_host(request)
    port = os.environ.get("PDP_CONSOLE_PORT", "443")
    server = f"https://{host}" + ("" if port == "443" else f":{port}")
    image = agent_image(host)
    if not image:
        body = "#!/bin/sh\necho 'error: no agent has been published on this server yet (operator: deploy/publish-agent.sh)' >&2\nexit 1\n"
        return PlainTextResponse(body, media_type="text/x-shellscript")
    with open(TEMPLATE) as f:
        body = f.read()
    body = (body.replace("__SERVER__", server).replace("__AGENT_URL__", f"https://{host}:{os.environ.get('PDP_AGENT_PORT', '8443')}")
                .replace("__IMAGE__", image).replace("__REGISTRY__", host))
    return PlainTextResponse(body, media_type="text/x-shellscript", headers={"Cache-Control": "no-store"})


@router.get("/api/registry/auth")
def registry_auth(request: Request):
    """nginx auth_request for /v2/: 204 admits the pull, 401 asks docker for credentials."""
    h = request.headers.get("authorization") or ""
    if not h.lower().startswith("basic "):
        raise HTTPException(401, "credentials required")
    try:
        user, _, token = base64.b64decode(h[6:].strip()).decode().partition(":")
    except Exception:
        raise HTTPException(401, "bad credentials") from None
    if user != "pdp" or not token or len(token) > 100:
        raise HTTPException(401, "bad credentials")
    with db.conn() as c:
        ok = db.q(c, "SELECT 1 FROM enroll_tokens t JOIN orgs o ON o.id=t.org_id WHERE t.token=%s AND t.expires_at > now() AND NOT o.disabled",
                  (token,), one=True) or db.q(c, "SELECT 1 FROM pull_tokens p JOIN endpoints e ON e.id=p.endpoint_id JOIN orgs o ON o.id=e.org_id "
                                                 "WHERE p.token=%s AND p.expires_at > now() AND NOT o.disabled AND e.phase <> 'retired'", (token,), one=True)
    if not ok:
        raise HTTPException(401, "bad credentials")
    return Response(status_code=204)
