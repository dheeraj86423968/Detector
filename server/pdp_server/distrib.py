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
import re
import time

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


BTF_DIR = os.environ.get("PDP_BTF_DIR", "/btf")
RELEASE_RE = re.compile(r"^[A-Za-z0-9._+~-]{1,120}$")


def find_btf(release: str, arch: str) -> str | None:
    """A BTF file for kernels without their own (/sys/kernel/btf/vmlinux): the operator puts them in PDP_BTF_DIR
    (deploy/btf) as <release>.btf, or as BTFHub's tree (<distro>/<version>/<arch>/<release>.btf.tar.xz)."""
    arch = {"aarch64": "arm64", "amd64": "x86_64"}.get(arch, arch)
    other = {"x86_64": "/arm64/", "arm64": "/x86_64/"}.get(arch, "/-/")
    hits = [os.path.join(root, f) for root, _d, files in os.walk(BTF_DIR) for f in files
            if f in (release + ".btf", release + ".btf.tar.xz") and other not in os.path.join(root, "")]
    hits.sort(key=lambda p: (f"/{arch}/" not in p, p.endswith(".tar.xz")))   # this architecture first, raw files first
    return hits[0] if hits else None


@router.get("/api/public/btf/{release}")
def btf_available(release: str, arch: str = "x86_64"):
    """For the installer on a kernel without BTF: can this server provide it? (availability only, no content)"""
    return {"ok": True, "available": bool(RELEASE_RE.match(release) and find_btf(release, arch))}


_sizes: dict[str, tuple[float, dict]] = {}
MANIFESTS = ("application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, "
             "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")


def image_sizes(ver: str) -> dict[str, int]:
    """Download size (compressed layers) of the published agent per architecture, read from the stack's registry
    (cached 10 minutes): the installer shows its download progress against it. {} when the registry is unreachable."""
    import json
    import urllib.request
    hit = _sizes.get(ver)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    base = os.environ.get("PDP_REGISTRY_URL", "http://registry:5000") + "/v2/pdp/agent/manifests/"

    def get(ref):
        with urllib.request.urlopen(urllib.request.Request(base + ref, headers={"Accept": MANIFESTS}), timeout=5) as r:
            return json.loads(r.read(1 << 20))
    out: dict[str, int] = {}
    try:
        m = get(ver)
        if "manifests" in m:                     # multi-architecture index (attestations have no platform)
            for e in m["manifests"]:
                arch = (e.get("platform") or {}).get("architecture")
                if arch in ("amd64", "arm64") and arch not in out:
                    out[arch] = sum(int(x.get("size", 0)) for x in get(e["digest"]).get("layers", []))
        else:
            out["amd64"] = sum(int(x.get("size", 0)) for x in m.get("layers", []))
    except Exception:  # noqa: BLE001 - progress then shows megabytes without a total
        out = {}
    _sizes[ver] = (time.time(), out)
    return out


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
    sizes = image_sizes(os.environ.get("PDP_AGENT_VERSION", "").strip())
    body = body.replace("__IMAGE_BYTES_AMD64__", str(sizes.get("amd64", 0))).replace("__IMAGE_BYTES_ARM64__", str(sizes.get("arm64", 0)))
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
