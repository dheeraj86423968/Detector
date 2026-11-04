"""Kubernetes: one manifest installs the agent on every node of a cluster (DaemonSet). The cluster enrols with one
fleet token (at most `max_nodes` enrolments, valid `days`); each node becomes an endpoint named after the node. The
agent runs privileged in the host pid and network namespaces with its state on the node (/var/lib/pdp), like the
one-line installer, and is updated by applying the manifest again (it carries the version the server currently
hands out; there is no host updater inside a cluster)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from . import db, pki
from .access import admin

router = APIRouter()
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")


def key_of(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def _q(v: str) -> str:            # YAML double-quoted scalar
    return json.dumps(v)


def manifest(token: str, cluster: str, request: Request) -> str:
    from .distrib import agent_image, public_host
    host = public_host(request)
    agent = f"https://{host}:{os.environ.get('PDP_AGENT_PORT', '8443')}"
    image = agent_image(host) or os.environ.get("PDP_AGENT_IMAGE", "pdp/agent:latest")
    pull = ""
    if agent_image(host):
        auth = {"auths": {host: {"username": "pdp", "password": token, "auth": base64.b64encode(f"pdp:{token}".encode()).decode()}}}
        pull = f"""---
apiVersion: v1
kind: Secret
metadata: {{name: pdp-registry, namespace: pdp-system}}
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: {base64.b64encode(json.dumps(auth).encode()).decode()}
"""
    return f"""# PDP agent for Kubernetes cluster {_q(cluster)}: kubectl apply -f this file. Every node (control plane included)
# runs one agent and appears in the console as its own endpoint. Re-apply a fresh copy from the console to update.
# The enrolment token in this file is valid until the date shown in the console and for a limited number of nodes:
# keep the file like a password. Removing: kubectl delete namespace pdp-system (then retire the endpoints).
apiVersion: v1
kind: Namespace
metadata:
  name: pdp-system
  labels: {{pod-security.kubernetes.io/enforce: privileged}}
---
apiVersion: v1
kind: Secret
metadata: {{name: pdp-enroll, namespace: pdp-system}}
type: Opaque
stringData:
  token: {_q(token)}
{pull}---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: pdp-agent
  namespace: pdp-system
  labels: {{app.kubernetes.io/name: pdp-agent}}
spec:
  selector:
    matchLabels: {{app.kubernetes.io/name: pdp-agent}}
  updateStrategy:
    type: RollingUpdate
    rollingUpdate: {{maxUnavailable: 1}}
  template:
    metadata:
      labels: {{app.kubernetes.io/name: pdp-agent}}
    spec:
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      priorityClassName: system-node-critical
      terminationGracePeriodSeconds: 40
      tolerations:
      - operator: Exists
{"      imagePullSecrets: [{name: pdp-registry}]" + chr(10) if pull else ""}      containers:
      - name: agent
        image: {_q(image)}
        imagePullPolicy: IfNotPresent
        args: [run]
        securityContext: {{privileged: true}}
        env:
        - name: PDP_ENROLL_TOKEN
          valueFrom: {{secretKeyRef: {{name: pdp-enroll, key: token}}}}
        - name: PDP_HOSTNAME
          valueFrom: {{fieldRef: {{fieldPath: spec.nodeName}}}}
        - {{name: PDP_CA_SHA256, value: {_q(pki.ca_sha256())}}}
        - {{name: PDP_SOURCE_KIND, value: ebpf}}
        - {{name: PDP_SERVER_URL, value: {_q(agent)}}}
        - {{name: PDP_AGENT_URL, value: {_q(agent)}}}
        resources:
          requests: {{cpu: 100m, memory: 512Mi}}
          limits: {{memory: 4Gi}}
        volumeMounts:
        - {{name: state, mountPath: /var/lib/pdp}}
      volumes:
      - name: state
        hostPath: {{path: /var/lib/pdp, type: DirectoryOrCreate}}
"""


class ClusterReq(BaseModel):
    cluster: str = Field(min_length=1, max_length=63)
    max_nodes: int = Field(default=50, ge=1, le=5000)
    days: int = Field(default=30, ge=1, le=365)


@router.post("/api/clusters")
def new_cluster(req: ClusterReq, request: Request, s=Depends(admin)):
    if not NAME_RE.match(req.cluster):
        raise HTTPException(400, "cluster name: letters, digits, space, dot, dash, underscore")
    token = secrets.token_urlsafe(24)
    exp = datetime.now(timezone.utc) + timedelta(days=req.days)
    with db.conn() as c:
        db.q(c, "INSERT INTO enroll_tokens (token, name, created_by, expires_at, kind, config, org_id, max_uses) VALUES (%s,%s,%s,%s,'live','{}',%s,%s)",
             (token, req.cluster, s["u"], exp, s["org"], req.max_nodes))
    return {"ok": True, "key": key_of(token), "expires_at": exp, "max_nodes": req.max_nodes, "manifest": manifest(token, req.cluster, request)}


def _cluster_tokens(c, org) -> list[dict]:
    return db.q(c, "SELECT token, name, uses, max_uses, expires_at FROM enroll_tokens WHERE org_id=%s AND max_uses IS NOT NULL "
                   "ORDER BY expires_at DESC", (org,))


@router.get("/api/clusters")
def list_clusters(s=Depends(admin)):
    now = datetime.now(timezone.utc)
    with db.conn() as c:
        rows = _cluster_tokens(c, s["org"])
        nodes = {r["cluster"]: r["n"] for r in db.q(c, "SELECT config->>'cluster' AS cluster, count(*) AS n FROM endpoints WHERE org_id=%s "
                                                       "AND config ? 'cluster' AND phase <> 'retired' GROUP BY 1", (s["org"],))}
    return {"ok": True, "clusters": [{"key": key_of(r["token"]), "cluster": r["name"], "uses": r["uses"], "max_nodes": r["max_uses"],
                                      "expires_at": r["expires_at"], "active": r["expires_at"] > now, "endpoints": nodes.get(r["name"], 0)} for r in rows]}


def _find(c, org, key):
    for r in _cluster_tokens(c, org):
        if key_of(r["token"]) == key:
            return r
    raise HTTPException(404, "not found")


@router.get("/api/clusters/{key}/manifest")
def cluster_manifest(key: str, request: Request, s=Depends(admin)):
    with db.conn() as c:
        r = _find(c, s["org"], key)
    if r["expires_at"] <= datetime.now(timezone.utc):
        raise HTTPException(410, "this cluster token has expired or was revoked; create a new one")
    return PlainTextResponse(manifest(r["token"], r["name"], request), media_type="application/yaml",
                             headers={"Cache-Control": "no-store", "Content-Disposition": f'attachment; filename="pdp-agent-{key}.yaml"'})


@router.post("/api/clusters/{key}/revoke")
def revoke_cluster(key: str, s=Depends(admin)):
    """New nodes can no longer enrol (or pull the image with this token); enrolled nodes keep working."""
    with db.conn() as c:
        r = _find(c, s["org"], key)
        db.q(c, "UPDATE enroll_tokens SET expires_at=least(expires_at, now()) WHERE token=%s", (r["token"],))
    return {"ok": True}
