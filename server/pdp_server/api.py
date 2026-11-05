"""FastAPI application: agent API (mTLS, client CN = endpoint id, enforced by the gateway and re-checked here)
and console API (session cookie, roles)."""
from __future__ import annotations

import gzip
import io
import json
import os
import secrets
import tarfile
import time
import uuid as uuidlib
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

import psycopg2.extras

from . import auth, db, oidc, pki
from .access import admin, end_sessions, require_endpoint, scope_sql, session, set_session, triager, visible
from .graphs import alert_graph, endpoint_timeline, incident_graph

app = FastAPI(title="PDP", docs_url=None, redoc_url=None, openapi_url=None)


def _include_console_routes():
    from .allowlist import router as allow_router
    from .console import router
    from .orgs import router as org_router
    from .distrib import router as dist_router
    from .notify import router as notify_router
    from .updates import router as updates_router
    from .metrics import router as metrics_router
    from .reports import router as reports_router
    from .audit import router as audit_router
    from .mfa import router as mfa_router
    from .sso import router as sso_router
    from .respond import router as respond_router
    from .hunt import router as hunt_router, agent_router as hunt_agent_router
    from .k8s import router as k8s_router
    app.include_router(dist_router)
    app.include_router(router)
    app.include_router(allow_router)
    app.include_router(org_router)
    app.include_router(notify_router)
    app.include_router(updates_router)
    app.include_router(metrics_router)
    app.include_router(reports_router)
    app.include_router(audit_router)
    app.include_router(mfa_router)
    app.include_router(sso_router)
    app.include_router(respond_router)
    app.include_router(hunt_router)
    app.include_router(k8s_router)
    hunt_agent_router(app, agent_endpoint, ndjson_rows)
DATA_DIR = os.environ.get("PDP_DATA_DIR", "/data")
ALERT_STATUSES = ("open", "ack", "closed", "true_positive", "false_positive")
FP_BUDGETS = (None, "99", "99.9", "99.99")
AGENT_COMMANDS = ("refetch_bundle",)
CONFIG_KEYS = {"baseline_days", "tz", "retain_baseline_events", "train", "window_minutes", "fp_budget",
               "approved_executables", "learned_daily_budget", "learned_alerts", "periodic_retrain", "early_models"}
SERVER_HOSTNAMES = os.environ.get("PDP_HOSTNAMES", "localhost").split(",")


@app.on_event("startup")
def startup():
    initialize()


def initialize():
    """PKI, schema and the first admin. Several API worker processes start at once: everything runs under one
    Postgres advisory lock so keys and DDL are created exactly once. Also run by the entrypoint before uvicorn."""
    import psycopg2
    lock = psycopg2.connect(db.PLATFORM_DSN)
    lock.autocommit = True
    try:
        with lock.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(714001)")
        _initialize()
    finally:
        with lock.cursor() as cur:
            cur.execute("SELECT pg_advisory_unlock(714001)")
        lock.close()


def _initialize():
    pki.ensure_pki(SERVER_HOSTNAMES)
    schema_changed = db.init_platform(os.path.join(os.path.dirname(__file__), "schema.sql"))
    from . import orgs
    with db.conn() as c:
        orgs.migrate(c)
    from .allowlist import migrate
    with db.conn() as c:
        migrate(c)
    if schema_changed:     # telemetry DDL is idempotent: re-apply it so schema changes reach existing endpoints
        with db.conn() as c:
            for ep in db.q(c, "SELECT id FROM endpoints"):
                db.init_telemetry(str(ep["id"]))
    with db.conn() as c:
        if not db.q(c, "SELECT 1 FROM users LIMIT 1"):
            # PDP_INITIAL_ADMIN_PASSWORD: only for the very first admin (staging / automated stacks); else generated
            pw = os.environ.get("PDP_INITIAL_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
            from .orgs import internal_org
            created = db.q(c, "INSERT INTO users (username, password_hash, role, org_id, operator) VALUES ('admin', %s, 'admin', %s, true) "
                              "ON CONFLICT (username) DO NOTHING RETURNING id", (auth.hash_password(pw), internal_org(c)), one=True)
            if not created:  # created concurrently (cannot happen under the lock, kept for safety)
                return
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(os.path.join(DATA_DIR, "initial-admin-password.txt"), "w") as f:
                f.write(pw + "\n")
            os.chmod(os.path.join(DATA_DIR, "initial-admin-password.txt"), 0o600)


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    from .audit import middleware
    return await middleware(request, call_next)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def err(status: int, msg: str):
    return JSONResponse({"ok": False, "error": msg}, status_code=status)


# ============================================================================ agent side
def agent_endpoint(endpoint_id: str, x_client_dn: str | None = Header(default=None), x_client_verify: str | None = Header(default=None)) -> dict:
    """The gateway terminates mTLS and forwards the verified client subject DN; its CN must equal the path endpoint id."""
    import re as _re
    m = _re.search(r"(?:^|,)CN=([^,]+)", x_client_dn or "")
    if x_client_verify != "SUCCESS" or not m or m.group(1) != endpoint_id:
        raise HTTPException(403, "client certificate does not match endpoint")
    with db.conn() as c:
        ep = db.q(c, "SELECT * FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
        if not ep or ep["phase"] == "retired":
            raise HTTPException(404, "unknown endpoint")
        db.q(c, "UPDATE endpoints SET last_seen=now() WHERE id=%s", (endpoint_id,))
    return ep


class EnrollReq(BaseModel):
    token: str
    hostname: str
    os: str = "linux"
    arch: str = "x86_64"
    agent_version: str = "0.1.0"
    tz: str = "UTC"
    csr_pem: str


@app.post("/v1/enroll")
def enroll(req: EnrollReq):
    with db.conn() as c:
        tok = db.q(c, "SELECT * FROM enroll_tokens WHERE token=%s AND (used_by IS NULL OR max_uses IS NOT NULL) AND expires_at > now()",
                   (req.token,), one=True)
        if not tok:
            raise HTTPException(403, "invalid or expired token")
        fleet = tok.get("max_uses") is not None      # Kubernetes: one token for many nodes
        if fleet:
            from .orgs import check_endpoint_limit
            check_endpoint_limit(c, tok["org_id"])
            if not db.q(c, "UPDATE enroll_tokens SET uses = uses + 1 WHERE token=%s AND uses < max_uses RETURNING uses", (req.token,), one=True):
                raise HTTPException(403, f"this cluster token has enrolled all {tok['max_uses']} nodes it allows; create a new one in the console")
        eid = pki.new_id()
        cert, serial = pki.sign_csr(req.csr_pem, eid)
        kind = tok.get("kind") or "live"
        cfg = {"baseline_days": 7, "window_minutes": 15, "kind": kind, "tz": req.tz}
        if tok.get("dataset"):
            cfg["dataset"], cfg["dataset_host"] = tok["dataset"], "postgres"
        if fleet:
            cfg["cluster"] = tok["name"]
        cfg.update(tok.get("config") or {})
        if not tok.get("org_id") or db.q(c, "SELECT 1 FROM orgs WHERE id=%s AND disabled", (tok["org_id"],), one=True):
            raise HTTPException(403, "invalid or expired token")
        db.q(c, "INSERT INTO endpoints (id, name, hostname, os, arch, agent_version, phase, kind, config, cert_serial, enrolled_at, org_id) "
                "VALUES (%s,%s,%s,%s,%s,%s,'baseline',%s,%s,%s,now(),%s)",
             (eid, req.hostname[:128] if fleet else tok["name"], req.hostname, req.os, req.arch, req.agent_version, kind, json.dumps(cfg), serial, tok["org_id"]))
        if not fleet:
            db.q(c, "UPDATE enroll_tokens SET used_by=%s WHERE token=%s", (eid, req.token))
    db.init_telemetry(eid)
    return {"ok": True, "endpoint_id": eid, "cert_pem": cert, "ca_pem": pki.ca_pem(), "bundle_signing_pub": pki.signing_public_pem(), "config": cfg}


async def ndjson_rows(request: Request):
    body = await request.body()
    if request.headers.get("content-encoding") == "gzip":
        body = gzip.decompress(body)
    for line in body.decode().splitlines():
        if line.strip():
            yield json.loads(line)


@app.post("/v1/endpoints/{endpoint_id}/entities")
async def upload_entities(endpoint_id: str, request: Request, ep=Depends(agent_endpoint)):
    rows = [r async for r in ndjson_rows(request)]
    s = db.tschema(endpoint_id)
    with db.conn(db.TELEMETRY_DSN) as c:
        with c.cursor() as cur:
            # dense_id: the agent's own registry index (0.2 agents); older agents get the upload order from the sequence.
            # The worker builds the endpoint registry in dense_id order, so ids match the agent's exactly.
            psycopg2.extras.execute_values(
                cur, f"INSERT INTO {s}.entities (uuid, dense_id, ntype, label, display) VALUES %s ON CONFLICT (uuid) DO NOTHING",
                [(r["uuid"], r.get("dense_id"), r["ntype"], r["label"], json.dumps(r.get("display", {}))) for r in rows],
                template=f"(%s, COALESCE(%s, nextval('{s}.dense_seq')), %s, %s, %s)", page_size=5000)
    return {"ok": True, "rows": len(rows)}


@app.post("/v1/endpoints/{endpoint_id}/events")
async def upload_events(endpoint_id: str, request: Request, ep=Depends(agent_endpoint), x_batch_id: str = Header(...)):
    with db.conn() as c:
        if db.q(c, "SELECT 1 FROM upload_batches WHERE endpoint_id=%s AND batch_id=%s", (endpoint_id, x_batch_id), one=True):
            return {"ok": True, "batch_id": x_batch_id, "duplicate": True}
    rows = [r async for r in ndjson_rows(request)]
    s = db.tschema(endpoint_id)
    with db.conn(db.TELEMETRY_DSN) as c:
        if rows:
            db.ensure_partitions(c, s, min(r["ts_ns"] for r in rows), max(r["ts_ns"] for r in rows))
        with c.cursor() as cur:
            psycopg2.extras.execute_values(   # batched multi-row INSERTs (row-by-row executemany was the upload bottleneck)
                cur, f"INSERT INTO {s}.events (ts_ns, src, op, dst, event_uuid, batch_id) VALUES %s",
                [(r["ts_ns"], r["src"], r["op"], r["dst"], r["event_uuid"], x_batch_id) for r in rows], page_size=10000)
    with db.conn() as c:
        db.q(c, "INSERT INTO upload_batches (endpoint_id, batch_id, kind, rows, bytes) VALUES (%s,%s,'events',%s,%s) ON CONFLICT DO NOTHING",
             (endpoint_id, x_batch_id, len(rows), int(request.headers.get("content-length") or 0) or None))
    return {"ok": True, "batch_id": x_batch_id}


class DayComplete(BaseModel):
    date: str


@app.post("/v1/endpoints/{endpoint_id}/day-complete")
def day_complete(endpoint_id: str, req: DayComplete, ep=Depends(agent_endpoint)):
    with db.conn() as c:
        db.q(c, "INSERT INTO baseline_days (endpoint_id, date, complete, completed_at) VALUES (%s,%s,true,now()) ON CONFLICT (endpoint_id, date) DO UPDATE SET complete=true, completed_at=COALESCE(baseline_days.completed_at, now())", (endpoint_id, req.date))
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, params) VALUES (%s,%s,'ingest',%s)", (pki.new_id(), endpoint_id, json.dumps({"date": req.date})))
    return {"ok": True}


@app.get("/v1/endpoints/{endpoint_id}/status")
def status(endpoint_id: str, ep=Depends(agent_endpoint)):
    with db.conn() as c:
        b = db.q(c, "SELECT id, sha256 FROM bundles WHERE id=%s", (ep["current_bundle"],), one=True) if ep["current_bundle"] else None
        cmds = db.q(c, "SELECT id, params FROM jobs WHERE endpoint_id=%s AND kind='command' AND state='queued' ORDER BY created_at", (endpoint_id,))
        from .allowlist import effective_config
        cfg = effective_config(c, endpoint_id, ep["config"])
        from .updates import update_for
        upd = update_for(c, ep)
    return {"ok": True, "phase": ep["phase"], "baseline_days_done": ep["baseline_days_done"], "config": cfg,
            "bundle": {"id": str(b["id"]), "sha256": b["sha256"]} if b else None,
            "commands": [{**r["params"], "id": str(r["id"])} for r in cmds], "update": upd}


@app.post("/v1/endpoints/{endpoint_id}/pull-token")
def agent_pull_token(endpoint_id: str, ep=Depends(agent_endpoint)):
    """A 15-minute registry credential for the update this endpoint is being offered."""
    from .updates import pull_token, update_for
    with db.conn() as c:
        upd = update_for(c, ep)
        if not upd:
            raise HTTPException(409, "no update for this endpoint")
        return {"ok": True, "user": "pdp", "token": pull_token(c, endpoint_id), **upd}


class CommandAck(BaseModel):
    result: str = "ok"


@app.get("/v1/endpoints/{endpoint_id}/btf/{release}")
def kernel_btf(endpoint_id: str, release: str, ep=Depends(agent_endpoint)):
    """BTF for an endpoint whose kernel has none (/sys/kernel/btf/vmlinux missing); see distrib.find_btf."""
    from .distrib import RELEASE_RE, find_btf
    if not RELEASE_RE.match(release):
        raise HTTPException(400, "bad kernel release")
    f = find_btf(release, ep.get("arch") or "x86_64")
    if not f:
        raise HTTPException(404, f"no BTF for kernel {release} on this server")
    return FileResponse(f, media_type="application/octet-stream")


@app.post("/v1/endpoints/{endpoint_id}/commands/{command_id}/ack")
def ack_command(endpoint_id: str, command_id: str, req: CommandAck, ep=Depends(agent_endpoint)):
    with db.conn() as c:
        db.q(c, "UPDATE jobs SET state=%s, result=%s, finished_at=now() WHERE id=%s AND endpoint_id=%s AND kind='command'",
             ("done" if req.result == "ok" or req.result.startswith("ok:") else "failed", req.result[:500], command_id, endpoint_id))
    return {"ok": True}


@app.get("/v1/endpoints/{endpoint_id}/bundle")
def get_bundle(endpoint_id: str, slim: bool = False, ep=Depends(agent_endpoint)):
    if not ep["current_bundle"]:
        raise HTTPException(404, "no bundle")
    with db.conn() as c:
        b = db.q(c, "SELECT path FROM bundles WHERE id=%s", (ep["current_bundle"],), one=True)
    from fastapi.responses import FileResponse
    from .bundles import archive
    # the archive is built once (normally by the worker when the model is published) and streamed from disk: a model
    # of a busy host is over 1 GB and compressing it per request outlasted the agent's read timeout
    return FileResponse(archive(b["path"], slim=slim), media_type="application/gzip", headers={"X-Bundle-Id": str(ep["current_bundle"])})


@app.post("/v1/endpoints/{endpoint_id}/windows")
async def upload_windows(endpoint_id: str, request: Request, ep=Depends(agent_endpoint)):
    rows = [r async for r in ndjson_rows(request)]
    with db.conn() as c:
        with c.cursor() as cur:
            cur.executemany("INSERT INTO windows (endpoint_id, start_ns, end_ns, edges, nodes, alerts, max_fused, max_r1, max_r2, bundle_id) "
                            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (endpoint_id, start_ns) DO UPDATE SET alerts=EXCLUDED.alerts, max_fused=EXCLUDED.max_fused",
                            [(endpoint_id, r["start_ns"], r["end_ns"], r["edges"], r["nodes"], r["alerts"], r["max_fused"], r["max_r1"], r["max_r2"], ep["current_bundle"]) for r in rows])
    return {"ok": True, "rows": len(rows)}


@app.post("/v1/endpoints/{endpoint_id}/alerts")
async def upload_alerts(endpoint_id: str, request: Request, ep=Depends(agent_endpoint)):
    rows = [r async for r in ndjson_rows(request)]
    with db.conn() as c:
        with c.cursor() as cur:
            cur.executemany("INSERT INTO alerts (endpoint_id, window_start_ns, node_uuid, ntype, label, display, fused, r1, r2, context, layer, rule, reason, reasons) "
                            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            [(endpoint_id, r["window_start_ns"], r["node"]["uuid"], r["node"]["ntype"], r["node"]["label"], json.dumps(r["node"].get("display", {})),
                              r["fused"], r["r1"], r["r2"], json.dumps(r.get("context", {})), r.get("layer", "learned"), r.get("rule"), r.get("reason"),
                              json.dumps(r.get("reasons", []))) for r in rows])
        from .allowlist import mark_new_alerts
        new = [x["id"] for x in db.q(c, "SELECT id FROM alerts WHERE endpoint_id=%s AND created_at = now()", (endpoint_id,))]
        mark_new_alerts(c, endpoint_id, new)
    return {"ok": True, "rows": len(rows)}


class Heartbeat(BaseModel):
    agent_version: str = ""
    queue_depth: int = 0
    last_window_end_ns: int = 0
    cpu_pct: float = 0
    rss_mb: float = 0
    collector_lost: int | None = None     # events the kernel dropped (ring buffer full) since the agent started
    spool_mb: float | None = None         # local event spool on disk (0.3.4+)
    spool_dropped_unscored: int | None = None     # events dropped by the spool size cap before local scoring
    spool_dropped_unuploaded: int | None = None   # ... before upload (lost for the baseline)
    entities: int | None = None           # entities held in the agent's registry (0.3.5+, after compaction)
    isolated: bool | None = None          # network isolation in force (response action, 0.3.15+)
    disk_free_mb: float | None = None     # free space of the agent's data file system (0.3.8+)
    disk_free_pct: float | None = None
    update: dict | None = None            # {"state": none|offered|updating|trial|failed, "version", "failed": [...]} (0.3.8+)
    collector_error: str | None = Field(default=None, max_length=1000)   # the collector could not start (0.3.18+)
    collector_behind: int | None = None   # records the loader dropped because the agent fell behind (0.3.19+)
    collector_lost_1h: int | None = None  # ... the same two over the last hour (0.3.19+)
    collector_behind_1h: int | None = None
    disk_full: bool | None = None         # the data disk is full now (0.3.20+)
    disk_full_dropped: int | None = None  # events that could not be stored because of it, since the agent started
    data_mb: dict | None = None           # the agent's disk use by kind (0.3.20+): spool, index, models, logs, images


@app.post("/v1/endpoints/{endpoint_id}/heartbeat")
def heartbeat(endpoint_id: str, hb: Heartbeat, ep=Depends(agent_endpoint)):
    with db.conn() as c:
        db.q(c, "UPDATE endpoints SET agent_version_since = CASE WHEN agent_version IS DISTINCT FROM %s OR agent_version_since IS NULL "
                "THEN now() ELSE agent_version_since END, agent_version=%s, health=%s WHERE id=%s",
             (hb.agent_version, hb.agent_version, json.dumps({**hb.dict(), "at": time.time()}), endpoint_id))
    return {"ok": True}


@app.get("/healthz")
def healthz():
    """Liveness + database reachability (for the gateway, compose healthchecks and monitoring)."""
    try:
        with db.conn() as c:
            db.q(c, "SELECT 1")
        with db.conn(db.TELEMETRY_DSN) as c:
            db.q(c, "SELECT 1")
            queued = None
        with db.conn() as c:
            queued = db.q(c, "SELECT count(*) AS n FROM jobs WHERE state='queued' AND kind<>'command'", one=True)["n"]
    except Exception as e:  # noqa
        return JSONResponse({"ok": False, "error": str(e)[:200]}, status_code=503)
    return {"ok": True, "queued_jobs": queued}


# ============================================================================ console side
class Login(BaseModel):
    username: str
    password: str


def _set_session(response: Response, user_id: int, role: str) -> None:
    set_session(response, user_id, role)


@app.get("/api/auth/config")
def auth_config():
    """Public: which sign-in methods the login page offers."""
    from .orgs import signup_mode
    with db.conn() as c:
        org_sso = bool(db.q(c, "SELECT 1 FROM orgs WHERE sso IS NOT NULL AND (sso->>'enabled')::boolean AND NOT disabled LIMIT 1", one=True))
    return {"ok": True, "sso": oidc.enabled(), "sso_label": oidc.LABEL, "password": oidc.PASSWORD_LOGIN != "disabled", "org_sso": org_sso,
            "password_policy": oidc.PASSWORD_LOGIN, "signup": signup_mode()}


@app.post("/api/login")
def login(req: Login, response: Response, request: Request):
    # every HTTPException is raised after its transaction committed (db.conn() rolls back on exceptions)
    failure = None
    with db.conn() as c:
        ident = (req.username or "").strip()
        u = db.q(c, "SELECT u.*, o.disabled AS org_disabled FROM users u JOIN orgs o ON o.id=u.org_id WHERE u.username=%s", (ident,), one=True) or \
            db.q(c, "SELECT u.*, o.disabled AS org_disabled FROM users u JOIN orgs o ON o.id=u.org_id "
                    "WHERE u.auth='local' AND lower(u.email)=lower(%s)", (ident,), one=True)
        if u and u.get("locked_until") and u["locked_until"] > datetime.now(timezone.utc):
            failure = (429, "too many failed sign-ins; try again later")
        elif not u or u["auth"] != "local" or u["disabled"] or not auth.verify_password(req.password, u["password_hash"]):
            if u:   # back off: 5 failures free, then 30 s, 60 s, ... up to 15 min (reset by a successful sign-in)
                db.q(c, "UPDATE users SET failed_logins = failed_logins + 1, locked_until = CASE WHEN failed_logins + 1 >= 5 "
                        "THEN now() + make_interval(secs => LEAST(900, 30 * power(2, failed_logins + 1 - 5))) END WHERE id=%s", (u["id"],))
            failure = (401, "bad credentials")
        elif u["org_disabled"]:
            failure = (403, "your organisation's access to PDP is suspended; contact your provider")
        elif not oidc.password_login_allowed(u["role"]):
            failure = (403, "password sign-in is disabled; use single sign-on")
        else:
            db.q(c, "UPDATE users SET failed_logins=0, locked_until=NULL, last_login=now() WHERE id=%s", (u["id"],))
    from .audit import record, _client_ip
    record(u["org_id"] if u else None, u["id"] if u else None, ident, "sign-in" if not failure else f"sign-in refused: {failure[1]}",
           None, failure[0] if failure else 200, _client_ip(request))
    if failure:
        if failure[0] == 401:
            time.sleep(0.5)
        raise HTTPException(*failure)
    if u.get("totp_enabled"):        # second step: POST /api/login/mfa with a code
        from .mfa import pending_cookie
        response.set_cookie("pdp_mfa", pending_cookie(u["id"]), httponly=True, secure=True, samesite="strict", max_age=300, path="/api/login")
        return {"ok": True, "mfa_required": True}
    _set_session(response, u["id"], u["role"])
    return {"ok": True, "role": u["role"], "username": u["username"]}


def _console_base(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{proto}://{request.headers.get('host', request.url.netloc)}"


@app.get("/api/oidc/login")
def oidc_login(request: Request):
    from fastapi.responses import RedirectResponse
    if not oidc.enabled():
        raise HTTPException(404, "single sign-on is not configured")
    redirect = oidc.REDIRECT_URL or _console_base(request) + "/api/oidc/callback"
    try:
        url, state = oidc.start(redirect)
    except oidc.OIDCError as e:
        return _sso_error(str(e))
    r = RedirectResponse(url, status_code=302)
    # Lax, not Strict: the IdP's redirect back to the callback is a cross-site navigation
    r.set_cookie("pdp_oidc", state, httponly=True, secure=True, samesite="lax", max_age=oidc.STATE_TTL, path="/api/oidc")
    return r


def _sso_error(msg: str):
    from fastapi.responses import RedirectResponse
    import urllib.parse as _u
    r = RedirectResponse("/#/login?sso_error=" + _u.quote(msg[:300]), status_code=302)
    r.delete_cookie("pdp_oidc", path="/api/oidc")
    return r


@app.get("/api/oidc/callback")
def oidc_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None,
                  error_description: str | None = None):
    from fastapi.responses import RedirectResponse
    if not oidc.enabled():
        raise HTTPException(404, "single sign-on is not configured")
    if error:
        return _sso_error(f"the identity provider refused the sign-in: {error_description or error}")
    try:
        ident = oidc.finish(code or "", state or "", request.cookies.get("pdp_oidc"))
    except oidc.OIDCError as e:
        return _sso_error(str(e))
    if not ident["role"]:
        with db.conn() as c:   # lost access at the IdP: also end any session the account still has
            db.q(c, "UPDATE users SET disabled=true WHERE oidc_issuer=%s AND oidc_sub=%s", (ident["iss"], ident["sub"]))
        return _sso_error(f"{ident['username']} is not in a group that has access to PDP")
    with db.conn() as c:
        u = db.q(c, "SELECT id FROM users WHERE oidc_issuer=%s AND oidc_sub=%s", (ident["iss"], ident["sub"]), one=True)
        if u:
            db.q(c, "UPDATE users SET role=%s, email=%s, disabled=false, last_login=now() WHERE id=%s", (ident["role"], ident["email"], u["id"]))
            uid = u["id"]
        else:
            clash = db.q(c, "SELECT auth FROM users WHERE username=%s", (ident["username"],), one=True)
            if clash:   # never bind an IdP identity to an existing local account (or another IdP subject)
                return _sso_error(f"the username {ident['username']} is already used by another PDP account; an admin must rename or delete it")
            from .orgs import internal_org
            uid = db.q(c, "INSERT INTO users (username, password_hash, role, auth, oidc_issuer, oidc_sub, email, last_login, org_id) "
                          "VALUES (%s,'!',%s,'oidc',%s,%s,%s,now(),%s) RETURNING id",
                       (ident["username"], ident["role"], ident["iss"], ident["sub"], ident["email"], internal_org(c)), one=True)["id"]
    r = RedirectResponse("/#/endpoints", status_code=302)
    _set_session(r, uid, ident["role"])
    r.delete_cookie("pdp_oidc", path="/api/oidc")
    return r


@app.post("/api/logout")
def logout(request: Request, response: Response):
    s = auth.read_session(request.cookies.get("pdp_session"))
    response.delete_cookie("pdp_session", path="/")
    end = None
    if s and oidc.enabled():
        with db.conn() as c:
            u = db.q(c, "SELECT auth FROM users WHERE id=%s", (s["u"],), one=True)
        if u and u["auth"] == "oidc":
            end = oidc.end_session_url(_console_base(request) + "/")
    return {"ok": True, "end_session_url": end}


@app.get("/api/me")
def me(s=Depends(session)):
    from .orgs import me_body
    with db.conn() as c:
        return me_body(c, s["u"])


class PasswordChange(BaseModel):
    old_password: str
    new_password: str


@app.post("/api/me/password")
def change_password(req: PasswordChange, response: Response, s=Depends(session)):
    """Ends the user's other sessions (every browser signed in before); this one continues with a new cookie."""
    if s["a"] != "local":
        raise HTTPException(400, "this account signs in with single sign-on; its password is managed by the identity provider")
    if len(req.new_password) < 10:
        raise HTTPException(400, "the new password must have at least 10 characters")
    with db.conn() as c:
        u = db.q(c, "SELECT password_hash FROM users WHERE id=%s", (s["u"],), one=True)
        if not u or not auth.verify_password(req.old_password, u["password_hash"]):
            raise HTTPException(400, "current password is wrong")
        db.q(c, "UPDATE users SET password_hash=%s WHERE id=%s", (auth.hash_password(req.new_password), s["u"]))
        end_sessions(c, s["u"])
    _set_session(response, s["u"], s["r"])
    return {"ok": True}


@app.post("/api/me/sessions/end")
def end_other_sessions(response: Response, s=Depends(session)):
    """Sign out everywhere else: ends every other session of this user (a lost laptop, a shared computer)."""
    with db.conn() as c:
        end_sessions(c, s["u"])
    _set_session(response, s["u"], s["r"])
    return {"ok": True}


def _user_out(r: dict, names: dict) -> dict:
    eps = None if r["role"] == "admin" or r["endpoints"] is None else [{"id": str(e), "name": names.get(str(e), "(removed endpoint)")} for e in r["endpoints"]]
    return {"id": r["id"], "username": r["username"], "display_name": r["display_name"] or r["username"], "email": r["email"],
            "role": r["role"], "auth": r["auth"], "endpoints": eps, "disabled": r["disabled"],
            "created_at": r["created_at"], "last_login": r["last_login"]}


@app.get("/api/users")
def list_users(s=Depends(admin)):
    with db.conn() as c:
        rows = db.q(c, "SELECT id, username, display_name, role, auth, email, endpoints, disabled, created_at, last_login FROM users "
                       "WHERE org_id=%s ORDER BY lower(coalesce(display_name, username))", (s["org"],))
        names = {str(r["id"]): r["name"] for r in db.q(c, "SELECT id, name FROM endpoints WHERE org_id=%s", (s["org"],))}
    from .access import ROLE_TEXT
    return {"ok": True, "users": [_user_out(r, names) for r in rows],
            "roles": [{"id": k, "text": v} for k, v in ROLE_TEXT.items()],
            "sso": {"enabled": oidc.enabled(), "label": oidc.LABEL, "password_policy": oidc.PASSWORD_LOGIN}}


def _check_endpoint_ids(c, ids, s: dict) -> list[str] | None:
    """Validate a list of endpoint ids against the caller's scope (their organisation); None = all endpoints."""
    if ids is None:
        return None
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids) or len(ids) > 10000:
        raise HTTPException(400, "endpoints must be null (all endpoints) or a list of endpoint ids")
    try:
        ids = sorted({str(uuidlib.UUID(x)) for x in ids})
    except ValueError:
        raise HTTPException(400, "endpoints: not an endpoint id") from None
    known = set(ids) & set(s["scope"] or ())
    if set(ids) - known:
        raise HTTPException(400, f"unknown endpoints: {sorted(set(ids) - known)}")
    return ids


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    display_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=254)
    endpoints: list[str] | None = None


@app.post("/api/users")
def create_user(req: NewUser, s=Depends(admin)):
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9_.@-]{2,64}", req.username):
        raise HTTPException(400, "username: 2-64 characters of letters, digits and _ . @ -")
    if req.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "role must be admin, analyst or viewer")
    if len(req.password) < 10:
        raise HTTPException(400, "password must have at least 10 characters")
    with db.conn() as c:
        eps = _check_endpoint_ids(c, req.endpoints, s)
        email = (req.email or "").strip().lower() or None
        if email and db.q(c, "SELECT 1 FROM users WHERE lower(email)=%s OR lower(username)=%s", (email, email), one=True):
            raise HTTPException(409, "a user with this email exists")
        row = db.q(c, "INSERT INTO users (username, password_hash, role, display_name, email, endpoints, org_id) VALUES (%s,%s,%s,%s,%s,%s,%s) "
                      "ON CONFLICT (username) DO NOTHING RETURNING id",
                   (req.username, auth.hash_password(req.password), req.role, (req.display_name or "").strip() or None,
                    email, json.dumps(eps) if eps is not None else None, s["org"]), one=True)
    if not row:
        raise HTTPException(409, "a user with this username exists")
    return {"ok": True, "id": row["id"]}


_UNSET = object()


@app.patch("/api/users/{user_id}")
def update_user(user_id: int, body: dict, s=Depends(admin)):
    allowed = {"role", "display_name", "email", "endpoints", "disabled", "password"}
    if set(body) - allowed:
        raise HTTPException(400, f"unknown fields: {sorted(set(body) - allowed)}")
    with db.conn() as c:
        u = db.q(c, "SELECT * FROM users WHERE id=%s AND org_id=%s", (user_id, s["org"]), one=True)
        if not u:
            raise HTTPException(404, "user not found")
        sets, params = [], []
        if "role" in body:
            if body["role"] not in ("admin", "analyst", "viewer"):
                raise HTTPException(400, "role must be admin, analyst or viewer")
            if u["auth"] == "oidc" and body["role"] != u["role"]:
                raise HTTPException(400, "this account signs in with single sign-on: its role comes from the identity provider's groups")
            sets.append("role=%s"); params.append(body["role"])
        if "display_name" in body:
            sets.append("display_name=%s"); params.append((str(body["display_name"] or "")[:128]).strip() or None)
        if "email" in body:
            em = (str(body["email"] or "")[:254]).strip().lower() or None
            if em and db.q(c, "SELECT 1 FROM users WHERE (lower(email)=%s OR lower(username)=%s) AND id<>%s", (em, em, user_id), one=True):
                raise HTTPException(409, "a user with this email exists")
            sets.append("email=%s"); params.append(em)
        if "endpoints" in body:
            eps = _check_endpoint_ids(c, body["endpoints"], s)
            sets.append("endpoints=%s"); params.append(json.dumps(eps) if eps is not None else None)
        if "disabled" in body:
            if not isinstance(body["disabled"], bool):
                raise HTTPException(400, "disabled must be true or false")
            sets.append("disabled=%s"); params.append(body["disabled"])
        if "password" in body:
            if u["auth"] != "local":
                raise HTTPException(400, "this account signs in with single sign-on and has no PDP password")
            if not isinstance(body["password"], str) or len(body["password"]) < 10:
                raise HTTPException(400, "password must have at least 10 characters")
            sets.append("password_hash=%s"); params.append(auth.hash_password(body["password"]))
            sets.append("failed_logins=0"); sets.append("locked_until=NULL")
            sets.append("session_gen = session_gen + 1")         # the user's open sessions end with the old password
        demote = body.get("role", u["role"]) != "admin" or body.get("disabled", u["disabled"])
        if u["role"] == "admin" and not u["disabled"] and demote:
            if user_id == s["u"]:
                raise HTTPException(400, "you cannot remove your own admin access")
            if _enabled_admins(c, s["org"]) <= 1:
                raise HTTPException(400, "this is the last enabled admin")
        if sets:
            db.q(c, f"UPDATE users SET {', '.join(sets)} WHERE id=%s", (*params, user_id))
    return {"ok": True}


def _enabled_admins(c, org_id: str) -> int:
    return db.q(c, "SELECT count(*) AS n FROM users WHERE role='admin' AND NOT disabled AND org_id=%s", (org_id,), one=True)["n"]


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, s=Depends(admin)):
    if user_id == s["u"]:
        raise HTTPException(400, "you cannot delete yourself")
    with db.conn() as c:
        u = db.q(c, "SELECT role, disabled FROM users WHERE id=%s AND org_id=%s", (user_id, s["org"]), one=True)
        if not u:
            raise HTTPException(404, "user not found")
        if u["role"] == "admin" and not u["disabled"] and _enabled_admins(c, s["org"]) <= 1:
            raise HTTPException(400, "this is the last enabled admin")
        db.q(c, "UPDATE enroll_tokens SET created_by=NULL WHERE created_by=%s", (user_id,))
        db.q(c, "UPDATE invites SET created_by=NULL WHERE created_by=%s", (user_id,))
        db.q(c, "UPDATE invites SET used_by=NULL WHERE used_by=%s", (user_id,))
        db.q(c, "DELETE FROM users WHERE id=%s", (user_id,))
    return {"ok": True}


@app.get("/api/endpoints")
def list_endpoints(s=Depends(session)):
    from .console import endpoint_rows
    return {"ok": True, "endpoints": endpoint_rows(s)}


def _ep_out(r: dict) -> dict:
    from .console import endpoint_state
    return dict(r, id=str(r["id"]), current_bundle=str(r["current_bundle"]) if r["current_bundle"] else None, health=r.get("health"),
                **endpoint_state(r))


class NewEndpoint(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: str = "live"
    dataset: str | None = None   # benchmark endpoints replay a dataset
    config: dict = {}             # initial endpoint configuration (same keys as POST /api/endpoints/{id}/config)


@app.post("/api/endpoints")
def create_endpoint(req: NewEndpoint, request: Request, s=Depends(admin)):
    if req.kind not in ("live", "benchmark", "simulation"):
        raise HTTPException(400, "kind must be live, benchmark or simulation")
    if req.kind != "live" and not s["op"]:
        raise HTTPException(403, "only the platform operator can create benchmark or simulation endpoints")
    bad = set(req.config) - CONFIG_KEYS
    if bad:
        raise HTTPException(400, f"unknown config keys: {sorted(bad)}")
    _validate_config(req.config)
    token = secrets.token_urlsafe(24)
    from .orgs import check_endpoint_limit
    with db.conn() as c:
        check_endpoint_limit(c, s["org"])
        db.q(c, "INSERT INTO enroll_tokens (token, name, created_by, expires_at, kind, dataset, config, org_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
             (token, req.name, s["u"], datetime.now(timezone.utc) + timedelta(hours=24), req.kind, req.dataset, json.dumps(req.config), s["org"]))
    fp = pki.ca_sha256()
    from .distrib import agent_image, public_host
    host = public_host(request)
    server = f"https://{host}" + ("" if os.environ.get("PDP_CONSOLE_PORT", "443") == "443" else f":{os.environ['PDP_CONSOLE_PORT']}")
    agent = f"https://{host}:{os.environ.get('PDP_AGENT_PORT', '8443')}"
    image = agent_image(host) or os.environ.get("PDP_AGENT_IMAGE", "pdp/agent:latest")
    login = f"echo {token} | docker login {host} -u pdp --password-stdin && \\\n" if agent_image(host) else ""
    docker = (login + f"docker run -d --name pdp-agent --restart=always --privileged --pid=host --network=host --log-driver local \\\n"
              f"  -v /var/lib/pdp:/var/lib/pdp -e PDP_ENROLL_TOKEN={token} -e PDP_CA_SHA256={fp} -e PDP_SOURCE_KIND=ebpf \\\n"
              f"  -e PDP_SERVER_URL={agent} -e PDP_AGENT_URL={agent} {image} run")
    from .k8s import key_of
    return {"ok": True, "token": token, "expires_in_hours": 24, "ca_sha256": fp, "server_url": server, "agent_url": agent,
            "progress_key": key_of(token),
            "install_command": f"curl -fsSL {server}/install.sh | sudo bash -s -- --token {token}",
            "package_command": f"sudo pdp-agent-install --server {agent} --agent-url {agent} --token {token} --ca-sha256 {fp}",
            "docker_command": docker,
            "enroll_command": f"python -m pdp_agent enroll {token} --ca-sha256 {fp}"}


@app.get("/api/endpoints/{endpoint_id}")
def endpoint_detail(endpoint_id: str, s=Depends(session)):
    require_endpoint(s, endpoint_id)
    with db.conn() as c:
        ep = db.q(c, "SELECT * FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
        if not ep:
            raise HTTPException(404)
        jobs = db.q(c, "SELECT id, kind, state, params, progress, error, created_at, finished_at FROM jobs WHERE endpoint_id=%s ORDER BY created_at DESC LIMIT 20", (endpoint_id,))
        days = db.q(c, "SELECT date, events, windows, complete FROM baseline_days WHERE endpoint_id=%s ORDER BY date", (endpoint_id,))
    from .allowlist import effective_config
    with db.conn() as c:
        ep = dict(ep, config=effective_config(c, endpoint_id, ep["config"]))
    return {"ok": True, "endpoint": _ep_out(ep),
            "jobs": [dict(j, id=str(j["id"])) for j in jobs], "baseline_days": [dict(d, date=str(d["date"])) for d in days],
            "timeline": endpoint_timeline(endpoint_id)}


class ConfigPatch(BaseModel):
    config: dict


@app.post("/api/endpoints/{endpoint_id}/config")
def patch_config(endpoint_id: str, req: ConfigPatch, s=Depends(admin)):
    """Merge keys into the endpoint configuration (baseline_days, tz, retain_baseline_events, train.*); the agent
    follows the server's configuration on its next status poll."""
    require_endpoint(s, endpoint_id)
    bad = set(req.config) - CONFIG_KEYS
    if bad:
        raise HTTPException(400, f"unknown config keys: {sorted(bad)}")
    _validate_config(req.config)
    with db.conn() as c:
        row = db.q(c, "UPDATE endpoints SET config = config || %s WHERE id=%s RETURNING config, phase, baseline_days_done", (json.dumps(req.config), endpoint_id), one=True)
        if not row:
            raise HTTPException(404)
        # a shorter baseline may already be complete: start training now instead of waiting for a day that is not needed
        need = int(row["config"].get("baseline_days", 7)) + 1
        if "baseline_days" in req.config and row["phase"] == "baseline" and row["baseline_days_done"] >= need and \
                not db.q(c, "SELECT 1 FROM jobs WHERE endpoint_id=%s AND kind='train' AND state IN ('queued','running')", (endpoint_id,), one=True):
            db.q(c, "INSERT INTO jobs (id, endpoint_id, kind) VALUES (%s,%s,'train')", (pki.new_id(), endpoint_id))
            db.q(c, "UPDATE endpoints SET phase='training' WHERE id=%s", (endpoint_id,))
    return {"ok": True, "config": row["config"]}


class ApprovalReq(BaseModel):
    executables: list[str]
    approve: bool = True


@app.post("/api/endpoints/{endpoint_id}/approved-executables")
def approve_executables(endpoint_id: str, req: ApprovalReq, s=Depends(admin)):
    """Layer-1 approvals (kept for older consoles and scripts): program entries of the allow list for this endpoint.
    Approving resolves the endpoint's open 'new program' alerts for these programs."""
    require_endpoint(s, endpoint_id)
    from .allowlist import entries_for, mark_alerts
    items = [x.strip() for x in req.executables if x and x.strip()]
    _validate_config({"approved_executables": items})
    with db.conn() as c:
        if not db.q(c, "SELECT 1 FROM endpoints WHERE id=%s", (endpoint_id,), one=True):
            raise HTTPException(404)
        mine = [e for e in entries_for(c, endpoint_id) if e["kind"] == "program" and e["endpoint_ids"] == [endpoint_id]]
        for prog in items:
            have = [e for e in mine if e["value"] == prog]
            if req.approve and not have:
                row = db.q(c, "INSERT INTO allowlist (kind, value, endpoint_ids, created_by, org_id) VALUES ('program', %s, %s, %s, %s) RETURNING *",
                           (prog, json.dumps([endpoint_id]), s["u"], s["org"]), one=True)
                mark_alerts(c, row)
            elif not req.approve:
                for e in have:
                    db.q(c, "DELETE FROM allowlist WHERE id=%s", (e["id"],))
                    db.q(c, "UPDATE alerts SET allowed_by=NULL WHERE allowed_by=%s", (e["id"],))
        ep = db.q(c, "SELECT config FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
        from .allowlist import effective_config
        approved = effective_config(c, endpoint_id, ep["config"])["approved_executables"]
    return {"ok": True, "approved_executables": approved}


def _validate_config(cfg: dict) -> None:
    if "approved_executables" in cfg:
        v = cfg["approved_executables"]
        if not (isinstance(v, list) and all(isinstance(x, str) and 0 < len(x) <= 4096 for x in v) and len(v) <= 20000):
            raise HTTPException(400, "approved_executables must be a list of program paths / names")
    if "learned_alerts" in cfg and not isinstance(cfg["learned_alerts"], bool):
        raise HTTPException(400, "learned_alerts must be true or false")
    if "learned_daily_budget" in cfg and not (isinstance(cfg["learned_daily_budget"], int) and 0 <= cfg["learned_daily_budget"] <= 100000):
        raise HTTPException(400, "learned_daily_budget must be an integer between 0 and 100000")
    if "fp_budget" in cfg and cfg["fp_budget"] not in FP_BUDGETS:
        raise HTTPException(400, f"fp_budget must be one of {list(FP_BUDGETS)}")
    if "baseline_days" in cfg and not (isinstance(cfg["baseline_days"], int) and 1 <= cfg["baseline_days"] <= 60):
        raise HTTPException(400, "baseline_days must be an integer between 1 and 60")
    if "window_minutes" in cfg and not (isinstance(cfg["window_minutes"], (int, float)) and 1 <= cfg["window_minutes"] <= 240):
        raise HTTPException(400, "window_minutes must be between 1 and 240 (takes effect for days ingested after the change)")
    if "tz" in cfg:
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo(cfg["tz"])
        except Exception:  # noqa
            raise HTTPException(400, f"unknown timezone {cfg['tz']!r}")
    if "train" in cfg:
        import dataclasses
        sys_path_engine()
        from pdp_engine.trainer import TrainConfig
        known = {f.name for f in dataclasses.fields(TrainConfig)} | {"fusion_calibration"}
        if not isinstance(cfg["train"], dict) or set(cfg["train"]) - known:
            raise HTTPException(400, f"train: unknown keys {sorted(set(cfg['train']) - known) if isinstance(cfg['train'], dict) else cfg['train']}")
        if cfg["train"].get("fusion_calibration", "fixed") not in ("fixed", "simulation"):
            raise HTTPException(400, "train.fusion_calibration must be 'fixed' or 'simulation'")


def sys_path_engine():
    import sys
    p = os.environ.get("PDP_ENGINE_PATH", "/opt/pdp/engine")
    if p not in sys.path:
        sys.path.insert(0, p)


@app.post("/api/endpoints/{endpoint_id}/retire")
def retire_endpoint(endpoint_id: str, s=Depends(admin)):
    """Permanently retire an endpoint: its certificate is no longer accepted and its raw telemetry is dropped.
    Alerts, windows and bundles are kept for the record."""
    require_endpoint(s, endpoint_id)
    with db.conn() as c:
        row = db.q(c, "UPDATE endpoints SET phase='retired' WHERE id=%s RETURNING id", (endpoint_id,), one=True)
        if not row:
            raise HTTPException(404)
        db.q(c, "UPDATE jobs SET state='cancelled', finished_at=now() WHERE endpoint_id=%s AND state='queued'", (endpoint_id,))
        from .allowlist import forget_endpoint
        forget_endpoint(c, endpoint_id)
    db.drop_telemetry(endpoint_id)
    return {"ok": True}


@app.delete("/api/endpoints/{endpoint_id}")
def delete_endpoint(endpoint_id: str, s=Depends(admin)):
    """Remove an endpoint for good: the endpoint, its alerts, incidents, models, activity data and checks are
    deleted, its agent's certificate stops working, and it no longer counts against the endpoint limit. (Retire
    keeps the alerts and incidents for the record.) The agent on the host keeps running until it is uninstalled."""
    import shutil
    require_endpoint(s, endpoint_id)
    with db.conn() as c:
        ep = db.q(c, "SELECT id, name FROM endpoints WHERE id=%s AND org_id=%s", (endpoint_id, s["org"]), one=True)
        if not ep:
            raise HTTPException(404, "not found")
        from .allowlist import forget_endpoint
        forget_endpoint(c, endpoint_id)
        db.q(c, "DELETE FROM sim_campaigns WHERE endpoint_id=%s", (endpoint_id,))
        db.q(c, "UPDATE users SET endpoints = endpoints - %s WHERE endpoints ? %s", (endpoint_id, endpoint_id))
        db.q(c, "DELETE FROM endpoints WHERE id=%s", (endpoint_id,))       # cascades: jobs, bundles, windows, alerts, days, uploads
    db.drop_telemetry(endpoint_id)
    shutil.rmtree(os.path.join(os.environ.get("PDP_DATA_DIR", "/data"), "bundles", endpoint_id), ignore_errors=True)
    return {"ok": True, "deleted": ep["name"]}


INSTALL_STAGES = ("started", "checks_ok", "docker_install", "docker_ready", "downloading", "downloaded", "configured",
                  "starting", "enrolled", "failed")


class InstallProgress(BaseModel):
    token: str = Field(min_length=10, max_length=100)
    stage: str
    detail: str | None = Field(default=None, max_length=1000)
    host: str | None = Field(default=None, max_length=255)
    done_bytes: int | None = Field(default=None, ge=0, le=10**12)      # download progress
    total_bytes: int | None = Field(default=None, ge=0, le=10**12)


@app.post("/api/public/install/progress")
def install_progress(req: InstallProgress):
    """The one-line installer reports each stage (authenticated by its enrolment token) so the console can show
    where an installation is. Only for live single-use tokens that have not expired."""
    if req.stage not in INSTALL_STAGES:
        raise HTTPException(400, "unknown stage")
    ev = {"stage": req.stage, "detail": (req.detail or "")[:300] or None, "host": (req.host or "")[:128] or None,
          "at": datetime.now(timezone.utc).isoformat()}
    if req.done_bytes is not None:
        ev["done_bytes"] = req.done_bytes
    if req.total_bytes:
        ev["total_bytes"] = req.total_bytes
    with db.conn() as c:
        t = db.q(c, "SELECT progress FROM enroll_tokens WHERE token=%s AND max_uses IS NULL AND kind='live' AND expires_at > now()",
                 (req.token,), one=True)
        if not t:
            raise HTTPException(404, "unknown or expired token")
        p = list(t["progress"] or [])
        if p and p[-1]["stage"] == req.stage == "downloading":
            ev["since"] = p[-1].get("since") or p[-1]["at"]     # download progress updates in place; speed from `since`
            p[-1] = ev
        else:
            p.append(ev)
        db.q(c, "UPDATE enroll_tokens SET progress=%s WHERE token=%s", (json.dumps(p[-60:]), req.token))
    return {"ok": True}


@app.get("/api/install-progress/{key}")
def get_install_progress(key: str, s=Depends(admin)):
    """Where an installation started from the Add endpoint dialog is: the installer's stages, then the endpoint's
    own (enrolled, reporting, collecting activity, first model)."""
    from .k8s import key_of
    with db.conn() as c:
        rows = db.q(c, "SELECT token, name, progress, used_by, expires_at FROM enroll_tokens WHERE org_id=%s AND max_uses IS NULL "
                       "AND kind='live' AND expires_at > now() - interval '7 days'", (s["org"],))
        t = next((r for r in rows if key_of(r["token"]) == key), None)
        if not t:
            raise HTTPException(404, "not found")
        ep = None
        if t["used_by"]:
            e = db.q(c, "SELECT id, name, hostname, phase, last_seen, health, agent_version, enrolled_at FROM endpoints WHERE id=%s",
                     (t["used_by"],), one=True)
            if e:
                up = db.q(c, "SELECT count(*) AS n, min(received_at) AS first FROM upload_batches WHERE endpoint_id=%s AND kind='events'",
                          (e["id"],), one=True)
                model = db.q(c, "SELECT min(created_at) AS at FROM bundles WHERE endpoint_id=%s", (e["id"],), one=True)
                h = e["health"] or {}
                ep = {"id": str(e["id"]), "name": e["name"], "hostname": e["hostname"], "phase": e["phase"], "agent_version": e["agent_version"],
                      "enrolled_at": e["enrolled_at"], "last_seen": e["last_seen"],
                      "reporting": bool(e["last_seen"]) and (datetime.now(timezone.utc) - e["last_seen"]).total_seconds() < 300,
                      "collector": "error" if h.get("collector_error") else ("running" if h else None),
                      "collector_error": h.get("collector_error"),
                      "first_data_at": up["first"] if up["n"] else None, "first_model_at": model["at"] if model else None}
    return {"ok": True, "name": t["name"], "expires_at": t["expires_at"], "installer": t["progress"] or [], "endpoint": ep}


class AgentCommand(BaseModel):
    command: str


@app.post("/api/endpoints/{endpoint_id}/commands")
def queue_command(endpoint_id: str, req: AgentCommand, s=Depends(admin)):
    require_endpoint(s, endpoint_id)
    if req.command not in AGENT_COMMANDS:
        raise HTTPException(400, f"command must be one of {list(AGENT_COMMANDS)}")
    cid = pki.new_id()
    with db.conn() as c:
        if not db.q(c, "SELECT 1 FROM endpoints WHERE id=%s AND phase<>'retired'", (endpoint_id,), one=True):
            raise HTTPException(404)
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, params) VALUES (%s,%s,'command',%s)", (cid, endpoint_id, json.dumps({"command": req.command})))
    return {"ok": True, "id": cid}


@app.post("/api/endpoints/{endpoint_id}/retrain")
def retrain(endpoint_id: str, s=Depends(admin)):
    """Protected endpoints with agent 0.3.13+: collect two fresh days, then retrain on the most recent days and the
    false-alarm verdicts (the model follows the server's current normal). Otherwise: retrain on the baseline days."""
    require_endpoint(s, endpoint_id)
    with db.conn() as c:
        ep = db.q(c, "SELECT phase, config, agent_version FROM endpoints WHERE id=%s", (endpoint_id,), one=True)
        if not ep or ep["phase"] == "retired":
            raise HTTPException(404)
        from .refresh import capable, request_refresh
        if ep["phase"] == "protected" and capable(ep["agent_version"]):
            if (ep["config"] or {}).get("refresh_days"):
                raise HTTPException(409, "fresh days are already being collected for a retraining")
            days = request_refresh(c, endpoint_id, ep["config"], "requested from the console")
            return {"ok": True, "refresh_days": days}
        if db.q(c, "SELECT 1 FROM jobs WHERE endpoint_id=%s AND kind='train' AND state IN ('queued','running')", (endpoint_id,), one=True):
            raise HTTPException(409, "a training job is already queued or running")
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind) VALUES (%s,%s,'train')", (pki.new_id(), endpoint_id))
        db.q(c, "UPDATE endpoints SET phase='training' WHERE id=%s AND phase IN ('baseline','protected','degraded')", (endpoint_id,))
    return {"ok": True}


@app.get("/api/alerts")
def list_alerts(s=Depends(session), endpoint_id: str | None = None, status: str | None = None, layer: str | None = None, limit: int = 200,
                allowed: str | None = None):
    limit = max(1, min(int(limit), 5000))
    if endpoint_id:
        require_endpoint(s, endpoint_id)
    sc, sp = scope_sql(s, "a.endpoint_id")
    with db.conn() as c:
        rows = db.q(c, "SELECT a.id, a.endpoint_id, e.name AS endpoint, a.window_start_ns, a.node_uuid, a.ntype, a.label, a.fused, a.r1, a.r2, a.status, a.created_at, "
                       "coalesce(a.layer, 'learned') AS layer, a.rule, a.reason, a.allowed_by "
                       "FROM alerts a JOIN endpoints e ON e.id=a.endpoint_id WHERE (%s::uuid IS NULL OR a.endpoint_id=%s) AND (%s::text IS NULL OR a.status=%s) "
                       f"AND (%s::text IS NULL OR coalesce(a.layer, 'learned')=%s) AND {sc} "
                       + {"true": "AND a.allowed_by IS NOT NULL ", "false": "AND a.allowed_by IS NULL "}.get(allowed or "", "")
                       + "ORDER BY a.window_start_ns DESC LIMIT %s", (endpoint_id, endpoint_id, status, status, layer, layer, *sp, limit))
        from . import incidents as _inc
        eps = sorted({str(r["endpoint_id"]) for r in rows})
        inc_of = {}
        if eps:
            for g in _inc.grouped(c, eps):
                for a in g:
                    inc_of[a["id"]] = g[0]["id"]
    out = []
    for r in rows:
        r = dict(r, endpoint_id=str(r["endpoint_id"]), reason=_inc.clean_reason(r["layer"], r["reason"]), incident_id=inc_of.get(r["id"]))
        for k in ("fused", "r1", "r2"):
            r.pop(k, None)
        out.append(r)
    return {"ok": True, "alerts": out}


class AlertUpdate(BaseModel):
    status: str


@app.post("/api/alerts/{alert_id}")
def update_alert(alert_id: int, req: AlertUpdate, s=Depends(triager)):
    if req.status not in ALERT_STATUSES:
        raise HTTPException(400, f"status must be one of {list(ALERT_STATUSES)}")
    sc, sp = scope_sql(s, "endpoint_id")
    with db.conn() as c:
        if not db.q(c, f"UPDATE alerts SET status=%s WHERE id=%s AND {sc} RETURNING id", (req.status, alert_id, *sp), one=True):
            raise HTTPException(404)
    return {"ok": True}


@app.get("/api/alerts/export")
def export_alerts(s=Depends(session), format: str = "csv", endpoint_id: str | None = None, status: str | None = None, limit: int = 100000):
    """Download alerts (newest first) as CSV or NDJSON for a SIEM / spreadsheet."""
    import csv
    if format not in ("csv", "ndjson"):
        raise HTTPException(400, "format must be csv or ndjson")
    if endpoint_id:
        require_endpoint(s, endpoint_id)
    sc, sp = scope_sql(s, "a.endpoint_id")
    with db.conn() as c:
        rows = db.q(c, "SELECT a.id, a.endpoint_id, e.name AS endpoint, e.hostname, a.window_start_ns, a.node_uuid, a.ntype, a.label, a.fused, a.r1, a.r2, a.status, a.created_at, "
                       "coalesce(a.layer, 'learned') AS layer, a.rule, a.reason FROM alerts a JOIN endpoints e ON e.id=a.endpoint_id WHERE (%s::uuid IS NULL OR a.endpoint_id=%s) AND (%s::text IS NULL OR a.status=%s) "
                       f"AND {sc} ORDER BY a.window_start_ns DESC LIMIT %s", (endpoint_id, endpoint_id, status, status, *sp, max(1, min(limit, 1_000_000))))
    from .incidents import clean_reason
    for r in rows:
        r["reason"] = clean_reason(r["layer"], r["reason"])
        r["endpoint_id"] = str(r["endpoint_id"]); r["created_at"] = r["created_at"].isoformat() if r["created_at"] else None
        r["window_start"] = datetime.fromtimestamp(r["window_start_ns"] / 1e9, tz=timezone.utc).isoformat()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if format == "ndjson":
        body = "".join(json.dumps({k: v for k, v in r.items() if k not in ("fused", "r1", "r2")}, default=str) + "\n" for r in rows)
        return PlainTextResponse(body, media_type="application/x-ndjson", headers={"Content-Disposition": f'attachment; filename="pdp-alerts-{stamp}.ndjson"'})
    out = io.StringIO()
    cols = ["id", "endpoint", "hostname", "endpoint_id", "window_start", "window_start_ns", "layer", "rule", "reason", "ntype", "label", "node_uuid",
            "status", "created_at"]
    w = csv.DictWriter(out, fieldnames=cols, extrasaction="ignore")
    w.writeheader(); w.writerows(rows)
    return PlainTextResponse(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="pdp-alerts-{stamp}.csv"'})


@app.get("/api/alerts/{alert_id}/graph")
def get_alert_graph(alert_id: int, s=Depends(session), expand: str | None = None, hops: int = 1):
    g = alert_graph(alert_id, expand, hops)
    if not g.get("alert") or not visible(s, g["alert"]["endpoint_id"]):
        raise HTTPException(404, "not found")
    return {"ok": True, **g}


@app.get("/api/endpoints/{endpoint_id}/incident")
def get_incident(endpoint_id: str, s=Depends(session), focus_ns: int | None = None, span: int = 3):
    """The stitched attack graph + analyst summary around a focus window (default: the strongest detection)."""
    require_endpoint(s, endpoint_id)
    return {"ok": True, **incident_graph(endpoint_id, focus_ns, span)}


@app.get("/api/jobs")
def list_jobs(s=Depends(admin)):
    with db.conn() as c:
        rows = db.q(c, "SELECT j.*, e.name AS endpoint FROM jobs j JOIN endpoints e ON e.id=j.endpoint_id WHERE e.org_id=%s "
                       "ORDER BY j.created_at DESC LIMIT 100", (s["org"],))
    return {"ok": True, "jobs": [dict(r, id=str(r["id"]), endpoint_id=str(r["endpoint_id"]) if r["endpoint_id"] else None) for r in rows]}


# ---- simulation (campaign results are written by the simulation harness; see sim/) ----

@app.get("/api/sim/campaigns")
def list_campaigns(s=Depends(session)):
    sc_, sp = scope_sql(s, "sc.endpoint_id")
    with db.conn() as c:
        rows = db.q(c, "SELECT sc.id, sc.name, sc.state, sc.seed, sc.created_at, sc.finished_at, e.name AS endpoint, sc.spec->'summary' AS summary, "
                       "(SELECT count(*) FROM sim_runs r WHERE r.campaign_id=sc.id) AS runs FROM sim_campaigns sc LEFT JOIN endpoints e ON e.id=sc.endpoint_id "
                       f"WHERE {sc_} ORDER BY sc.created_at DESC LIMIT 100", sp)
    return {"ok": True, "campaigns": [dict(r, id=str(r["id"])) for r in rows]}


class NewCampaign(BaseModel):
    name: str
    endpoint_id: str
    spec: dict = {}
    bundle_id: str | None = None


@app.post("/api/sim/campaigns")
def create_campaign(req: NewCampaign, s=Depends(triager)):
    require_endpoint(s, req.endpoint_id)
    spec = dict(req.spec)
    from_sim = {"days", "runs", "attacks_per_pass", "families", "evasion_levels", "seed", "horizon_windows", "fp_budget"}
    if set(spec) - from_sim:
        raise HTTPException(400, f"unknown spec keys: {sorted(set(spec) - from_sim)}")
    if not (1 <= int(spec.get("runs", 40)) <= 5000) or not (1 <= int(spec.get("attacks_per_pass", 3)) <= 50):
        raise HTTPException(400, "runs must be 1..5000 and attacks_per_pass 1..50")
    if spec.get("fp_budget") not in FP_BUDGETS:
        raise HTTPException(400, f"fp_budget must be one of {list(FP_BUDGETS)}")
    spec.setdefault("days", ["validation"])
    spec.setdefault("runs", 40)
    spec.setdefault("attacks_per_pass", 3)
    spec["seed"] = int(spec.get("seed") or secrets.randbits(31))
    cid = pki.new_id()
    with db.conn() as c:
        ep = db.q(c, "SELECT id, current_bundle FROM endpoints WHERE id=%s", (req.endpoint_id,), one=True)
        if not ep:
            raise HTTPException(404, "endpoint not found")
        if not (req.bundle_id or ep["current_bundle"]):
            raise HTTPException(409, "the endpoint has no trained bundle yet")
        db.q(c, "INSERT INTO sim_campaigns (id, name, endpoint_id, bundle_id, spec, seed, state) VALUES (%s,%s,%s,%s,%s,%s,'queued')",
             (cid, req.name, req.endpoint_id, req.bundle_id, json.dumps(spec), spec["seed"]))
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, params) VALUES (%s,%s,'sim',%s)", (pki.new_id(), req.endpoint_id, json.dumps({"campaign_id": cid})))
    return {"ok": True, "id": cid, "seed": spec["seed"]}


@app.get("/api/sim/families")
def sim_families(s=Depends(session)):
    import glob
    attack_dir = os.environ.get("PDP_ATTACK_DIR", "/opt/pdp/sim/attacks")
    synthetic = ["web_backdoor", "browser_dropper", "lotl_recon", "priv_esc_lateral", "exfiltration", "ransomware", "script_c2"]
    transplants = sorted("transplant:" + os.path.basename(f)[:-5] for f in glob.glob(os.path.join(attack_dir, "*.json")))
    return {"ok": True, "families": synthetic + transplants, "evasion_levels": ["none", "low", "medium", "high", "extreme", "stealth"]}


@app.get("/api/sim/campaigns/{campaign_id}/results")
def campaign_results(campaign_id: str, s=Depends(session)):
    with db.conn() as c:
        camp = db.q(c, "SELECT id, name, state, seed, spec, created_at, finished_at, endpoint_id FROM sim_campaigns WHERE id=%s", (campaign_id,), one=True)
        if not camp or not visible(s, camp["endpoint_id"]):
            raise HTTPException(404)
        camp.pop("endpoint_id")
        runs = db.q(c, "SELECT run_index, attack, result FROM sim_runs WHERE campaign_id=%s ORDER BY run_index", (campaign_id,))
    spec = camp["spec"] or {}
    return {"ok": True, "campaign": dict(camp, id=str(camp["id"])), "summary": spec.get("summary"), "by_family": spec.get("by_family", []),
            "by_evasion": spec.get("by_evasion", []), "runs": [dict(r) for r in runs]}


_include_console_routes()
