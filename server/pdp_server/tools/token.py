"""Create an enrolment token from the server host (scripted provisioning, CI, the sandbox benchmarks).

  docker exec pdp-api-1 python -m pdp_server.tools.token --name sandbox-live --config '{"baseline_days": 3}'

Prints JSON: token, CA fingerprint and the agent's enrol command. Same rules as Console -> Endpoints -> Add.
"""
from __future__ import annotations

import argparse
import json
import secrets
from datetime import datetime, timedelta, timezone

from pdp_server import db, pki


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--kind", default="live", choices=["live", "benchmark", "simulation"])
    ap.add_argument("--dataset")
    ap.add_argument("--config", default="{}", help="initial endpoint config JSON, e.g. '{\"baseline_days\": 3}'")
    ap.add_argument("--hours", type=int, default=24)
    a = ap.parse_args()
    from pdp_server.posture import validate_config
    cfg = json.loads(a.config)
    try:
        validate_config(cfg)            # the console's rules: every configurable key (posture.CONFIG_SCHEMA), typed
    except Exception as e:
        raise SystemExit(f"bad config: {getattr(e, 'detail', e)}")
    token = secrets.token_urlsafe(24)
    from pdp_server.orgs import internal_org
    with db.conn() as c:   # operator tool: tokens for the provider's own (internal) organisation
        db.q(c, "INSERT INTO enroll_tokens (token, name, created_by, expires_at, kind, dataset, config, org_id) VALUES (%s,%s,NULL,%s,%s,%s,%s,%s)",
             (token, a.name, datetime.now(timezone.utc) + timedelta(hours=a.hours), a.kind, a.dataset, json.dumps(cfg), internal_org(c)))
    fp = pki.ca_sha256()
    print(json.dumps({"token": token, "ca_sha256": fp, "enroll_command": f"python -m pdp_agent enroll {token} --ca-sha256 {fp}"}))


if __name__ == "__main__":
    main()
