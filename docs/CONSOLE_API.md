# Console API (0.4)

The console is a single-page app served by the gateway; every call is same-origin under `/api/`, authenticated
by the `pdp_session` cookie (HttpOnly, Secure, SameSite=Strict). Errors: non-2xx with `{"detail": "..."}`.
`401` = not signed in, `403` = role or endpoint scope does not allow it, `404` = not found *or not visible to
this user* (scoped users never learn that other endpoints exist).

Timestamps: `*_ns` are Unix nanoseconds (int), `*_at` are ISO-8601 strings.

## Access control

Three roles, plus an optional endpoint scope per user:

| role | can |
|---|---|
| `admin` | everything: users and access, add/retire endpoints, endpoint settings, approve programs, triage, run checks |
| `analyst` | view everything in scope, triage incidents/alerts, run detection checks |
| `viewer` | view everything in scope (read-only) |

`endpoints`: `null` = all endpoints (default), or a list of endpoint ids the user may see. Admins always see all.

`GET /api/me` →
```json
{"ok": true, "user_id": 3, "username": "alice", "display_name": "Alice Admin", "email": "alice@example.com",
 "role": "admin", "auth": "local|oidc", "endpoints": null,
 "can": {"manage_users": true, "manage_endpoints": true, "triage": true, "run_checks": true}}
```
The UI must use `can.*` to show/hide actions (never infer from role names).

`GET /api/users` (admin) →
```json
{"ok": true, "sso": {"enabled": true, "label": "Sign in with Okta", "password_policy": "enabled|admin-only|disabled"},
 "users": [{"id": 3, "username": "alice", "display_name": "Alice Admin", "email": "alice@example.com", "role": "admin",
            "auth": "local", "endpoints": null, "disabled": false, "created_at": "...", "last_login": "..."|null}]}
```
`endpoints` here is `null` or `[{"id": "...", "name": "web-01"}]`.

`POST /api/users` (admin) `{"username", "password", "role", "display_name"?, "email"?, "endpoints": null|[ids]}`
→ `{"ok": true, "id": 7}`. Password >= 10 chars; username `[A-Za-z0-9_.@-]{2,64}`; 409 if taken.

`PATCH /api/users/{id}` (admin) any of `{"role", "display_name", "email", "endpoints", "disabled", "password"}`
→ `{"ok": true}`. `password` = admin reset (local accounts only). An admin cannot demote, disable or delete
themselves (400), and the last enabled admin cannot be demoted/disabled/deleted (400).

`DELETE /api/users/{id}` (admin) → `{"ok": true}`.

Existing: `POST /api/login`, `POST /api/logout` (→ `{"end_session_url"}`), `GET /api/auth/config`,
`GET /api/oidc/login` (link, not fetch), `POST /api/me/password`.

## Overview

`GET /api/overview` →
```json
{"ok": true,
 "endpoints": {"total": 5, "protected": 3, "learning": 1, "offline": 1},
 "incidents": {"open": 4, "last_7d": 6, "by_severity": {"critical": 1, "high": 2, "medium": 1, "low": 0}},
 "per_day": [{"date": "2026-10-22", "incidents": 0}, "... 14 entries, oldest first"],
 "recent_incidents": ["<incident summary>, up to 6, newest first"],
 "attention": [{"kind": "offline|dropping_events|check_failed|no_check", "endpoint_id": "...", "endpoint_name": "web-01",
                "text": "web-01 has not reported for 2 h"}]}
```

## Endpoints

`GET /api/endpoints` → `{"ok": true, "endpoints": [<endpoint>]}` where
```json
{"id": "...", "name": "web-01", "hostname": "web-01.corp", "os": "linux", "kind": "live|benchmark|simulation",
 "state": "learning|training|protected|offline|retired",
 "state_text": "Learning normal behaviour (day 3 of 7)",
 "baseline": {"done": 3, "needed": 8},
 "last_seen": "...", "online": true, "agent_version": "0.3.1",
 "open_incidents": 2, "last_incident_ns": 1793765749000000000 | null}
```
`state`: `offline` when protected/learning but no heartbeat for > 10 min.

`GET /api/endpoints/{id}/overview` → "is detection working on my data":
```json
{"ok": true, "endpoint": <endpoint>,
 "lifecycle": [
   {"step": "enrolled",   "status": "done",    "at": "...", "text": "Agent installed and enrolled"},
   {"step": "baseline",   "status": "done|active|pending", "text": "Learning normal behaviour", "done": 3, "needed": 8,
    "days": [{"date": "2026-11-04", "events": 1834567, "complete": true}]},
   {"step": "model",      "status": "done|active|pending", "at": "...", "text": "Detection model trained on 7 days",
    "details": {"known_programs": 412, "trusted_addresses": 37, "benign_rules": 12}},
   {"step": "protecting", "status": "done|active|pending", "at": "...", "text": "Protecting since 12 Nov"}],
 "health": {"online": true, "last_seen": "...", "agent_version": "0.3.1", "collector": "eBPF (CO-RE)",
            "events_dropped": 0, "queue_depth": 0, "cpu_pct": 4.1, "rss_mb": 600,
            "events_24h": 120345678, "status": "ok|warning|error", "issues": ["text", "..."]},
 "detection": {"incidents_open": 2, "incidents_total": 5, "alerts_7d": 31,
               "by_type_7d": {"novelty": 20, "rules": 9, "corroborated": 2, "learned": 0},
               "triaged": {"true_positive": 3, "false_positive": 1, "open": 27},
               "per_day": [{"date": "...", "alerts": 3, "incidents": 1}, "... 14 entries"]},
 "check": <check summary>|null,
 "can_run_check": true, "check_blocked_reason": null | "the endpoint is still learning (day 3 of 7)"}
```

Detection checks (synthetic attacks replayed into this endpoint's own data, scored by its own model):

`GET /api/endpoints/{id}/checks` → `{"ok": true, "checks": [<check summary>]}` newest first.
`POST /api/endpoints/{id}/checks` (`can.run_checks`) `{}` → `{"ok": true, "id": "..."}` (sensible defaults; 409 with
`detail` when the endpoint has no model yet).
```json
<check summary> = {"id": "...", "state": "queued|running|done|failed", "created_at": "...", "finished_at": "..."|null,
  "attacks": 24, "detected": 22, "rate": 0.917,
  "false_alarms_on_clean_data": 0,
  "by_family": [{"family": "web_backdoor", "label": "Web shell / backdoor", "attacks": 3, "detected": 3}],
  "verdict": "pass|warn|fail", "verdict_text": "22 of 24 simulated attacks detected; no false alarms on clean data"}
```

Endpoint actions (admin): `POST /api/endpoints` (enrol token: `{"name"}` →
`{"token", "ca_sha256", "expires_in_hours", "server_url", "agent_url", "install_command"` (Linux package),
`"docker_command"` (container), `"enroll_command"` (already-installed agent)`}`), `POST /api/endpoints/{id}/config`,
`POST /api/endpoints/{id}/approved-executables {"executables": [...], "approve": true|false}`,
`POST /api/endpoints/{id}/retire`. `GET /api/endpoints/{id}` (existing, includes `config.approved_executables`).

## Incidents

An incident is a group of alerts on one endpoint that are close in time (gap <= 30 min); its id is the id of its
first alert. Scores are never shown; what is shown is *why* (the detection's reason).

`GET /api/incidents?status=open|all|investigating|resolved|false_positive&endpoint_id=&severity=&limit=100` →
`{"ok": true, "incidents": [<incident summary>]}` newest first.
```json
<incident summary> = {"id": 816, "endpoint_id": "...", "endpoint_name": "web-01",
  "first_ns": 1736173200000000000, "last_ns": 1736174100000000000,
  "severity": "critical|high|medium|low",
  "title": "Sensitive data sent to untrusted 198.51.100.237 by python",
  "tactics": ["Execution", "Command and control", "Exfiltration"],
  "alerts": 12, "processes": 5, "status": "open|investigating|true_positive|false_positive|resolved"}
```

`GET /api/incidents/{id}` →
```json
{"ok": true, "incident": <incident summary>,
 "story": [{"ts_ns": 1736173200068075431, "kind": "process|exec|write|read|network|detection",
            "text": "python started /bin/sh -c cat /etc/issue; uname -a", "node": "<node id>", "detection": null | {"type": "novelty", "reason": "..."}}],
 "graph": {
   "nodes": [{"id": "proc:...", "type": "process|file|network|group",
              "label": "sh", "title": "/bin/sh -c cat /etc/issue; uname -a",
              "details": {"Program": "/bin/sh", "Command line": "...", "PID": "4242"},
              "alerted": true, "detection": {"type": "novelty|rules|corroborated|learned|evidence", "rule": "novel_executable",
                                             "reason": "runs /bin/sh, which never ran during the baseline", "alert_id": 817} | null,
              "first_ns": 1736173200068075431, "count": 1}],
   "edges": [{"id": "e1", "source": "proc:...", "target": "file:...", "op": "WRITE", "label": "wrote",
              "first_ns": 1736173200068075431, "count": 3, "order": 4}],
   "truncated": false},
 "alerts": [{"id": 817, "ts_ns": 1736173200000000000, "node": "<node id>", "label": "sh", "title": "/bin/sh -c ...",
             "type": "novelty", "rule": "novel_executable", "reason": "...", "status": "open"}]}
```
Edges point in the direction of information flow (a process *writes* a file: process -> file; a process *reads* a
file: file -> process; *executes*: file -> process; *connects/sends*: process -> network; *receives*:
network -> process; *starts* (CLONE): parent -> child). `order` is the edge's rank by first time (1 = earliest),
so the UI can number the attack steps. Library/system file reads of a process are folded into one `group` node
("42 system files"). `group` nodes have `details` with a sample of paths.

`POST /api/incidents/{id}/status` (`can.triage`) `{"status": "investigating|true_positive|false_positive|resolved|open", "note"?}`
→ `{"ok": true}` (applies to every alert of the incident).

Alerts (secondary view): `GET /api/alerts?endpoint_id=&status=&layer=&limit=` → fields `id, endpoint_id, endpoint,
window_start_ns, node_uuid, ntype, label, layer, rule, reason, status, created_at, incident_id` (no scores; reasons are
score-free sentences),
`POST /api/alerts/{id} {"status"}` (`can.triage`), `GET /api/alerts/export?format=csv|ndjson`.

Detection type names for the UI: `novelty` "New program", `rules` "Suspicious data flow", `corroborated`
"Related activity", `learned` "Unusual behaviour", `evidence` "Supporting evidence".
