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
`"docker_command"` (container), `"enroll_command"` (already-installed agent)`}`), `POST /api/endpoints/{id}/config
{"config": {...}, "reason"?}` (typed and range-checked; `reason` required when the change weakens detection, see
"Misuse resistance (0.6)"), `POST /api/endpoints/{id}/approved-executables {"executables": [...], "approve": true|false,
"note", "force"?}` (allow-list rules), `POST /api/endpoints/{id}/retire`. `GET /api/endpoints/{id}` (includes the
effective `config.approved_executables` from the allow list, and `posture`); `GET /api/endpoints/{id}/posture`.


### Removing an endpoint, install progress (0.6)
- `POST /api/endpoints/{id}/retire`: the agent is no longer accepted, raw activity deleted; alerts and incidents kept.
- `DELETE /api/endpoints/{id}` (admins) -> `{ok, deleted}`: the endpoint and everything about it (alerts, incidents,
  models, activity data, checks) are deleted; its allow-list-only entries and user access to it are removed too.
- `POST /api/endpoints` adds `progress_key`. The one-line installer reports its stages to
  `POST /api/public/install/progress {token, stage, detail?, host?}` (stages: started, checks_ok, docker_install,
  docker_ready, downloading (detail "n of m layers", updated in place), downloaded, configured, starting, enrolled,
  failed (detail = the error)); only live single-use tokens that have not expired.
- `GET /api/install-progress/{progress_key}` (admins of the token's organisation) -> `{name, installer: [{stage, detail,
  host, at}], endpoint: null | {id, name, hostname, phase, agent_version, enrolled_at, last_seen, reporting,
  collector: running|error|null, collector_error, first_data_at, first_model_at}}`. The Add endpoint dialog polls it.
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
`POST /api/alerts/{id} {"status"}` (`can.triage`), `GET /api/alerts/export?format=csv|ndjson&endpoint_id=&status=&limit=&since_id=`
(`can.triage`; at most 100000 rows per request, see "Misuse resistance (0.6)").

Detection type names for the UI: `novelty` "New program", `rules` "Suspicious data flow", `corroborated`
"Related activity", `learned` "Unusual behaviour", `evidence` "Supporting evidence".

## Allow list (0.4)

What the customer accepts as normal, so it stops alerting. Entries apply to all endpoints (`endpoints: null`) or to
selected endpoints. Agents receive the merged list with their configuration; the server also marks matching alerts
(`allowed_by` = entry id, status `false_positive`). Allowed alerts are kept but are **not part of any incident**.

`GET /api/allowlist?endpoint_id=` (any role; scoped) →
```json
{"ok": true,
 "kinds": [{"id": "program", "label": "Program", "text": "..."}, {"id": "address", "label": "Network address", "text": "..."},
           {"id": "detection", "label": "Specific detection", "text": "..."}],
 "entries": [{"id": 3, "kind": "program|address|detection", "value": "/usr/local/bin/links",
              "rule": null | "untrusted_exec", "rule_text": "Executes a downloaded file",
              "endpoints": null | [{"id": "...", "name": "web-01"}], "note": "browser used by ops",
              "created_by": "admin", "created_at": "...", "alerts_allowed": 18}]}
```
`POST /api/allowlist` (`can.manage_endpoints`) `{"kind", "value", "rule"?, "endpoints": null|[ids], "note"?, "resolve_open": true}`
→ `{"ok": true, "id": 3, "alerts_allowed": 18}` (how many open alerts it covered and removed from incidents).
`value`: program = full path (`/usr/bin/links`, `C:\Program Files\App\app.exe`), compared as the agent compares
programs (0.6: a bare name matches only a program recorded without a path, and is accepted only for endpoints whose
collector records none); address = IP or CIDR (at most /16, IPv6 /48); detection = the detection's key with `rule`
one of `novel_executable, untrusted_exec, untrusted_code_network, exfiltration, tainted_modify, tainted_spawn`, or
`learned` with a program as value (unusual-behaviour / related-activity alerts of that program). 0.6: `note` (or
`reason`) is required; interpreters, shells, loaders and system binaries need `"force": true`; wildcards and folders are
refused. 409 if the same entry exists; 400 with a message on invalid input. Entries carry `risks` (`name_only`,
`interpreter`, `wildcard`, `large_network`) and `force`.
`DELETE /api/allowlist/{id}` (`can.manage_endpoints`) → `{"ok": true, "alerts_reopened": n}` (0.6: alerts the entry
resolved automatically are open again; alerts an analyst triaged since keep their status).

`GET /api/alerts/{id}/allow-options` → ready-made entries for an "Allow..." dialog on an alert / graph node:
```json
{"ok": true, "alert_id": 817, "endpoint_id": "...", "allowed_by": null,
 "options": [{"kind": "program", "value": "/bin/sh", "rule": null, "title": "Allow the program /bin/sh", "text": "..."},
             {"kind": "detection", "value": "/tmp/font", "rule": "untrusted_exec", "title": "Don't alert on this again: ...", "text": "..."},
             {"kind": "address", "value": "155.162.39.48", "rule": null, "title": "Trust the address 155.162.39.48", "text": "..."}]}
```
`GET /api/alerts` rows carry `allowed_by` (null or entry id); `?allowed=false` lists only alerts not covered by the allow list, `?allowed=true` only covered ones. `POST /api/endpoints/{id}/approved-executables` still works
and creates/removes `program` entries for that endpoint; `GET /api/endpoints/{id}` returns the effective
`config.approved_executables`, `trusted_addresses`, `suppressed_detections`.

## Agent updates (0.6)
`GET /api/org/agent-updates` → `{policy: auto|manual|<version>, latest, target, held, staged, versions: {version: count},
canary_minutes}`; `PATCH /api/org/agent-updates {agent_update}` (admins). Agent side: `status.update = {version, image,
registry}` when the endpoint should update now; `POST /v1/endpoints/{id}/pull-token` → 15-minute registry credential.
Endpoint overview `health` adds `disk_free_pct`, `disk_free_mb`, `spool_mb`, `entities`, `update {state, target,
failed, updater}`; `issues` lists disk, event loss, falling behind, failed update, host needing `--upgrade`.

## Sign-in security, audit, retention (0.6)
- `POST /api/login` answers `{mfa_required: true}` (and a 5-minute `pdp_mfa` cookie) for accounts with two-factor
  sign-in; `POST /api/login/mfa {code}` (a TOTP code or a recovery code) completes it.
- `POST /api/me/mfa/setup` → `{secret, otpauth_uri}`; `POST /api/me/mfa/enable {code}` → `{recovery_codes}` (shown
  once); `POST /api/me/mfa/disable {password, code}`. `/api/me` adds `mfa_enabled`, `mfa_setup_required`.
- `PATCH /api/org {retention_days (30-3650), require_mfa}`; `GET /api/org` returns them and `sso` (without secret).
- `PUT /api/org/sso {provider: google|microsoft|oidc, tenant?, issuer?, client_id, client_secret?, domains,
  default_role: viewer|analyst, admin_emails, enabled}`, `DELETE /api/org/sso`; sign-in: `GET /api/sso/start?email=`
  → provider → `GET /api/sso/callback`. `/api/auth/config` adds `org_sso`. `sso.proof` lists each domain
  `{domain, verified_at|null, record_name, record_value}`: a domain signs in only once proven.
  `POST /api/org/sso/verify` looks up the TXT records (`_pdp-verification.<domain>` = `pdp-verification=<token>`)
  → `{sso, errors: {domain: why}}`. While unproven, other organisations may list the domain too; once proven,
  `PUT` by another organisation answers 409.
- Sessions: `POST /api/me/password` ends the user's other sessions (this one gets a new cookie); so does an admin
  setting a user's password (`PATCH /api/users/{id} {password}`) and `tools/reset_password`.
  `POST /api/me/sessions/end` signs out everywhere else. An ended session answers 401.
- `GET /api/audit?limit=` (admins): `{entries: [{at, who, action, target, status, ip, detail}]}` (`detail`, 0.6: redacted
  before/after `changes`, `reason`, `weakens`, export `rows`, hunt `query`).
- `POST /api/incidents/{id}/assign {user_id|null}`, `POST /api/incidents/{id}/notes {text}`; incident detail adds
  `assignee`, `history`, `assignable`; `GET /api/incidents?assignee=me|none`. `GET /api/reports/weekly`.

## Response actions (0.6, admins, opt-in)
`PATCH /api/org {response_actions: true}`; `POST /api/endpoints/{id}/respond {action: kill_process|isolate|release,
node_uuid (kill_process: a process an alert of this endpoint was raised on), reason (required, 0.6)}` → `{id}`;
`GET /api/endpoints/{id}/commands/{id}` → `{state, result}` (the agent acts within its next status poll). Health
adds `isolated`. Agents 0.3.15+.

## Kubernetes clusters (0.6, admins)
`POST /api/clusters {cluster, max_nodes (1-5000, 50), days (1-365, 30)}` → `{key, expires_at, max_nodes, manifest}`
(YAML: namespace, Secrets, DaemonSet). `GET /api/clusters` → `[{key, cluster, uses, max_nodes, expires_at, active,
endpoints}]`; `GET /api/clusters/{key}/manifest` (YAML with the current agent version; 410 once closed);
`POST /api/clusters/{key}/revoke` closes it to new nodes. Each node enrols as its own endpoint named after the node
(`config.cluster` = the cluster name). Public, for the installer: `GET /api/public/btf/{release}?arch=` →
`{available}`.

## Threat hunting (0.6)
`POST /api/hunts {q (2-200 characters), kind: exec|net|write|null}` (admins, analysts) → `{id, endpoints, skipped}`:
sent as a `hunt` command to every endpoint of the organisation that reported within a day and runs agent 0.3.17+
(older ones are counted in `skipped`). `GET /api/hunts` → the last 30 with `asked`, `answered`, `matches`;
`GET /api/hunts/{id}` → per endpoint `{answered, at, rows: [{kind, program, object, first_ns, last_ns, count}]}`
(endpoints with matches first). The search is a case-insensitive substring match over the program and the object
(command line, `ip:port`, file path) in each agent's local activity index (30 days, de-duplicated).

## Notifications (0.6, admins)
`GET /api/notifications/channels` → `{channels: [{id, name, kind, target, has_secret, min_severity, events, every_alert,
enabled, last_ok_at, last_error, last_error_at, ...}], email_available, notifier_running}` (secrets are never returned).
`POST /api/notifications/channels` `{name, kind: email|slack|teams|webhook|syslog, target, secret?, min_severity:
low|medium|high|critical, events: [incident, agent_offline, agent_health, weekly, detection_weakened, response_action],
every_alert (webhook/syslog), enabled}`;
`PATCH` / `DELETE /api/notifications/channels/{id}`; `POST /api/notifications/channels/{id}/test` queues a test
message; `GET /api/notifications/log?channel_id=` recent deliveries (sent, failed, suppressed, digest, queued).
All org-scoped: another organisation's channel ids answer 404.

## Misuse resistance (0.6)

Someone with console or API access - an insider, or an attacker holding a stolen session or an admin's password -
must not be able to weaken detection silently, and the product resists uses it was not built for (bulk extraction,
reaching other endpoints' or organisations' data, burning shared GPU time). Implemented in `pdp_server/posture.py`;
unit tests `tests/unit/test_posture.py`, database check `tests/e2e/misuse_check.py`.

**Typed settings.** Every key of `POST /api/endpoints/{id}/config` (and of the initial `config` of `POST
/api/endpoints`) and every `train.*` key has a type and a range (`posture.CONFIG_SCHEMA`, `TRAIN_SCHEMA`, checked
against `pdp_engine.trainer.TrainConfig`: a new engine field is not configurable until it is listed). Examples:
`learned_daily_budget` 0-1000, `train.*_epochs` 1-100, `train.velox_runs` 1-10, at most 10 `train.orthrus_seeds`,
`train.alert_layers` null or a non-empty list of layers, `train.corroboration_percentile` 99 / 99.9 / 99.99.
`train.device` is refused (the training worker chooses it; it used to make every training fail), and so are keys the
server manages (`kind`, `cluster`, `refresh_days` ...). `approved_executables` is refused with a pointer to the allow
list. A configuration in which neither deterministic layer (new programs, data-flow rules) can alert is refused
outright, reason or not (retire the endpoint instead).

**Weakening needs a reason, is audited and notified.** These changes are allowed for admins but answer `400 "Reason
required: ..."` until the request carries a non-empty `reason` (at most 500 characters):

| where | weakening |
|---|---|
| endpoint settings | layer 1 or 2 turned off; alerting dropped for a layer (`train.alert_layers`); `train.layers_only`; corroboration percentile raised; learned alerts turned off; a learned-alert daily limit above 100 (a flood that buries real alerts) or set to 0 while they are on; `periodic_retrain: false`; `early_models: false`; `fp_budget` raised; a shorter baseline; `retain_baseline_events: true` (privacy) |
| allow list | every new entry (program, address, detection); the `note` is the reason |
| organisation | retention lowered; two-factor sign-in no longer required |
| response actions | every action (`reason` required) |

Each is written to the audit log in the same transaction as the change, with a redacted before/after diff (secret
values never, webhook URLs reduced to their host), the reason and what it weakens, and becomes a security event:
`GET /api/security-events` (admins) → `{events: [{id, kind: detection_weakened|response_action, severity, endpoint_id,
endpoint, who, title, detail: {reason, changes, diff, ...}, at}]}`. The notifier sends them (severity high, whatever the
channel's minimum severity) to every channel subscribed to `detection_weakened` / `response_action` **or to
`incident`**: an admin cannot keep incident notifications while silencing these. Removing or disabling a channel,
dropping events from it, raising its minimum severity or changing its destination is itself a `detection_weakened`
event (sent to the remaining channels).

**Allow-list programs.** Full paths only, matched exactly as the agent's layer 1 matches approvals
(`pdp_engine.layers.program_key`: Windows spellings and per-version / GUID folders normalised) - approving `python3`
no longer marks alerts for `/dev/shm/x/python3` as allowed. A bare name is accepted only for endpoints whose model
shows the collector records programs without paths (otherwise 400). Wildcards (`*`, `?`, `[...]`) and folders are
refused. Interpreters, shells, loaders and system binaries that run other code (bash, sh, python*, perl, node,
java, env, sudo, ld-linux*.so, powershell, cmd, wscript/cscript, mshta, rundll32, regsvr32, msiexec, certutil ...)
answer `400 "Confirmation required: ..."` unless the request has `"force": true` and a note; the entry records
`force`. Existing `approved_executables` stored in endpoint configurations are migrated at start-up into allow-list
entries with the note "migrated from endpoint config" (no creator, an audit row each; values kept as they were - a
migration is not a new approval - and shown with their `risks`); the endpoint configuration no longer contributes
approvals. Deleting an entry reopens the alerts it resolved automatically (`allowed_by` = the entry, still
`false_positive`, `status_by` = the entry's creator or never set).

**Who changed an alert.** `alerts.status_by` / `status_at` are set by `POST /api/alerts/{id}`, incident status
actions and allow-list auto-resolution (`status_by` = the entry's creator), and cleared when a deletion reopens it.

**Detection posture.** Per endpoint, from the model manifest and the settings: no model (protected, or long after
enrolment), stuck on an early model, degraded (last build failed), model older than 60 days with periodic retraining
off or older than 120 days, a deterministic layer off in the model or in the settings, the model not alerting on
them, a rules-only model, learned alerts on with a daily limit above 100, stored training settings that would make
training fail, risky allow-list entries (interpreter, bare name). Shown with the endpoint's health issues (overview)
and as `posture: {level: ok|warning|error, problems: [{key, level, text}]}` on `GET /api/endpoints/{id}` and
`/posture`. The notifier recomputes it every 5 minutes (`PDP_POSTURE_REFRESH_S`); a new or worse problem is a
`detection_weakened` event.

**Export, hunts, simulation.** `GET /api/alerts/export` needs `can.triage` (viewers 403), returns at most 100000 rows
per request (`PDP_EXPORT_MAX_ROWS`; a larger `limit` is a 400): page with `since_id` (rows with a larger id, oldest
first; `X-PDP-Next-Since-Id` gives the next page while `X-PDP-More: 1`). Every export is audited with its filters and
row count. Hunts ask only the endpoints in the starter's scope, and every user sees hunts and answers only for the
endpoints in their own scope; each hunt is audited with its query text. `POST /api/sim/campaigns` accepts a
`bundle_id` only if it is one of that endpoint's own models (the simulation worker checks again before loading a
model); simulated attacks are capped per organisation at `PDP_SIM_RUNS_PER_DAY` (20000) per 24 hours (429).
Per-user token buckets (table `rate_buckets`, shared by all API workers; burst/per hour): exports `PDP_RATE_EXPORT`
10/30, hunts `PDP_RATE_HUNT` 20/120, simulation campaigns and detection checks `PDP_RATE_SIM` 5/20; over the limit:
429 with `Retry-After`. Sign-in and sign-up keep their gateway rate limits.

**Audit retention.** The audit log is kept for at least 365 days whatever the organisation's data retention (a lower
retention deletes old alerts and incidents, not the record of who changed what).

**What remains.** An organisation admin can still weaken detection - now only visibly: with a reason, in the audit
log and notified to the organisation's channels. There is no two-person approval, so a single malicious admin can
still act (and could also delete the channels first; that is notified to the other channels and kept in the audit
log, but if every channel is gone only the console's security events and audit log show it). The audit log and the
security events live in the same database the platform operator controls; they are not tamper-proof against the
operator or anyone with database access, and admins of the organisation can read but not edit them through the API.
Rate limits are per user, not per organisation (many accounts multiply them); exports are bounded per request, not
in total. Program matching is exactly the agent's: a program approved at one path is still trusted if an attacker
replaces the file at that path (layer 2 and the learned layer still see what it does). Detection settings changed by
the platform operator's tools (`tools/token.py`, direct database access) bypass the reason requirement.

## Organisations (multi-tenant, 0.5)

PDP is hosted for many client organisations on one server. Every user and endpoint belongs to exactly one
organisation; a user sees only their organisation's endpoints, incidents, alerts, allow list, users and invites
(anything else answers 404). Roles (admin / analyst / viewer) and per-user endpoint scope apply *within* the
organisation. The platform operator (`me.operator`) additionally sees the list of organisations and their usage -
never their incidents, alerts or graphs.

`GET /api/me` adds
```
org: {id, name}, operator: bool,
can: {..., manage_org: bool (org admin), operate: bool (operator)}
```

### Sign-up (public)
`GET /api/auth/config` adds `signup: "off" | "code" | "open"`.

`POST /api/signup` `{organisation, name, email, password, code?}` creates the organisation and its first admin
(username = email) and signs them in (sets the session cookie, returns the same body as `/api/me`).
Errors: 400 invalid field (message says which), 403 sign-up off or wrong code, 409 email already registered,
429 too many sign-ups from this address.

### Invites
Admin:
- `GET /api/invites` -> `{ok, invites: [{id, email|null, role, endpoints: [{id,name}]|null, created_at, expires_at, created_by, link}]}`
  (pending only)
- `POST /api/invites` `{email?: string, role, endpoints: [ids]|null}` -> `{ok, invite: {...same fields, link}}`.
  `link` is `https://<host>/#/join/<token>`; valid 7 days, single use. The console shows it to copy (no e-mail is sent).
- `DELETE /api/invites/{id}` -> `{ok}`

Public:
- `GET /api/invites/{token}` -> `{ok, organisation, role, email|null, expires_at, invited_by}`; 404 if unknown,
  used, revoked or expired.
- `POST /api/invites/{token}/accept` `{name, email?, password}` (email required when the invite has none; must match
  when it has one) -> signs in, returns the `/api/me` body. 409 if the email is already registered.

### Organisation
- `GET /api/org` -> `{ok, org: {id, name, created_at, max_endpoints, endpoints, users, pending_invites}}`
- `PATCH /api/org` `{name}` (admin) -> `{ok, org}`

Endpoint limit: `POST /api/endpoints` answers 403 "Your organisation has reached its limit of N endpoints" when
active endpoints plus unused enrolment tokens reach `max_endpoints`.

Install: `POST /api/endpoints` returns `install_command`, a one-line installer for a Linux server:
`curl -fsSL https://<host>/install.sh | sudo bash -s -- --token <token>` (checks kernel/BTF, root and docker,
pulls the agent from `<host>`'s read-only registry, writes the configuration, starts `pdp-agent.service`, enrols).
`docker_command` remains for hosts that only run containers.

### Operator
- `GET /api/operator/orgs` -> `{ok, signup: {mode, code|null}, orgs: [{id, name, created_at, disabled, max_endpoints,
  users, endpoints, endpoints_online, alerts_7d, last_activity|null, sso_domains|null, sso_verified: {domain: at}}]}`
- `POST /api/operator/orgs/{id}/sso/confirm {domain}` -> `{ok}`: the operator confirms a listed SSO domain checked
  by other means (409 when another organisation proved it).
- `PATCH /api/operator/orgs/{id}` `{disabled?: bool, max_endpoints?: int}` -> `{ok, org}`. A disabled organisation's
  users cannot sign in; its agents keep running.
- `DELETE /api/operator/orgs/{id}` -> `{ok, endpoints_deleted}`: offboards a client - deletes the organisation and
  everything it owns (users, endpoints and their telemetry, alerts, models, checks, allow list, invites). Only a
  disabled organisation can be deleted; the operator's own organisation never.
