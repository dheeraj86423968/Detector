# Agent <-> server protocol (v1, agent 0.2)

Transport: HTTPS with mutual TLS on the agent port (gateway 8443, published on the host as `PDP_AGENT_PORT`, default 9443). The server CA signs one client certificate per
endpoint at enrolment; the certificate's CN is the endpoint id. JSON bodies; binary payloads are gzip'd
newline-delimited JSON (NDJSON). All responses carry `{"ok": true, ...}` or `{"ok": false, "error": ...}`.

## Enrolment
`POST /v1/enroll` (plain TLS, one-time token from the console)
```
{ "token": "...", "hostname": "...", "os": "linux", "arch": "x86_64", "agent_version": "0.1.0", "csr_pem": "..." }
-> { "endpoint_id": "...", "cert_pem": "...", "ca_pem": "...", "config": { "baseline_days": 7, "window_minutes": 15 } }
```
The agent generates its key locally; only the CSR leaves the host. The CN of the issued certificate is the endpoint id
(whatever the CSR says is ignored). Before enrolling, the agent fetches `/dl/ca.pem` once and pins it; with
`--ca-sha256 <hex>` / `PDP_CA_SHA256` (hex sha256 of the CA certificate's DER, shown in the console with the token)
it refuses a CA that does not match. `enroll` is idempotent and retries until the server is reachable. A token may
carry an initial endpoint configuration (`POST /api/endpoints {"name", "config": {...}}`), merged into `config`.

## Baseline upload (phase `baseline`)
`POST /v1/endpoints/{id}/entities`   NDJSON of `{"uuid","ntype","label","display","dense_id"}` (idempotent, by uuid). `dense_id` is the
                                      agent's registry index; the server builds the endpoint registry in exactly this order, so node ids
                                      (and the detector-2 neighbour state in the bundle) are identical on both sides. Uploaded in order.
`POST /v1/endpoints/{id}/events`     NDJSON of `{"ts_ns","src","op","dst","event_uuid"}` with header `X-Batch-Id` (exactly-once; the
                                      server acknowledges `{"ok":true,"batch_id":...}` and ignores re-sends of acknowledged ids)
`POST /v1/endpoints/{id}/day-complete`  `{"date": "YYYY-MM-DD"}` marks a calendar day as fully uploaded. Wall-clock collectors (ebpf,
                                      strace, auditd, etw) send it when a later day has started or the day ended more than 5 minutes ago;
                                      replays and the sandbox declare their days explicitly. The calendar is the endpoint's `config.tz`.
`GET  /v1/endpoints/{id}/status`     `{ "phase": "pending|baseline|training|protected|degraded", "baseline_days_done": n, "bundle": {"id","sha256"} | null }`

## Bundles (phase `protected`)
`GET /v1/endpoints/{id}/bundle`      tar.gz of the bundle directory (manifest.json, signature.json, featurizer/, *.npz).
                                      `?slim=1` (agents 0.3.4+): without the server-only files (tgn_state_val_start.npz);
                                      their digests stay in the signed manifest and are checked only if the file is present.
The agent verifies the Ed25519 signature against the server's bundle-signing public key received at enrolment
(`ca_pem` bundle), then the file digests, before loading anything.

## Results (phase `protected`)
`POST /v1/endpoints/{id}/windows`    NDJSON window summaries `{"start_ns","end_ns","edges","nodes","alerts","max_fused","max_r1","max_r2"}`
`POST /v1/endpoints/{id}/alerts`     NDJSON alerts with context:
```
{ "window_start_ns", "node": {"uuid","ntype","label","display"}, "fused", "r1", "r2",
  "context": { "nodes": [ {uuid,ntype,label} ... ], "edges": [ {src,dst,op,ts_ns,loss} ... ] } }   // k-hop subgraph around the node inside the window
```
Only flagged nodes and their window-local neighbourhood leave the host; benign telemetry does not.

Real time (agent 0.3.7+): layers 1-2 (new program, rules) run on each batch of events as it is scored, and the alerts
they raise on their own are posted at once, seconds after the events, with `window_start_ns` of the still-open
window, `fused`/`r1`/`r2` = 0 (no learned score yet) and the batch's events as `context`. When the window closes its
summary is posted as before; those alerts are not posted again, and the learned/corroborated alerts follow with it.
An alert already sent is remembered for two hours, so a restart that replays the open window does not repeat it.

## Control
`POST /v1/endpoints/{id}/heartbeat`  `{ "agent_version", "queue_depth", "last_window_end_ns", "cpu_pct", "rss_mb", "collector_lost",
                                      "spool_mb", "spool_dropped_unscored", "spool_dropped_unuploaded" }` — stored as the
                                      endpoint's `health` (with `at`); `queue_depth` = events awaiting upload (baseline) or scoring;
                                      `spool_*` (0.3.4+): local spool size and events its size cap dropped.
Commands are delivered in the `status` response: `"commands": [{"id": "...", "command": "refetch_bundle"}, ...]`
(queued from the console, `POST /api/endpoints/{id}/commands`). The agent executes each and acknowledges it:
`POST /v1/endpoints/{id}/commands/{cmd_id}/ack` `{"result": "ok" | "unsupported" | "error: ..."}`; an acknowledged
command is not delivered again. The alert threshold mode (`fp_budget`) travels in `config`, not as a command.
The bundle manifest carries `window_ns`; the agent builds detection windows of that length.

Kernels without BTF (0.3.18+): `GET /v1/endpoints/{id}/btf/{release}` → the kernel's BTF (raw, or BTFHub `.btf.tar.xz`),
404 when the server has none; heartbeat `collector_error` while the collector cannot start. Enrolment: a Kubernetes
fleet token accepts several enrolments; `hostname` is `$PDP_HOSTNAME` when set (the node name in a DaemonSet).
Response commands (0.3.15+): `kill_process {pid, uuid, label}`, `isolate`, `release`; results start with `ok:` on success.
Hunting (0.3.17+): `hunt {hunt_id, q, kind, limit}` - the agent searches its activity index (programs run with their
command line, `ip:port` contacted in either direction, files written outside /proc, /sys, /dev; first / last seen and
a count per distinct entry; 30 days, at most 300k entries) and answers with
`POST /v1/endpoints/{id}/hunts/{hunt_id}` (gzip NDJSON rows `{kind, program, object, first_ns, last_ns, count}`, or
one row `{"none": true}`), then acknowledges the command. Only endpoints the hunt was sent to can answer.

## Console API (session cookie, roles admin|analyst)
`/api/login`, `/api/logout`, `/api/me`, `/api/me/password`, `/api/users` (admin: list / create / delete),
`/api/endpoints` (admin POST: enrolment token + `ca_sha256` + `enroll_command`), `/api/endpoints/{id}` (timeline,
agreement, `health`), `/api/endpoints/{id}/config|retrain|retire|commands` (admin), `/api/endpoints/{id}/incident`,
`/api/alerts`, `/api/alerts/{id}` (status: open, ack, closed, true_positive, false_positive), `/api/alerts/{id}/graph`
(expandable subgraph: `?expand=<uuid>&hops=1`), `/api/alerts/export?format=csv|ndjson`, `/api/jobs`,
`/api/sim/families`, `/api/sim/campaigns`, `/api/sim/campaigns/{id}/results`. Unauthenticated: `/healthz`, `/dl/ca.pem`.

### POST /api/endpoints/{id}/config (admin)
Merge keys into the endpoint configuration: `baseline_days` (1-60 train days; validation day is added), `tz` (IANA
name), `retain_baseline_events`, `train` (TrainConfig field overrides), `window_minutes` (for days ingested after the
change; recorded in the bundle), `fp_budget` (null, "99", "99.9", "99.99"). Invalid values are rejected with 400.
Lowering `baseline_days` below the days already ingested starts training. The agent adopts the server's configuration
on its next status poll. Benchmark note: THEIA E3 has data on 04-03/04/05 and 04-09..13
only, so its endpoint uses `baseline_days: 3` (train 03-05, validation 09), matching the research split.
