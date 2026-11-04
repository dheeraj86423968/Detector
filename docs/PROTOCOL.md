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

## Control
`POST /v1/endpoints/{id}/heartbeat`  `{ "agent_version", "queue_depth", "last_window_end_ns", "cpu_pct", "rss_mb" }` — stored as the
                                      endpoint's `health` (with `at`); `queue_depth` = events awaiting upload (baseline) or scoring.
Commands are delivered in the `status` response: `"commands": [{"id": "...", "command": "refetch_bundle"}, ...]`
(queued from the console, `POST /api/endpoints/{id}/commands`). The agent executes each and acknowledges it:
`POST /v1/endpoints/{id}/commands/{cmd_id}/ack` `{"result": "ok" | "unsupported" | "error: ..."}`; an acknowledged
command is not delivered again. The alert threshold mode (`fp_budget`) travels in `config`, not as a command.
The bundle manifest carries `window_ns`; the agent builds detection windows of that length.

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
