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

## Integrity of the endpoint signal (0.6)

Threat: an attacker with root on a monitored host blinds the product quietly - stops or detaches the collector,
drops alerts before they leave the host, swaps the model or its signing key, or stops the agent and keeps the console
green by re-sending its last heartbeat with the agent's own key. 0.6 makes each of these visible to the analyst: an
endpoint health problem (console) and an `agent_health` notification; the detection-relevant ones are errors and are
notified as **high** severity. Server logic: `server/pdp_server/integrity.py`; state per endpoint in
`endpoint_integrity`, received sequence numbers in `integrity_seqs` (schema.sql, "0.6"). Everything is general (no
per-client logic); the thresholds are defaults, overridable through the environment variables named below.

What the agent (0.6.0+) adds to every heartbeat:

| field | meaning |
|---|---|
| `hb_seq` | heartbeat sequence number, persisted in the agent's state (never goes back, also across restarts) |
| `run_id`, `started_at` | one per agent process start (the restart marker) |
| `agent_time` | the agent's wall clock when sending |
| `counters` | since the last heartbeat the server received: `events` collected, `dropped` (kernel, loader, spool cap, full disk), `windows`, `alerts`, `interval_s` |
| `source` | collector `kind`, `alive`, `events` (eBPF total) and `canary` `{sent, seen, missed, pending, last_seen_age_s}` |
| `bundle` | loaded model `id`, its `manifest_sha256`, the `signing_key_fp` on disk, the `pinned_key_fp`, and `refused {id, reason}` |
| `config_sha256` | sha256 of the effective local configuration (agent.json + environment + defaults, secret-looking keys left out) |
| `window_seq`, `alert_seq`, `unreported`, `lost_seqs` | last sequence numbers assigned, batches still queued for delivery, numbers the agent's own queue limit dropped |
| `score_failures`, `score_failures_24h` | windows the detector failed on and that were skipped |

Every window summary carries `seq`; every alert carries `seq` and `aid` (idempotency key: sha256 of endpoint,
sequence number, window, node, layer and rule). Upload batch ids no longer repeat after the local spool empties.

What the server checks (problem key, level, default):

| check | problem | level |
|---|---|---|
| a heartbeat whose `hb_seq` does not increase within the same run, or comes from an earlier run: a replay. It is **not** stored as the endpoint's health, so the health also goes stale | `heartbeat_replay` | error |
| the sequence went back at a restart (new `run_id`): the agent's local state was deleted or restored | `heartbeat_reset` | warning |
| the agent still calls the server (`last_seen` < 3 min) but no valid heartbeat for max(5 min, 3 heartbeat intervals) (`PDP_INTEGRITY_HB_STALE_S`) | `heartbeat_stale` | error |
| no events for longer than max(30 min, 2 x the longest silence this endpoint had in the last 7 days); only after 24 h of 0.6 history, only for live endpoints; endpoints whose normal silences exceed 3 h (i.e. threshold above 6 h) are not judged (`PDP_INTEGRITY_QUIET_MIN_S`, `_QUIET_FACTOR`, `_QUIET_MAX_S`, `_QUIET_HISTORY_S`) | `collection_stopped` | error |
| eBPF canary: every 60 s (`source.canary_s`, 0 = off) a short-lived child of the agent opens a file with a fresh nonce in the data directory; the collector must deliver that open within 300 s. 3 misses in a row (`PDP_INTEGRITY_CANARY_MISSED`) | `collector_blind` | error |
| collector kind on a live endpoint is not a whole-host collector (`ebpf`, `auditd`, `etw`): replay/sandbox error, `strace` warning | `source_kind` | error / warning |
| window/alert sequence numbers missing once the agent reports `unreported = 0` (everything delivered): alerts were removed before delivery. Checked from the first number this server received (no false gap when the server is upgraded after its agents). Numbers the agent declares lost to its queue limit (500 batches during a long outage) are a warning instead | `a_seq_gap`, `w_seq_gap` (`*_seq_lost`) | error (warning) |
| signing key on the endpoint is not the server's, or differs from the one pinned at enrolment | `bundle_key`, `bundle_key_pin` | error |
| the agent runs another model than the endpoint's current one, or none, more than 1 h after it was published (`PDP_INTEGRITY_BUNDLE_GRACE_S`) and for at least 10 min (a re-fetch) | `bundle_mismatch` | error |
| the current model's manifest digest on the endpoint differs from the published one | `bundle_modified` | error |
| the agent refused a model (wrong endpoint or id in the manifest, digest not the announced one, key not the pinned one) | `bundle_refused` | error |
| the detector failed on windows in the last 24 h (they were skipped, see below) | `scoring_failed` | error |
| agent clock more than 5 min off (`PDP_INTEGRITY_CLOCK_SKEW_S`); more than 1 h: error | `clock_skew` | warning / error |
| local configuration digest changed | `config_changed` | info (notified as low, shown for 24 h; does not make the endpoint unhealthy) |
| uploaded events with impossible timestamps refused (below) | `ingest_rejected` | warning |

One-off findings are shown for 24 h (`PDP_INTEGRITY_FINDING_H`); ongoing problems carry their start time in the key,
so each episode is notified once. Window summaries are insert-only for their alert count and highest score: a later
upload of the same window can raise but never lower them (past summaries cannot be rewritten to hide alerts). Alerts
are stored once per `aid` (a retried upload no longer duplicates them).

Agent side: the model signing key is pinned at enrolment (agents enrolled earlier pin the key they have when 0.6
first starts); a bundle is loaded only if the key on disk matches the pin, the manifest digest is the one the server
announced in `status`, and the manifest's `endpoint`/`bundle_id` (when present) are this endpoint and the announced
id. Scoring is guarded per window: an exception is retried once, then the window is skipped and counted; a crash
that kills the process while scoring (marker in the state) counts as an attempt too, so a window that crashes the
detector twice is skipped after the restart instead of crash-looping (detection off). The heartbeat is also sent
while a long backlog is scored, and the auditd source no longer holds the loop while audit.log is quiet.

Notifications (`agent_health`): event drops (`collector_lost`, `collector_behind`, `spool_dropped`) are keyed per
hour on the 1-hour counts (no longer by the order of magnitude of a running total that resets with the collector),
and are high when over 100,000 in the hour (`PDP_NOTIFY_DROPS_HIGH`) or while the endpoint raised alerts in the last
hour (agents before 0.3.19/0.3.22 report only running totals and keep the order-of-magnitude keys); `disk_full` and
`collector_error` repeat once a day while they last.

Ingest bounds (agent uploads): gzip bodies are decompressed in bounded steps (at most 1 GiB, `PDP_INGEST_MAX_BYTES`,
and above 64 MB at most 200 x the compressed size, `PDP_INGEST_MAX_RATIO`); at most 250,000 rows per request
(`PDP_INGEST_MAX_ROWS`); events of live endpoints must lie between enrolment - 1 day and server time + 1 day
(benchmark/simulation endpoints replay 2018/2019 datasets: 2000-01-01 .. now + 1 day), others are refused and counted;
a batch may touch at most 8 days (`PDP_INGEST_MAX_DAYS`) and only the days present get a partition. Single-use
enrolment tokens are locked while used: two concurrent enrolments with one token cannot both succeed.

Older agents (0.3.x-0.5.x) send none of these fields and are never flagged for their absence: their integrity
posture is `unsupported` (endpoint detail `health.integrity`), and only the pre-0.6 checks apply to them.

**Not covered.** All of this raises the bar from "stop the service" to "replace the agent". A root attacker who
fully emulates the agent - takes its key and state, and keeps sending heartbeats with increasing sequence numbers,
plausible event counters, the right model identity and a canary answer, while not actually collecting - is not
detected; nor is a collector that drops chosen events while passing the canary through. Root can also edit the
pinned key and the agent's state (the server-side comparison of the reported key and model is what catches a swap,
as long as the agent code itself reports truthfully). Closing this needs host attestation (TPM-measured boot and
agent binary, remote attestation of the running agent), which PDP does not have. Hosts that are naturally silent for
hours are not judged by the silence check (only the canary covers them, eBPF only); auditd and ETW have no canary
yet. A state reset re-starts the alert/window sequence and can hide a gap from before the reset.

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
