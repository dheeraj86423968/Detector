# Provenance Detection Platform (PDP) - architecture

Status: design baseline, 2026-10-29. Fresh codebase in `detector/platform`.

## Decisions (from the kickoff)

| topic | decision |
|---|---|
| detectors | detector-1 = Velox, detector-2 = ORTHRUS (3-seed average); the 2:1 weighted-mean fusion is the primary alert source; per-detector views kept. Detector names never appear in client-facing surfaces. |
| placement | training on the server; detection on the endpoint; egress = baseline upload + results only |
| external services | none (no LLMs, no telemetry, no experiment trackers); backend network has no internet egress |
| telemetry | Linux auditd first, eBPF second, Windows later; DARPA TC CDM replay for benchmarks and simulation |
| scope | processes, files, sockets and the 10 system-call edge types the detectors use; plus user, cmdline, parent pid and hashes for display |
| GUI | web console first (desktop wrapper later); alert subgraph (capped, expand on demand), endpoint timeline + agreement, attack reconstruction, simulation dashboard |
| simulation | graph-level injection with mimicry, telemetry-level transplant of real attacks, later live attacks in a sandbox VM; randomised campaigns against fixed trained models; detection rate, time-to-detect, FP/endpoint-day, evasion robustness, CIs, regression tracking |
| operations | tens of endpoints per on-prem server (scalable to two), one GPU; 7-day baseline, weekly retrain, 3 ORTHRUS seeds, validation-max threshold + optional FP budget |

## Components

```
endpoint                                               server (docker compose)
┌───────────────────────────────┐    mTLS :8443     ┌──────────────────────────────────────────┐
│ agent (pdp_agent)             │ ────────────────▶ │ gateway (nginx TLS)                      │
│  sources: auditd | cdm-replay │  baseline events  │  ├ console (SPA) :443                    │
│  normaliser -> event schema   │                   │  └ agent API :8443 (client certs)        │
│  spool (sqlite)               │ ◀──────────────── │ api (FastAPI) ── platform-db (Postgres)  │
│  runtime (pdp_engine.runtime) │  signed bundles   │  │                telemetry-db (Postgres) │
│   detector-1 + detector-2     │                   │  ▼                                       │
│   fusion + thresholds         │ ────────────────▶ │ queue (redis) ─ worker-ingest            │
│  reporter (alerts + context)  │  alerts, scores,  │              ─ worker-train (GPU)        │
└───────────────────────────────┘  graph context    │              ─ worker-sim (simulation)   │
                                                    └──────────────────────────────────────────┘
```

| component | path | responsibility |
|---|---|---|
| engine | `engine/pdp_engine` | event schema, streaming graph construction (15-min windows, edge fusion), featurisation (word2vec on labels, train split only), models (Velox, ORTHRUS), trainer, thresholds, fusion, runtime scorer, signed bundles |
| server | `server/pdp_server` | enrolment + PKI, baseline ingest, training jobs (3 seeds + fusion calibration), bundle signing/distribution, alert + context storage, graph queries for the console, simulation campaigns |
| agent | `agent/pdp_agent` | collectors (auditd, CDM replay), normaliser, baseline uploader, local detection with bundles, reporter |
| console | `console/` | React + TypeScript SPA: endpoints, alerts, provenance subgraph (Sigma.js/Graphology, WebGL), timeline + agreement, attack reconstruction, simulation dashboard |
| sim | `sim/pdp_sim` | attack generators (graph-level injection with mimicry padding; telemetry-level transplant of DARPA/OpTC attacks), campaign runner, metrics (detection rate, time-to-detect, FP/endpoint-day, robustness vs evasion strength, bootstrap CIs), regression store |
| deploy | `deploy/` | Dockerfiles, compose (CPU + GPU overlay), nginx, secrets bootstrap |
| tests | `tests/` | unit (engine semantics), parity (engine vs PIDSMaker artifacts on CADETS/THEIA), e2e (replayed DARPA day through agent -> server -> console) |

## Event schema (normalised telemetry)

Entities: `process {uuid, pid, exe, cmdline, user, ppid}`, `file {uuid, path}`, `socket {uuid, local_ip, local_port, remote_ip, remote_port}`.
Events: `{ts_ns, src_uuid, op, dst_uuid, event_uuid}` with `op` in
`CONNECT, EXECUTE, OPEN, READ, RECVFROM, RECVMSG, SENDMSG, SENDTO, WRITE, CLONE`. Direction follows the
DARPA/PIDSMaker convention: data flow from src to dst (RECV*/ACCEPT are reversed so the socket is the source).
Node labels used for featurisation: process = `exe cmdline`, file = `path`, socket = `remote_ip remote_port`.

## Detection semantics (must match the research setting, non-snooped)

1. Windows of 15 minutes of events; consecutive identical (src, dst, op) events fused.
2. word2vec (256-d) fitted on the labels of the baseline days only; node feature = [embedding(256), type one-hot(3)].
3. detector-1: linear encoder + edge MLP predicting the edge type; per-edge loss = cross entropy.
   detector-2: TGN last-neighbour sampling (20) + 2-layer TransformerConv (8 heads) + edge MLP; 3 seeds.
4. Node score per window = max loss over edges where the node is src or dst; threshold = max node score on the
   validation day (last baseline day); optional FP-budget threshold = validation percentile.
5. Fusion: r_i = score_i / threshold_i; fused = (2 r_1 + mean_seeds(r_2)) / 3; alert if fused > max fused score on the validation day.
6. Model selection by lowest validation loss (never a test metric).
7. (0.3) Layered alerting: layer 1 executable novelty, layer 2 information-flow tag alarms with per-key thresholds
   fitted on the baseline (leave-one-day-out), layer 3 the fused score as a ranker - corroborated alerts next to layer
   1/2 detections, otherwise at most `learned_daily_budget` per day. detector-1 gets window degree features and 3
   seeds, detector-2 5 seeds averaged. Pre-0.3 bundles alert as in 5. Details: docs/DETECTION_LAYERS.md.

## Security

mTLS between agent and server with per-endpoint client certificates issued at enrolment; bundles signed
(Ed25519) and verified on the endpoint; no pickle in bundles (safetensors + JSON); console behind TLS with
session auth and roles (admin, analyst); backend network without egress; secrets in Docker secrets.

## Phases

1. Core pipeline: engine + agent (CDM replay, auditd) + server (ingest, train, bundles, alerts) with parity tests against the existing CADETS/THEIA artifacts.
2. Console with graph views.
3. Simulation harness (injection + transplant) and dashboard.
4. THEIA_E3 and CADETS_E3 end to end through the product.
5. Live attack stage: a live endpoint whose telemetry is captured from running processes (strace/ptrace collector),
   with benign baseline + attack-shaped scenarios driven in a throwaway sandbox (`sim/pdp_sim/sandbox`). Done.


## Simulation harness

`sim/pdp_sim` (see `docs/SIMULATION.md`): synthetic attack families and real DARPA transplants with mimicry /
camouflage / slow-and-low evasion, injected into benign days and scored by the real runtime. Campaigns are
created from the console (`POST /api/sim/campaigns`), executed as `sim` jobs by the training worker, stored in
`sim_campaigns` / `sim_runs`, and shown on the Simulation page with confidence intervals.


## Telemetry notes

* `event_uuid` is not a key. DARPA CADETS reuses event uuids across days (every uuid of 2018-04-07 also occurs on
  an earlier day) and weekend days contain many content-identical records; the research pipeline keeps all of them.
  Upload idempotence therefore comes from the per-batch id (`upload_batches`), and the per-endpoint `events` table
  has no uniqueness constraint. A uuid key silently dropped 43 % of two baseline days during the first benchmark run.
* The baseline is the first `baseline_days + 1` days the agent sees (touch order), and the server trains on the
  first `baseline_days + 1` days completed (completion order); the chronologically last of them is the validation
  day. Replays may stream days out of order, so days are completed only by the source's declaration unless the
  source is a chronological live collector.
* Live collectors (`agent/pdp_agent/sources`): `ebpf` (libbpf CO-RE raw tracepoints, the production Linux collector; bcc engine as fallback), `strace_src`
  (ptrace, the portable fallback where eBPF/audit are unavailable, e.g. the WSL2 kernel), `auditd` (kernel audit log),
  `windows_etw` (Windows ETW), and `db-replay`/`sandbox` for benchmarks. All emit the same normalised Entity/Event
  stream with one syscall set (execve/open/connect/clone family; file reads and writes are inferred from the open
  mode, not traced), so edge semantics are identical across collectors and OSes. The eBPF collector additionally
  reports data moved on connected INET sockets (read/write/send/recv without an address, sendfile, splice, io_uring)
  as READ / WRITE / RECV* / SEND* edges to the connection's netflow node (next agent release; docs/DEPLOYMENT.md §1;
  file I/O stays inferred from the open mode). The record->event mapping of each
  collector is unit-tested without a kernel (tests/unit/test_{strace,ebpf,windows_etw,auditd}.py).
* Entity dense ids must be identical on the agent and in the server's window store (detector-2 neighbour state is
  keyed by them). The agent uploads each entity with its own registry index (`dense_id`) and the server builds the
  registry in that order, so the ids match regardless of event order, timestamp ties or ingest order.


## Status (2026-10-30)

All five phases are implemented and exercised (results in `artifacts/platform_bench/results/RESULTS.md`). Product
hardening completed this round:

* Collectors for every target: eBPF (bcc) production Linux collector, strace/ptrace portable fallback, auditd, and
  Windows ETW — all emitting one shared event stream, each with unit-tested mapping. (This WSL2 kernel ships no
  headers and no CONFIG_IKHEADERS, so eBPF/bcc and bpftrace cannot load here; the strace collector is used on this
  host and is validated live. eBPF runs on a standard host.)
* Slim endpoint runtime image (`deploy/docker/agent.Dockerfile`, ~1.7 GB CPU) separate from the 24 GB training
  image; the featuriser is gensim-free at inference. The sandbox endpoint runs on it.
* False-positive budget wired end to end: per-endpoint `fp_budget` (validation-max or a percentile) set from the
  console, applied by the agent (it re-instantiates the detectors with the new calibration on the next poll).
* GPU memory: the node-feature matrix can live on CPU while the models run on the GPU (`feat_device`, default CPU
  when detecting on GPU), so large registries no longer OOM. Verified with GPU models + CPU features.
* Desktop console wrapper (`desktop/`, Electron, CA-pinned) packages the console for Windows/macOS/Linux.
* Detector-2 aggregation is label-free and defaults to `best_val_loss` (beats the mean on CADETS at no extra FP).
* The agent persists its open detection window across restarts (validated live on the sandbox endpoint).

Remaining future work is operational, not functional: tuning agent CPU throughput, and running eBPF/Windows/desktop
on their native hosts (they cannot be exercised on this WSL2/Linux box).


## Status (2026-11-03, agent/server 0.3)

Layered detection (docs/DETECTION_LAYERS.md): after the DARPA E3 benchmark showed both learned detectors unreliable
under an honest protocol (docs/BENCHMARK_E3.md), deterministic layers 1-2 run first and the learned detectors became a
bounded ranker. New: `pdp_engine.layers`, `AlertPolicy`, detector-1 degree input + seed ensembles, alert
layer/rule/reason columns, layer-1 approvals (console + `POST /api/endpoints/{id}/approved-executables`), learned
daily budget, `pdp_server.tools.add_layers` (upgrade a bundle without retraining), layered views in darpa_eval,
tests/unit/test_layers.py and new stack e2e checks.

## Status (2026-11-03, agent/server 0.2)

Moved to the GPU host (NVIDIA L40S 46 GB, Ubuntu 26.04, kernel 7.0). Changes this round:

* **eBPF collector rewritten and validated on a stock kernel**: ring buffer (global order, so a child's exec never
  precedes its fork), raw `sys_enter`/`sys_exit` dispatch (the per-syscall `sys_enter_*` tracepoints fire for only a
  fraction of calls under BPF on kernel 7.0), `sched_process_exec` for execs with argv, in-kernel thread filtering,
  IPv6 and send/recv/accept addresses, process exit, fd duplication, chroot-aware symlink resolution. Shares its mapping with the
  strace collector (`sources/common.py`); cross-checked against strace (docs/SANDBOX.md). Whole-host run: ~70k
  events in 90 s at ~6 % of one CPU, 460 MB RSS.
* **Baseline completion for live collectors** (ebpf/strace/etw never declared their days, so such endpoints never
  trained); idle hosts complete a day by the wall clock. Day order no longer depends on set iteration order.
* **Agent/server node ids** derived from the agent's registry order (see Telemetry notes).
* Agent image (Ubuntu 24.04, CPU torch 2.4; CO-RE eBPF loader since 0.3.1) runs every collector; idempotent enrolment with CA pinning; full
  heartbeat; acknowledged commands; window length from the bundle; tz from the server config.
* Server: users/roles management, password change, retire endpoint, agent commands, config validation, `/healthz`,
  CSV/NDJSON alert export and a SOC exporter (syslog CEF / webhook), generated DB secret, serialised multi-worker
  start-up (PKI + DDL under an advisory lock), job heartbeats + recovery of jobs of a dead worker, full TLS chain.
* Console: users, account, health columns, enrol command with fingerprint, retire / re-fetch, export, filters.
  Desktop: certificate pinning fixed (it hashed the leaf's PEM text, so a CA pin never matched).
* Alerting: an explicit float-safe margin above the validation-max threshold (`ALERT_MARGIN`), so behaviour identical
  to the benign validation maximum cannot alert on rounding (it did, reproducibly, on the eBPF sandbox).
* Tests: unit tests for the agent logic and the new eBPF decoder, an end-to-end test of the running stack through
  the gateway (41 checks), the collector cross-check.

Done on 2026-11-04 (0.3 hardening round; docs/DEPLOYMENT.md):
* Source under git (`main`).
* Signing keys in a KMS: agent CA (pki engine) and bundle-signing key (transit) in OpenBao/Vault, sign-only service
  token, audit log, key id in every bundle signature; existing keys imported, so enrolled agents are unaffected.
* SSO (OIDC code + PKCE) with IdP group -> role mapping, allow-listed egress proxy for the offline backend, sessions
  re-checked per request, sign-in back-off, password policy (enabled / admin-only / disabled).
* libbpf CO-RE eBPF collector (agent 0.3.1): no kernel headers, compiler or tracefs on endpoints; 16 MB ring buffer;
  dropped-event counter in the heartbeat; dirfd-path race fixed; path-resolution cache.
* Release CI (`.github/workflows`): desktop installers on macOS / Windows / Linux runners with optional signing and
  notarisation, agent .deb/.rpm, images, SHA256SUMS. Built and checked locally for Linux only; the hosted
  workflow has not run (no remote yet).
* Field validation started: the agent runs as a systemd service on this host (endpoint `l40s-host`).

Still open: Windows ETW on a Windows host; macOS/Windows installer builds and signing on real runners; PIDSMaker
parity tests (need PIDSMaker's trained artifacts); console certificate from the customer's CA / ACME; backups.
