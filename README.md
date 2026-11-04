# PDP — provenance detection platform

Host-level intrusion detection from kernel telemetry. Endpoints run a small agent that builds a provenance graph
from system calls and scores it locally in three layers - (1) executable novelty against the baseline, (2)
information-flow tag rules calibrated on benign data, (3) two learned detectors (detector-1, detector-2) as a ranker
with bounded alerting (docs/DETECTION_LAYERS.md) - and reports alerts with their layer, reason and provenance context
to an on-premises server. The server trains and calibrates the detectors on
each endpoint's own baseline (GPU), publishes signed model bundles, serves the analyst console, exports alerts to
the SOC and runs randomised adversarial simulations against the deployed detectors.

```
engine/    pdp_engine   graph construction, featurisation, models, scoring, training, runtime (shared by agent + server)
agent/     pdp_agent    collectors (eBPF, strace/ptrace, auditd, Windows ETW, DB replay, sandbox), spool, mTLS transport,
                        local detection, context extraction; tools/crosscheck.py (strace vs eBPF parity)
server/    pdp_server   FastAPI (agent API + console API), Postgres job queue worker (ingest / train / sim), PKI,
                        alert exporter (syslog CEF / webhook), tools (token, bench_eval, sandbox_eval)
console/                React + TypeScript analyst console (Vite); dist/ is served by the gateway
desktop/                Electron desktop wrapper for the console (Windows/macOS/Linux, CA-pinned)
sim/       pdp_sim      adversarial simulation (attack families, DARPA transplants, evasion, campaigns) + sandbox workloads
deploy/                 compose files, nginx gateway, server + agent images, bringup.sh, systemd unit for agents
docs/                   ARCHITECTURE.md, PROTOCOL.md, DEPLOYMENT.md, SIMULATION.md, SANDBOX.md
tests/                  unit (no kernel / server needed), e2e (live stack), parity (vs the research framework)
```

## Quick start (server)

Host: Linux with Docker Engine + compose plugin; for GPU training the NVIDIA driver and the NVIDIA Container Toolkit
(`nvidia-ctk runtime configure --runtime=docker`). Then:

```
./deploy/bringup.sh          # GPU training (./deploy/bringup.sh cpu without a GPU)
```

It generates the database secret into `deploy/.env`, builds the server image, the agent image and the console in
parallel, starts the stack, waits for `/healthz` and prints the first admin password and the CA fingerprint.

* Console: `https://<host>:8443` (ports in `deploy/.env`; self-signed CA at `/dl/ca.pem`). Change the admin password
  under Account; add analysts under Users.
* Agent API: port 9443, mutual TLS.
* Health: `https://<host>:8443/healthz`.

## Enrolling an endpoint

1. Console → Endpoints → Add endpoint → copy the enrol command (token + CA fingerprint), or on the server:
   `docker exec pdp-api-1 python -m pdp_server.tools.token --name web-01`.
2. On the endpoint, run the agent image (eBPF collector) — as a systemd service with `deploy/systemd/pdp-agent.service`,
   or directly (see `bringup.sh` output / `docs/DEPLOYMENT.md`). Natively: `python -m pdp_agent enroll <token>
   --ca-sha256 <fp>` then `python -m pdp_agent run` (config `/etc/pdp/agent.json`).
3. The agent uploads the baseline (7 days + 1 validation day by default), the server trains and publishes a bundle,
   the agent verifies its signature and starts local detection. Alerts, window summaries and heartbeats flow back;
   raw telemetry is not uploaded after the baseline and is deleted on the server once windowed.

## Collectors

All emit the same normalised event stream (`source.kind` in the agent config):

| kind | where | notes |
|---|---|---|
| `ebpf` | production Linux (kernel >= 5.8, headers) | bcc, ring buffer, raw syscall tracepoints; verified against strace on kernel 7.0 |
| `strace` | where eBPF/audit are unavailable (WSL2, locked-down containers) | ptrace, higher overhead |
| `auditd` | hosts that already run auditd | kernel audit log |
| `etw` | Windows | pywintrace; mapping unit-tested, needs validation on a Windows host |
| `db-replay`, `sandbox` | benchmarks | DARPA TC replay; scripted live workloads (strace or eBPF) |

## Benchmarks and sandbox

* `deploy/docker-compose.bench.yml`: live sandbox endpoints (`--profile sandbox` strace, `--profile sandbox-ebpf`
  eBPF) and a whole-host eBPF endpoint (`--profile ebpf-host`). See `docs/SANDBOX.md`; evaluate with
  `python -m pdp_server.tools.sandbox_eval --endpoint <id>`.
* `deploy/docker-compose.research.yml`: DARPA TC replay endpoints (needs the research Postgres on `shared_network`).

## Simulation

Console → Simulation → New campaign (runs on the GPU worker). See `docs/SIMULATION.md`.

## Alert export

`docker compose ... --profile export up -d exporter` with `PDP_EXPORT_SYSLOG=udp|tcp|tls://host:port` (CEF) and/or
`PDP_EXPORT_WEBHOOK=https://...` in `deploy/.env`. Ad-hoc: Alerts → Export CSV / NDJSON.

## Tests

```
# unit (inside the images; no kernel, server or database needed)
docker run --rm -v $PWD:/src:ro -w /src -e PYTHONPATH=/src/engine:/src/agent:/src/sim --entrypoint bash pdp/agent:dev \
  -c 'for t in tests/unit/test_*.py; do python $t | tail -1; done'
# end to end against the running stack (console API + agent protocol through the gateway)
docker run --rm --network pdp_edge -v $PWD:/src:ro -w /src -e PDP_ADMIN_PASSWORD=<pw> \
  -e PYTHONPATH=/src/engine:/src/agent --entrypoint python pdp/agent:dev tests/e2e/stack_e2e.py
# strace vs eBPF collector parity on this kernel
docker run --rm --privileged --pid=host -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro \
  -v /sys/kernel/tracing:/sys/kernel/tracing --entrypoint python pdp/agent:dev -m pdp_agent.tools.crosscheck
# parity with the research framework (needs the research Postgres + PIDSMaker artifacts)
python tests/parity/test_windows_parity.py CADETS_E3 2018-04-06 <nx dir>
```
