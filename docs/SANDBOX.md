# Live sandbox (phase 5)

The sandbox proves the detectors on **live kernel telemetry** rather than a replayed database. It is an ordinary
`live` endpoint: enrol, upload a benign baseline, server-side train and sign a bundle, local scoring on the agent.
The only difference from a production endpoint is that the workload and its day labels are scripted so a full
baseline-train-detect cycle runs in minutes.

## Collector

`agent/pdp_agent/sources/strace_src.py` is a portable live collector built on `strace` (ptrace). It is used where
the kernel audit netlink is unavailable (containers, WSL2) and the eBPF toolchain is not installed. strace runs
with `-ff -o`, one file per process (`t.<pid>`); the collector tails each file, stitches `<unfinished>/<resumed>`
blocking calls, and emits the same normalised `Entity`/`Event` stream as the auditd collector, with the same
syscall set (execve/open/connect/clone family — file reads and writes are inferred from the open mode, not traced).
A production **eBPF** (libbpf CO-RE) collector is the intended high-volume front-end and is a drop-in for the same
stream. Requirements: `strace` on the host and `CAP_SYS_PTRACE`.

Sources: `kind: "strace"` (trace one command) or `kind: "sandbox"` (the scheduled benign+attack scenario driver).
The sandbox captures each session with strace (default) or with the production eBPF collector (`"collector": "ebpf"`, optional
`"engine": "core"` (default) or `"bcc"`, compose service `agent-sandbox-ebpf`): one kernel program for all sessions, events filtered to the workload's process
tree.

## Scenarios

`sim/pdp_sim/sandbox/workloads.py` runs **harmless** programs that reproduce DARPA provenance *shapes* with real
syscalls in a throwaway directory. Benign: `build`, `web`, `admin`, `user`. Attack-shaped: `dropper`
(write a new executable then run it, which calls out), `backdoor` (service spawns a shell that reads sensitive
files and opens a channel), `exfil` (stage files into an archive then send), `lotl` (trusted-tool recon then a
beacon). "External" connections target RFC 5737 TEST-NET addresses with a short timeout, so nothing leaves the host.

## Run (scripted)

```
DC="docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.gpu.yml -f deploy/docker-compose.bench.yml --env-file deploy/.env"
T=$(docker exec pdp-api-1 python -m pdp_server.tools.token --name sandbox-ebpf --config '{"baseline_days": 3}')
PDP_SANDBOX_EBPF_TOKEN=$(echo $T | jq -r .token) PDP_CA_SHA256=$(echo $T | jq -r .ca_sha256) $DC --profile sandbox-ebpf up -d agent-sandbox-ebpf
docker exec pdp-api-1 python -m pdp_server.tools.sandbox_eval --endpoint <endpoint-id>
```
(`--profile sandbox` / `PDP_SANDBOX_TOKEN` / `agent-sandbox` for the strace variant.) The whole cycle — 3 baseline
days + validation day, GPU training, signed bundle, live scoring of the attack day — takes about a minute.

## Run (manual)

```
TOK=$(openssl rand -hex 24)
# create a live enrolment token named sandbox-live, then:
PDP_SANDBOX_TOKEN=$TOK docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.gpu.yml \
  -f deploy/docker-compose.bench.yml --env-file deploy/.env --profile sandbox up -d agent-sandbox
# set the server-side baseline length to match the sandbox schedule (3):
#   UPDATE endpoints SET config = config || '{"baseline_days":3}' WHERE name='sandbox-live';
python -m pdp_server.tools.sandbox_eval --endpoint <endpoint-id>
```

The agent uploads 3 benign days + a validation day, the server trains and publishes a bundle, the agent installs it
and then the test day's attack scenarios are scored live. `sandbox_eval` classifies the reported alerts into attack
indicators (the dropped payload, recon shell, external C2) and benign-window false positives. See
`artifacts/platform_bench/results/RESULTS.md` (phase 5) for the recorded run: dropper and backdoor detected, exfil
and living-off-the-land missed, zero benign-window false positives — the same pattern as the DARPA replays.

Config knobs (`source` in the agent config): `baseline_days`, `sessions_per_day`, `scale`, `base_date`, `benign`,
`test_days` (each `{benign:[...], attacks:[...]}`), `seed`.

## Results on the L40S host (kernel 7.0, 2026-11-03)

Both collectors, same schedule (3 benign baseline days + validation day; test day = benign cover traffic + the four
attack-shaped scenarios), GPU training (~5 s per endpoint, detector-1 + 3 detector-2 seeds):

| collector | baseline events | dropper | backdoor | exfil | lotl | benign-window false positives |
|---|---|---|---|---|---|---|
| strace | 9,754 | detected (3.1x) | detected (3.2x) | detected (3.1x) | missed | 0 |
| eBPF   | 9,754 | detected (2.0x) | detected (2.1x) | detected (2.0x) | missed | 0 |

(x = fused score / alert threshold.) The collectors produce the same telemetry: `pdp_agent.tools.crosscheck` gives
identical edge counts on all eight scenarios and identical (op, src label, dst label) edge sets on all of them except
for the pid inside `/proc/<pid>/maps`, which differs between any two runs. The score levels differ between the two
endpoints because each training run is separate (GPU scatter operations are not bit-deterministic).

Before the alert margin (`pdp_engine.scoring.ALERT_MARGIN`) was introduced, the eBPF endpoint reproducibly raised one
alert on a benign `cp` in the test day's build session at 1.000x threshold (+5e-7): the test day repeats the
validation day's build workload, whose node *is* the threshold, and float32 rounding decided the tie. A node that
behaves exactly like the benign validation maximum now never alerts. Living-off-the-land remains the miss, as in the
DARPA replays: trusted binaries doing ordinary things.

Simulation on an eBPF endpoint's bundle (144 runs, all 7 synthetic families + the 5 DARPA transplants, evasion
none/medium/high/stealth, GPU, 12.5 s): 100 % detected (Wilson 95 % CI 0.97-1.00), 0 false positives per
endpoint-day on the clean pass. The sandbox baseline is tiny (four short synthetic days), so almost any unseen
behaviour is anomalous here; these numbers validate the pipeline, not real-world detection rates — use DARPA
benchmark endpoints or a real baseline week for those.
