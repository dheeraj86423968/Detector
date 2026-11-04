# Client attack-emulation suite

A randomised, harmless re-enactment of common intrusion techniques, for checking that a deployed endpoint detects
attacks — on a customer's own machines, during acceptance testing, after upgrades or retrains. Code:
`sim/pdp_sim/suite/` (scenarios, runner), `server/pdp_server/tools/suite_eval.py` (scoring).

## What it does

16 scenarios across the ATT&CK tactics a host-based detector is expected to see. Each performs real system calls
(fork/exec, file open/read/write, socket connect/send), so the agent records genuine kernel telemetry:

| scenario | tactic | techniques |
|---|---|---|
| web_shell | initial access / persistence | T1190, T1505.003, T1059.004 |
| drop_and_execute | execution | T1105, T1204.002, T1059.004 |
| reverse_shell | execution / C2 | T1059.004, T1071 |
| credential_access | credential access | T1003.008, T1552.004 |
| discovery | discovery | T1082, T1033, T1057, T1049 |
| persistence_cron | persistence | T1053.003 |
| persistence_ssh_key | persistence | T1098.004 |
| staged_exfiltration | collection / exfiltration | T1005, T1074.001, T1560.001, T1041 |
| exfil_dns_tunnel | exfiltration | T1048.003, T1071.004 |
| ransomware | impact | T1486, T1083 |
| lateral_movement | lateral movement | T1021.004, T1570 |
| masquerade_and_cleanup | defense evasion | T1036.005, T1070.004 |
| privesc_discovery | privilege escalation | T1548.001 |
| cryptominer | impact | T1496 |
| ingress_tool_transfer | command and control | T1105 |
| interpreter_beacon | command and control | T1059.006, T1071.001, T1029 |

**Randomness** (seeded; the seed is printed and stored, so a run can be reproduced): process and file names
(including masquerading as system daemons), drop locations, C2 addresses and ports, number of files, which optional
steps run and in what order, beacon counts and jitter; the runner shuffles the scenarios, waits a random time
between them and interleaves benign "cover" activity (builds, editing, log writes, local web requests).

**Safety.** Everything is created, changed and deleted inside a private scratch directory; system files are only
read; "external" connections go to the RFC 5737 TEST-NET ranges (never routed, 0.2 s timeouts, no data leaves the
host); the "ransomware" only encrypts decoy files it generated; the "miner" uses one core for under two seconds;
persistence is written to scratch copies of the cron directory and authorized_keys. It still *looks* like an attack —
tell the customer's SOC before running it on a monitored host.

## Running on a client endpoint

The endpoint must be enrolled and **protected** (baseline trained, bundle installed: Console → Endpoints).
```
# inside the agent image (same host, so the agent traces it) ...
docker run --rm --pid=host -v /tmp:/tmp pdp/agent:dev python -m pdp_sim.suite run --scenarios all --repeat 2 \
    --root /tmp/pdp-suite --manifest /tmp/pdp-suite/manifest.json
# ... or natively with the agent's Python
python -m pdp_sim.suite run --scenarios random:8 --seed 42 --gap-min 30 --gap-max 300
```
Then, after the agent's detection window has closed (>= 20 minutes after the last scenario):
```
docker cp /tmp/pdp-suite/manifest.json pdp-api-1:/tmp/m.json
docker exec pdp-api-1 python -m pdp_server.tools.suite_eval --endpoint <id> --manifest /tmp/m.json --live
```
The report gives detection per scenario and per tactic (with a Wilson 95 % interval), the alerted indicators, time
to alert, and every alert that does not belong to the suite (false positives during the run).

## Running it in the sandbox (whole product cycle in minutes)

`agent-suite` (compose profile `suite`, `deploy/bench/agent-suite.json`) is a live eBPF endpoint: three benign
baseline days and a validation day, GPU training, signed bundle, then two test days, each a randomised campaign of all
16 scenarios twice (different seeds) mixed with benign sessions. Its manifest is written to the agent volume:
```
docker cp pdp-agent-suite-1:/var/lib/pdp/sandbox/suite-manifest.json /tmp/m.json && docker cp /tmp/m.json pdp-api-1:/tmp/m.json
docker exec pdp-api-1 python -m pdp_server.tools.suite_eval --endpoint <id> --manifest /tmp/m.json
```
Results on this host: docs/BENCHMARK_E3.md (0.3: 58/64 detected, no false positives from the deterministic
layers). The report also says which layer caught each run (`detected_by_layer`) and recognises the suite's own recon
commands by its command vocabulary (`suite_command_nodes`), so they are not counted as false positives.

## Graph-level campaigns

For large-scale, statistically powered testing against a deployed bundle without touching the host, use the
simulation harness (Console → Simulation; docs/SIMULATION.md): 7 synthetic families + 5 real DARPA transplants ×
6 evasion levels, randomised per run. A ready-made acceptance spec is `sim/suites/client_acceptance.json` (210 attacks,
all synthetic families x all evasion levels; no seed, so every campaign draws new attacks and the server records the
seed for repetition):
```
curl -b cookies --cacert ca.pem https://<server>:8443/api/sim/campaigns -H 'Content-Type: application/json' \
  -d "{\"name\": \"acceptance\", \"endpoint_id\": \"<id>\", \"spec\": $(cat sim/suites/client_acceptance.json)}"
```
