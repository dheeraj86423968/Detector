# Held-out benchmarks

## 0.7 (2026-11-07): DARPA E3 TRACE and ATLASv2 (EDR telemetry)

Three hosts nobody on this project had looked at, prepared by a separate step that ran no detector
(`tools.heldout_prep` for ATLASv2 from its Carbon Black EDR database, `tools.heldout_stream` for TRACE, streamed
from its dump - byte-identical to the normal replay on a sample). Chronological split (train, validation, test).
CARBANAKv2 could not be downloaded (Google Drive quota, 7 attempts). Protocol and decision record:
artifacts/lab_v07/PROTOCOL.md (the 0.7 configuration was frozen and committed, 54386cf, before this run).

| host | platform | train / validation / test days | attacks (ground-truth nodes) |
|---|---|---|---|
| ATLASv2 h1 | Windows (Carbon Black EDR) | 07-15..17 / 07-18 / 07-19 | 10 (48) |
| ATLASv2 h2 | Windows | same | none (false positives only) |
| TRACE | Linux | 04-02..08 / 04-09 / 04-10..13 | 3 (35) |

Per host: one 0.6-configured bundle trained on the baseline (GPU), then upgraded to 0.7 with `upgrade_bundle_07`
(same detectors 1-2, so the comparison isolates the 0.7 changes); test days scored by the runtime. Run once:

| host | 0.6: TP / FP / attacks | 0.7 (as frozen, layer 1 off): TP / FP / attacks |
|---|---|---|
| ATLASv2 h1 | 6 / 46 / 4 of 10 | 11 / 139 / 8 of 10 |
| ATLASv2 h2 | 0 / 26 / - | 0 / 39 / - |
| TRACE | 9 / 69 / 3 of 3 | 0 / 10 / 0 of 3 |

0.7 doubled the attacks found on the Windows EDR host and lost all three on the Linux host, where 0.6 had found them
only through layer 1 (new executable) - which 0.7 had turned off. Diagnosis and the configuration released after it
(layer 1 kept as a safety net, decided by the user; on these hosts, now seen: ATLASv2 h1 8 of 10 with 125 false
positives, h2 36, TRACE 3 of 3 with 81): docs/DETECTION_LAYERS.md "0.7". Results: artifacts/benchmark_heldout/eval-*-v07.json.

## 0.6 (2026-11-06): DARPA E3 ClearScope and FiveDirections

Two DARPA TC E3 datasets this project had never looked at, added so a change can be checked on data it was not
developed on (CADETS, THEIA and OpTC H201 / H501 / H051 have all been used for development by now). Protocol written
before any change or any look at the data: artifacts/lab_v06/PROTOCOL.md. Raw JSON:
`artifacts/benchmark_heldout/eval-{clearscope,fivedirections}-{v05,v06}.json`.

### Data and product cycle

PIDSMaker's databases (`clearscope_e3`, `fivedirections_e3`) and its orthrus ground truth, replayed through the
normal product path (`deploy/bench/run_heldout.sh`: enrolment token, replay agent, baseline upload, GPU training,
signed bundle) with the product **defaults** - no per-dataset settings, what a new client gets. Chronological split
(a product trains, then validates, then detects):

| dataset | platform | train | validation | test | attacks in the ground truth |
|---|---|---|---|---|---|
| ClearScope E3 | Android | 04-03..05, 07..09 | 04-10 | 04-11, 04-12 | Firefox 04-11 (41 nodes) |
| FiveDirections E3 | Windows | 04-04..07 | 04-08 | 04-09..11 | Excel macro 04-09, Firefox 04-11 (108 nodes) |

(PIDSMaker validates these two on a day before training and trains on days after the test days; not possible in a
live product. Its own ground-truth lists leave out the 04-12 attacks of both, which left no malicious nodes.) One
training run per dataset (the other benchmarks use five).

0.5 = the bundle the product trained (0.5 learned detectors, 0.4 layer configuration). 0.6 = the same bundle with
its layers re-fitted under the frozen 0.6 defaults (`tools.add_layers`). Run once each.

### Results

| | product: TP / FP | attacks | MCC | product ADP | learned ranker alone: ADP, attacks |
|---|---|---|---|---|---|
| ClearScope 0.5 | 0 / 0 | 0 / 1 | 0.000 | 0.33 | 0.33, 1 / 1 (1 TP, 138 FP above threshold) |
| ClearScope 0.6 | 0 / 0 | 0 / 1 | 0.000 | 0.33 | same |
| FiveDirections 0.5 | 1 / 43 | 1 / 2 | 0.014 | 0.04 | 0.05, 2 / 2 (9 TP, 229 FP) |
| FiveDirections 0.6 | 1 / 47 | 1 / 2 | 0.014 | 0.04 | same |

**The product does not carry over to these two datasets**, with or without 0.6: one of three attacks is alerted.
0.6 changes nothing on ClearScope and adds 4 false positives on FiveDirections.

Why, label-free (record formats only, looked at after the run):
- ClearScope: every network endpoint has address `0`, there are no exec events, and apps are recorded by package
  name only. Layer 1 has no new program to see and layer 2 no untrusted source - both layers were silent.
- FiveDirections: processes are recorded by name only (no path) and file paths are stored as escaped JSON
  fragments (`{"C:\\\\Program Files\\\\...\\\\tvnserver.exe"}`), which the layers do not recognise as Windows paths
  (no rule fired; new-program alerts were 44 for 1 attack node; the 4 extra in 0.6 are most likely such paths, which
  the stricter program key no longer case-folds).

So the deterministic layers depend on what a collector records - program paths, exec events, remote addresses -
and these two databases lack it or encode it differently. The product's own collectors (eBPF, auditd, ETW) record
all three, but a client whose telemetry is as thin as this would get almost nothing from layers 1-2. Possible
follow-ups, not done here because they would be fitted to this held-out data: normalise these encodings in the
research replay adapter; a per-endpoint "telemetry coverage" check (share of processes with a path, of flows with
an address, exec events present) that warns when layers 1-2 cannot work.
