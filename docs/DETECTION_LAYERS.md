# Layered detection (0.3, revised in 0.4 and 0.5)

## 0.5 (2026-11-06): the learned detectors

Layers 1-2 and the alert policy are unchanged; 0.5 changes how detector-1 (Velox) is trained and how the two
learned detectors are fused. Nothing is per dataset or per client: one default for every endpoint, chosen on the
development sets only (protocol, lab scripts and logs: `artifacts/lab_v05/`).

| change | setting (`TrainConfig`) | why |
|---|---|---|
| Detector-1 structural input = the published Velox's reindexer input: per 1024-edge batch a node that both sends and receives gets its features scaled by 1 + 1/k (k = its in-count in the batch) | `velox_input = "batch_scale"` (`models.batch_role_scale`) | Velox has no message passing; the only structure it sees comes from PIDSMaker's GraphReindexer double scatter-mean, which our port had replaced with window degrees. Without any structure detector-1 is useless (CADETS ADP 0.008); window degrees do not reproduce it (0.13); batch_scale does (0.36-0.60) |
| Learning rate 1e-3 (was 1e-4) | `velox_lr` | PIDSMaker's tuned value on 6 of its 8 Velox datasets; >= 1e-4 on THEIA, equal within seed noise on CADETS / H201 |
| The weights of the 3 epochs with the lowest validation loss are averaged | `velox_average_top = 3` | same mean ADP as the single best epoch, worst seed better (0.09 vs 0.04); no inference cost |
| Fusion = max of the two detectors' threshold ratios (was 2:1 weighted mean) | `fusion_mode = "max"` | the stronger detector differs per dataset (CADETS: detector-2, THEIA: detector-1); max has no weight to choose and was best on the development mean (0.65 vs 0.52 for 2:1) |

Detector-2 (ORTHRUS) is unchanged: the 5-seed mean of max-normalised ratios was best or tied among 11 label-free
seed combinations (median, trimmed mean, robust-z, percentile normalisation). Published Velox's CADETS ADP (0.94)
uses test-ADP epoch selection; ours selects by validation loss only, as a product must.

**Compatibility**: 0.5 bundles name detector-1's weights `detector-1-bs-s<k>.npz` and list `requires:
["detector-1:batch_scale", "fusion:max"]` in the manifest. 0.4 agents find no weights they can load and keep their
previous bundle; 0.5.0 agents check `requires` and refuse a bundle that needs a feature they do not know. Older
bundles keep working unchanged in 0.5 agents (window-degree input, weighted fusion). Existing endpoints get 0.5 on
their next retrain, or without detector-2 GPU time:
```
docker exec pdp-worker-train-1 python -m pdp_server.tools.retrain_detector1 --endpoint <id> --bundles <current bundle> --deploy
```
(detector-1 retrained on the bundle's own baseline, detector-2 / layers / policy copied, fusion re-calibrated on the
validation day; about 4-9 min per endpoint on the L40S on the benchmark data).

### Result (5 runs per dataset; details in docs/BENCHMARK_E3.md and docs/BENCHMARK_OPTC.md, "0.5")

Learned-only ranking ADP (node level, mean over runs; 0.4 -> 0.5):

| dataset | detector-1 | fused (learned ranker) | product ADP | alerts (TP / FP) |
|---|---|---|---|---|
| CADETS (dev) | 0.12 -> **0.41** | 0.30 -> **0.83** | 1.00 -> 1.00 | unchanged |
| THEIA (dev) | 0.26 -> **0.98** | 0.71 -> **0.95** | 1.00 -> 1.00 | unchanged |
| H201 (dev) | 0.15 -> 0.18 | 0.13 -> 0.17 | 0.80 -> **1.00** | unchanged |
| H501 (held out) | 0.02 -> 0.07 | 0.02 -> 0.09 | 0.61 -> 0.60 | unchanged |
| H051 (held out) | 0.20 -> **0.03** | 0.18 -> **0.08** | 0.86 -> 0.83 | unchanged |

On DARPA E3 the learned ranker went from weak to good. **The held-out OpTC hosts do not confirm the gain**: H501
improves slightly, H051 gets worse, and their held-out mean is about flat (fused 0.10 -> 0.08, product ADP 0.74 ->
0.72). On Windows OpTC both learned detectors stay close to useless before and after (ADP <= 0.26). Alerts, MCC,
precision and recall are identical on all 25 bundles, because since 0.4 the learned layer only orders alerts within
a severity. H501 / H051 had already been used as held-out sets for 0.4; nothing in this round looked at them before
the single final run.

## 0.4 (2026-11-06): what changed and why

Every change is general (no program names, paths, addresses or dataset names in the detection logic). Each one comes
from a failure seen in the 0.3 benchmarks and is either a bug fix or a change in how alerts are counted and ranked:

| change | setting (layers.json / policy) | the 0.3 failure it fixes |
|---|---|---|
| Program identity: Windows NT and drive spellings, letter case, per-run GUID / hex directories and version directories are one program; a process recorded without a path matches a known program by name | `normalize_programs` | `PING.EXE` vs `ping.exe`, `.../Temp/<GUID>/dismhost.exe`, `taskkill` vs `.../taskkill.exe` alerted as new programs |
| One new-program alert per program per day; later runs are evidence (`novel_executable_repeat`) | `novel_instances: 1` | one new tool run in a loop raised one alert per process: 251 for `PING.EXE` on OpTC H201, 31 for one installer on THEIA |
| Windows paths with spaces read in full | `full_paths` | the process label separates path and command line by a space, so every program under `C:\Program Files` was the one program `.../Program` (1,902 of 60,275 processes on H201): layer 1 could never flag a new program there |
| Windows paths in their real folders; Windows credential stores are sensitive | `full_paths` | `tainted_modify` keys were all `@ /Device/HarddiskVolume1`; only Linux credential stores were known |
| Multicast and limited broadcast are local traffic | `local_multicast` | IPv6 neighbour discovery (`ff02::1:ff..`), LLMNR (`224.0.0.252`), mDNS and SSDP were untrusted remote sources: every Windows process receiving them was tainted (23,476 and 38,074 benign `tainted_modify` events on H201 / H051 baselines) |
| A process started from a file written with untrusted content counts as executing it | `image_exec` | collectors without an EXECUTE event (Windows) never raised `untrusted_exec` |
| The learned layer ranks; it raises no alerts of its own unless the endpoint turns them on | bundle `learned_policy.learned_alerts: false`; endpoint setting `learned_alerts` overrides | corroborated and learned-only alerts were 3-5 % precise on every dataset (e.g. THEIA: 232 alerts, 9 attack nodes) |
| Triage order = the severity the console shows (critical data-flow rules, then untrusted exec / new program with a rule, then the other alerts, then learned-only), ties by the learned score | `pdp_engine.runtime.alert_tier` | 0.3 ranked new-program and rule alerts as one tier ordered by the learned score, so ADP depended on detector noise (THEIA min 0.77) |

Existing bundles keep their 0.3 behaviour until their layers are re-fitted (`tools.add_layers`, seconds per
endpoint, no retraining): the settings change keys and benign thresholds. Agents need 0.4.0 to apply them (0.3
agents ignore the new keys). The learned detectors themselves are unchanged.

**Tried and rejected on the development data**: following an alarmed channel (flagging later traffic between the
alarmed process, or any process, and the alarmed address) added 372-714 false positives on THEIA, where a benign
Firefox exfiltration alarm spread over all its traffic; `novel_instances: 3` and the corroboration variants
(data-flow-forward neighbours only, the fusion threshold instead of the 99.9th percentile, evidence rules only,
no learned-only budget) were all below ranking-only on MCC on all three development sets.

### How it was evaluated

Protocol fixed before any change was tried (artifacts/lab_v04/PROTOCOL.md, with the lab scripts and outputs): development sets CADETS E3, THEIA E3 and
OpTC H201 (per-node inspection allowed); OpTC H501 and H051 held out, run once after the configuration was frozen.
Their 0.3 aggregate results were already known (docs/BENCHMARK_OPTC.md). All numbers re-use the 25 trained bundles of
the published 0.3 results (5 per dataset), so the differences come from the changes, not from retraining. A
label-free check on the baseline days of all five datasets (leave-one-day-out) points the same way: new-program
alarms on benign days fall 30-80 % (CADETS 54 -> 18, THEIA 293 -> 61, H201 32 -> 21, H501 35 -> 19, H051 17 -> 11).

Results: docs/BENCHMARK_E3.md and docs/BENCHMARK_OPTC.md, "0.4".

## Background (0.3)

Why: the 0.2 product alerted on one signal, the fused score of two learned detectors (Velox, ORTHRUS) above the
maximum benign validation score. On DARPA E3 that was not reliable (docs/BENCHMARK_E3.md): across five training runs
detector-2 alone ranged from ADP 0.09 to 1.00 on THEIA, one run produced 25,378 false positives, and detector-1
detected nothing on CADETS. The literature reaches the same conclusion under honest protocols:

* Bilot et al. (USENIX Security 2025) re-ran 8 PIDS - all unstable across training runs.
* Moon et al. (arXiv 2609.33532, preprint) - checkpoint selection on test labels inflates published ADP by
  0.16-0.33; ORTHRUS re-sets its threshold from unlabelled test scores; the original Velox gets degree-dependent
  inputs through a reindexer buffer-reuse defect.
* Guerra et al. (NDSS 2027) - an executable-novelty allowlist matches or exceeds the learned baselines on key
  operating-point metrics.
* Xiao et al. (industrial evaluation) - learned PIDS lose 27-38 % AUC across hosts and platforms.

0.3 therefore puts deterministic, explainable layers first and keeps the learned detectors as a ranker whose
false-positive volume is bounded by construction.

## The three layers

Code: `engine/pdp_engine/layers.py` (layers 1-2), `engine/pdp_engine/runtime.py` (`AlertPolicy`),
`engine/pdp_engine/models.py` (`batch_role_scale`, `window_degrees`), `engine/pdp_engine/trainer.py`.

### Layer 1 - executable novelty

A process alerts when its program (exe path; the process name when the collector records no path, as DARPA CADETS)
never ran during the baseline (training + validation days) and has not been approved since. Deterministic, one alert
per process. **Approvals**: Console -> alert -> "Approve program", or Endpoint -> Detection layers; the list is part
of the endpoint configuration (`approved_executables`), the agent applies it on its next poll without a new bundle,
and open novelty alerts for that program are resolved as false positives. Blind spot: attacks that use only programs
the host already runs (living off the land, masquerading under an existing path) - layer 2 covers those.

### Layer 2 - information-flow tags with benign-calibrated alarms

After Morse (tag propagation with attenuation and decay) and CAPTAIN (NDSS 2025: tag initialisation, propagation and
alarm thresholds adapted to benign data). This is a compact re-implementation in that spirit, not a port of either
system. Tags are propagated along the data-flow edges of the stream in time order:

| node | tag | initial value / propagation |
|---|---|---|
| netflow | integrity | 1 if the remote address is local or was contacted during the baseline, else 0 |
| file | integrity | 1 (pre-existing content); lowered to the writer's integrity on WRITE |
| file | confidentiality | 1 for credential / secret stores (`/etc/shadow`, `~/.ssh/`, shell history, browser logins, ...) |
| process | code integrity | integrity of the executed file; inherited on fork without exec |
| process | data integrity | min of the data it consumed (+0.2 per file hop), recovers with a 1 h half-life; inherited on fork |
| process | confidentiality | max of the data it read (-0.25 per write hop) |

| alarm | fires when | role in 0.3 |
|---|---|---|
| `untrusted_exec` | a file with untrusted content is executed | alarm |
| `untrusted_code_network` | a program loaded from an untrusted file talks to an untrusted address | alarm |
| `exfiltration` | a process that read sensitive data sends to an untrusted address | alarm |
| `tainted_spawn` | a process holding untrusted data starts a program | evidence (see below) |
| `tainted_modify` | a process with untrusted code/data writes a named file that existed in the baseline | evidence |

**Benign calibration** (`fit_layers`): the engine replays the baseline days; every (alarm, key) that fires there -
key = program, parent -> program, or program @ target directory - gets its own threshold just below the lowest tag
value it reached on benign data (margin 0.05). A benign routine stays quiet; the same alarm with a key never seen in
the baseline, or a strictly more untrusted value, still fires. The calibration replay is *leave-one-day-out*: an
address is trusted on a day only if it also occurs on another baseline day, and a file is pre-existing only if it was
seen on an earlier day - otherwise every baseline address is trusted in hindsight and no benign alarm is ever
observed (this was the first version's flaw, caught by the label-free validation-day check). Fitting takes ~4 s on
DARPA E3. Both collector layouts are handled: DARPA's one node per process (fork, then EXECUTE into the same node) and
the live collectors' one node per exec image (EXECUTE into the new image, then CLONE from the old one).

### Layer 3 - learned ranker (Velox + ORTHRUS), fixed

* **Detector-1 structural input** (0.5: `models.batch_role_scale`, `velox_input = "batch_scale"`): per 1024-edge
  batch, a node that both sends and receives has its features scaled by 1 + 1/k (k = in-count in the batch) - the
  input the published Velox gets from PIDSMaker's reindexer. 0.3-0.4 used `models.window_degrees` (log1p of each
  node's out-/in-degree and distinct successors / predecessors appended to the features), which old bundles keep.
  Per-edge-type counts are deliberately excluded - they would contain the label being predicted. 0.5 also trains
  detector-1 at lr 1e-3 and averages the weights of its 3 lowest-validation-loss epochs.
* **Fusion** (0.5: `fusion_mode = "max"`): the fused score is the max of the two detectors' threshold ratios;
  0.2-0.4 bundles use the 2:1 weighted mean, recorded as `calibration.fusion.mode`.
* **Seed ensembles**: detector-1 averages 3 seeds, detector-2 averages 5 seeds (`orthrus_aggregate = "mean"`; 0.2
  kept only the seed with the lowest validation loss, which keeps all of that seed's variance).
* **Bounded alerting** (`AlertPolicy`): the fused score alerts on its own only
  - as **corroborated** - a node marked by an evidence rule, or a window neighbour of a layer-1/2 alert, whose score
    is above the validation-day 99.9th percentile of fused scores; or
  - as **learned** - above the fusion threshold, at most `learned_daily_budget` (default 20) per UTC day, highest
    first. A false-positive storm like the 25,378-node THEIA run is capped at 20 alerts a day.
  - With the endpoint setting `learned_alerts: false` the learned layer raises no alerts at all and only orders them
    (deterministic mode; on DARPA E3 this is the higher-MCC operating point, see the results below).
* Every alert carries its layer, rule and an analyst-facing reason (`alerts.layer/rule/reason/reasons`); the SIEM
  exporter maps deterministic detections to high severity (rules >= 8, novelty/corroborated >= 7).

## Pre-registration and the one revision

All layer parameters above were fixed before any test-day evaluation. The first test-day run of layers 1-2 (CPU,
deterministic) showed two rules - `tainted_modify` (THEIA: 1013 nodes, 2 true) and `tainted_spawn` (221 nodes, 13
true) - flagging long-lived processes that had ever received untrusted data, the dependency explosion Morse and
CAPTAIN describe. They were then made **evidence** (alert only when the learned score corroborates). This revision
was decided after seeing test-set results, so it is optimistic on DARPA E3: every evaluation reports the
pre-registered policy (all five rules alarm on their own) next to the revised one, computed on the same learned
scores, and the revised policy is checked on independent data (the live client suite, which played no part in the
decision). Results: docs/BENCHMARK_E3.md, "0.3 layered detection". In short (5 runs per dataset, mean):

| | CADETS MCC | CADETS ADP | THEIA MCC | THEIA ADP | attacks | client suite |
|---|---|---|---|---|---|---|
| 0.3 layered product | 0.41 | 0.99 (min 0.98) | 0.45 | 0.91 (min 0.77) | all, every run | 58/64, no layer-1/2 FP |
| layers 1+2 only | 0.42 | – | 0.61 | – | all | |
| 0.2 best configuration | 0.17 | 0.57 (min 0.06) | 0.14 | 0.87 (min 0.61) | | 43/64 |
| best published (Bilot et al.) | – | 0.94 (min 0.85) | – | 0.72 (min 0.42) | | |

The learned layer's alerts add mostly false positives (on THEIA ~280 false for ~9 true); run it ranking-only
with the endpoint setting `learned_alerts: false` where precision matters more than the last few percent of recall.

## Upgrading endpoints

Bundles trained by 0.3 contain `layers.json` and a `learned_policy`. Pre-0.3 bundles keep alerting exactly as before
(fused score above threshold) until upgraded - retrain, or add the layers to the current bundle in seconds:
```
docker exec pdp-worker-train-1 python -m pdp_server.tools.add_layers --endpoint <id> --deploy
```
Agents must be 0.3 to load a bundle *trained* by 0.3 (detector-1's input width and seed files changed; an older
agent refuses it at load time and keeps its previous bundle). A pre-0.3 bundle upgraded with `add_layers` loads in an
old agent but is scored without the layers - upgrade the agent first.

Agents must be 0.5.0 to load a bundle trained (or upgraded with `retrain_detector1`) by 0.5: detector-1's weight
files are renamed and the manifest's `requires` lists the new features; an older agent keeps its previous bundle.
