# Layered detection (0.3)

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
`engine/pdp_engine/models.py` (`window_degrees`), `engine/pdp_engine/trainer.py`.

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

* **Detector-1 structural input** (`models.window_degrees`): log1p of each node's out-/in-degree and distinct
  successors / predecessors in the window are appended to the node features. The published Velox got
  degree-dependent inputs only through the reindexer defect; our faithful port had none. Per-edge-type counts are
  deliberately excluded - they would contain the label being predicted.
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
