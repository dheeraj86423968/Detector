# 0.8 lab protocol (written 2026-11-08, before any end-to-end 0.8 result and before any held-out data exists)

## Goal (user request, 2026-11-08)
"Implement the process-chain scoring so we can drop the rule; get and test on clean test data after this."
The rule = layer 1 ("new executable"), kept in 0.7 only because on TRACE it was the only layer that caught the
attacks. 0.8 must catch what it caught with the learned layer, with layer 1 off.

## What was looked at before this protocol (development, all on seen data)
Offline, detector-3 alone (dumps of the released 0.7 bundles, lab8 chain8/chainall/horizon8): one maximum per
process vs evidence summed over a process's kinds of activity ("breadth", capped, floored) vs lineage sums along the
process tree. On all 10 dev/seen sets at a 10-benign-validation-node threshold: max 19/34 attacks, 138.6 FP/day mean;
breadth (4 groups, cap 10, floor 4) 24/34, 50.6; lineage sums added false positives everywhere (rejected);
per-endpoint normalised caps were worse than caps in nats; time horizon (15 min .. whole period) changed little
(4 h chosen to bound accumulation on long-lived processes).

## Data
- Development / seen (all tuning happens here): CADETS_E3, THEIA_E3, OPTC_H201, OPTC_H501, OPTC_H051, CLEARSCOPE_E3,
  FIVEDIRECTIONS_E3, ATLASV2_EDR h1 / h2, TRACE_E3.
- Held-out (never looked at by this project; prepared by a separate agent that runs no detector, in parallel with
  this development): CARBANAKV2_EDR (per host), THEIA_E5, CADETS_E5, CLEARSCOPE_E5 - whichever could be prepared.
  Scored once, after the 0.8 configuration is frozen and committed. No re-tuning afterwards.

## Systems compared (end to end: bundle upgraded by the product trainer, test days streamed through the runtime)
- 0.8 candidate: TrainConfig defaults of the candidate (detector-3 breadth on, layer 1 off).
- 0.7 released: detector-3 max, layer 1 on, corroboration at the learned threshold (the production configuration).
- 0.6 (held-out only, as in earlier rounds): the 0.6-configured bundle.
Same source bundles (detectors 1-2) for all, so differences are the configuration.

## Metrics (node level, PIDSMaker/orthrus ground truth, test days)
Attacks detected (>= 1 ground-truth node alerted), ground-truth node recall, false-positive nodes per test day.

## Acceptance rule for 0.8 (decided now), on the 10 development / seen sets, versus 0.7 released
1. Attacks detected >= 0.7 released on every set (TRACE: 3 of 3, without layer 1).
2. False positives per day: mean over the 10 sets <= 0.7 released's mean (41.2 per day on the 10 sets: the
   released-configuration numbers in docs/DETECTION_LAYERS.md 0.7).
3. Ground-truth node recall: mean over the 9 sets with ground truth (not ATLASv2 h2) >= 0.7 released's (0.306).
If no candidate meets 1-3, layer 1 stays and the findings are reported.

## Held-out decision rule (decided now)
After the single held-out run: 0.8 goes to production if, summed over the held-out hosts, it detects at least as
many attacks as 0.7 released with no more than 1.5x its false positives; otherwise 0.7 stays and the result is
reported. Either way all three systems' held-out numbers are reported as they come out.

## Honesty rules
Development/seen and held-out numbers are reported separately. Held-out data is touched once. Nothing here supports
"replaces an EDR" beyond what these benchmark numbers show.

## Decision record (2026-11-08, written before any held-out data was scored)

End to end on the 10 development / seen sets (prod08.py: product trainer upgrade + runtime, streaming; same source
bundles; 0.7 released re-run through the same harness reproduces the published numbers exactly):

| set | 0.7 released (layer 1 on) TP / FP (per day) / attacks | 0.8 (v08b, layer 1 off) TP / FP / attacks |
|---|---|---|
| CADETS | 32 / 42 (10.5) / 3 of 3 | 33 / 29 (7.2) / 3 of 3 |
| THEIA | 111 / 127 (42.3) / 2 of 2 | 109 / 129 (43.0) / 2 of 2 |
| OpTC H201 | 7 / 42 (14.0) / 1 of 1 | 8 / 8 (2.7) / 1 of 1 |
| OpTC H501 | 19 / 132 (44.0) / 1 of 1 | 12 / 24 (8.0) / 1 of 1 |
| OpTC H051 | 76 / 58 (19.3) / 1 of 1 | 69 / 41 (13.7) / 1 of 1 |
| ClearScope | 0 / 51 (25.5) / 0 of 1 | 0 / 41 (20.5) / 0 of 1 |
| FiveDirections | 11 / 225 (75.0) / 2 of 2 | 4 / 40 (13.3) / 2 of 2 |
| ATLASv2 h1 | 14 / 125 (125) / 8 of 10 | 10 / 111 (111) / 8 of 10 |
| ATLASv2 h2 (no labelled attack) | 0 / 36 (36) | 0 / 68 (68) |
| TRACE | 9 / 81 (20.2) / 3 of 3 (layer 1) | 4 / 39 (9.8) / 3 of 3 (learned) |
| **mean** | 21 of 34 attacks, 41.2 FP/day, recall 0.306 | 21 of 34 attacks, 29.7 FP/day, recall 0.266 |

Acceptance: rule 1 met (same attacks on every set; TRACE 3 of 3 without layer 1); rule 2 met (29.7 vs 41.2 FP/day);
**rule 3 NOT met** (ground-truth node recall 0.266 vs 0.306). The lost nodes are the attack's new executables that
layer 1 alerted one by one (TRACE 9 vs 4) and nodes corroborated next to those alerts (FiveDirections 11 vs 4,
ATLASv2 h1 14 vs 10, OpTC H501/H051). One variant was tried for it: corroboration at the 99.9th validation percentile
(v08c): recall 0.276, FP/day 33.9 - still below 0.306. ATLASv2 h2 gets more false positives (68 vs 36; 12 of them
are payload.exe processes of the multi-host attack, unlabelled on h2 by the ground truth).

Frozen candidate: v08b = TrainConfig defaults in this commit (detector-3 breadth: 4 activity groups, cap 10 nats,
floor 4 nats, horizon 4 h; layer 1 off; corroboration at the learned threshold; final threshold floored at 1).
Per this protocol layer 1 would stay, since rule 3 failed; dropping it anyway is a deviation that the user decides,
with the held-out results (0.6, 0.7 released, 0.8 all scored once) in hand.

## Held-out result (2026-11-08, scored once; heldout08.py / heldout08.sh, configuration frozen in 55c5eb8)

CARBANAKV2_EDR h1-h5 (Windows, Carbon Black EDR) and THEIA_E5 (Linux) - prepared by a separate agent that ran no
detector (artifacts/heldout_v08/PREP_LOG.md); CADETS_E5 and CLEARSCOPE_E5 could not be downloaded (Google Drive
quota). Per host: a 0.6-configured bundle trained on the baseline, upgraded with the product trainer to 0.7 released
and to 0.8; the test days scored by the runtime.

| host (test days) | 0.6: attacks / TP / FP | 0.7 released | 0.8 |
|---|---|---|---|
| CARBANAKv2 h1 (8) | 1 / 5 / 85 | 1 / 5 / 3756 | 1 / 3 / 67 |
| CARBANAKv2 h2 (9) | 1 / 40 / 164 | 1 / 40 / 220 | 1 / 29 / 149 |
| CARBANAKv2 h3 (7) | 1 / 1 / 72 | 1 / 2 / 269 | **0** / 0 / 150 |
| CARBANAKv2 h4 (7) | 1 / 3 / 26 | 1 / 3 / 64 | 1 / 1 / 49 |
| CARBANAKv2 h5 (11) | 1 / 9 / 54 | 1 / 18 / 313 | 1 / 2 / 112 |
| THEIA E5 (2) | 0 / 0 / 87 | 0 / 0 / 129 | 0 / 0 / 76 |
| **total** | **5 of 6, 58 TP, 488 FP** | **5 of 6, 68 TP, 4751 FP** | **4 of 6, 35 TP, 603 FP** |

Decision rule: 0.8 needed >= 0.7's attacks (5) with <= 1.5x its false positives. It found 4: **rule failed**; 0.8 is
not released and layer 1 stays (commit 11bcac4: breadth off by default, available per endpoint). On h3 only layer 1
caught the attack; 0.8's learned alerts there (132 in 7 days, all false) ran at the daily budget.

Also seen: 0.7 released - the configuration in production - produced 3,511 corroborated false positives on h1 (3,756
in total, 470 a day), and on these hosts found the same attacks as 0.6 with ten times its false positives. Not tuned
here (this data is now seen); reported to the user for a decision.
