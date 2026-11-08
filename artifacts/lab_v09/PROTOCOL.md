# Lab 0.8.1: the corroboration false-positive storm (written before any variant was scored)

## Problem (diagnosis on seen data, 2026-11-08)
0.7 released (production) produced 4,751 false positives on the 0.8 held-out hosts against 488 for 0.6, with the same
attacks found. `anat9.py` on the 0.7 released bundles (these hosts are seen data from now on):

- CARBANAKv2 h1: 3,511 corroborated alerts, 0 true. 3,478 sit next to ONE layer-1 alert (`poqexec.exe`, Windows Update
  servicing, writing ~3,500 `winsxs` files). 3,476 of the corroborated nodes were above the threshold only through
  propagation inside the window - suspicion that flowed to them from the alert they then "corroborated". Circular evidence.
- CARBANAKv2 h5: 152 corroborated (9 true). learned_near_alert: 36 false via propagation, 31 false + 2 true on their own
  score. novel_executable_repeat (repeat runs of a new program, evidence rule): 70 false + 6 true on their own score,
  48 of the false ones are repeat runs of one program (configure-smremoting.exe).

## Variants (runtime alert policy only; same bundles, same code path as the agent)
- **R**  0.7 released as is (reproduced as the reference).
- **A**  `learned_near_alert` uses the neighbour's own score in the window (detector-1/2 fusion and detector-3, before
  propagation) instead of the propagated score. Evidence-rule corroboration (repeats, tainted rules) is unchanged:
  there the flagged node itself is the subject, and suspicion flowing to it from its parents is real corroboration.
- **B**  A + a repeat run of a new program corroborates at most 3 times per program per UTC day (the first runs already
  alerted through layer 1; more instances of the same program are the same finding).

## Sets
Development / seen: the 10 lab sets of lab_v08 (CADETS, THEIA, OpTC H201/H501/H051, ClearScope E3, FiveDirections,
ATLASv2 h1/h2, TRACE) + the 6 hosts of the 0.8 held-out run (CARBANAKv2 h1-h5, THEIA E5), all seen.
Held-out (fresh, never scored by any detector): CLEARSCOPE_E5 (split fixed in artifacts/heldout_v08/PREP_LOG.md
before any survey: train 05-08..05-12, val 05-13, test 05-14, 05-15, 05-17; PIDSMaker ground truth). CADETS_E5 is not
used: the remaining 23.5 GB download would take free disk below the 25 GB floor.

## Acceptance (development / seen, all 16 sets)
1. No attack lost: attacks found >= R on every set.
2. Total false positives lower than R.
3. Mean ground-truth node recall over the sets >= 0.9 x R's.
Choice: B if it passes and has at least 15 % fewer false positives than A in total; else A if it passes; else no change.

## Held-out decision (run once, after the choice is committed)
Release if, on CLEARSCOPE_E5, the chosen variant finds at least as many attacks as R with no more false positives.
Results are reported for R, A and B regardless.

## Decision record (development / seen, 16 sets, before any held-out run)
| | attacks | TP | FP (per day, 71 days) | precision | mean node recall |
|---|---|---|---|---|---|
| R (0.7 released) | 26 of 30 | 347 | 5,670 (79.9) | 0.058 | 0.294 |
| A (own score next to alerts) | 26 of 30 | 344 | 2,034 (28.6) | 0.145 | 0.291 |
| B (A + 3 repeat corroborations) | 26 of 30 | 342 | 1,986 (28.0) | 0.147 | 0.288 |

A and B pass all three rules (no attack lost on any set; fewer FP; recall 0.291 / 0.288 >= 0.264). B has 2.4 %
fewer false positives than A, below the 15 % margin: **A is chosen** (runtime NEAR_ALERT_SCORE = "own",
REPEAT_CORROBORATIONS = 0). CARBANAKv2 h1: 3,756 -> 285 false positives (corroborated 3,511 -> 40).
Per-set results: res9-*.json (summ9.py). Held-out (CLEARSCOPE_E5) pending: data prepared up to conversion,
which waits for disk (artifacts/heldout_v09/PREP_LOG.md).

# 0.9: false positives of 0.8.1 (user request 2026-11-08 "make the best version much better, fix false positives")

## Exploration grid 1 (seen data, eval10.py, res10-*.json): learned-only alerts are 0.6 % precise (779 alerts, 5 true)
| variant | attacks | TP | FP | note |
|---|---|---|---|---|
| A (0.8.1) | 26/30 | 344 | 2,034 | |
| L0 no learned-only alerts | 26/30 | 339 | 1,264 | |
| L5 learned budget 5/day | 26/30 | 342 | 1,495 | |
| F2 learned-only above 2x threshold | 26/30 | 340 | 1,442 | |
| F3 learned-only above 3x threshold | **27/30** | 340 | 1,292 | budget no longer spent on weak anomalies: ClearScope E3 attack found |
| C2 / L0C2 / L0C15 corroboration at 2x / 1.5x | 22-23/30 | | 1,050-1,830 | lose ATLASv2 h1 attacks: rejected |

Remaining false positives analysed (dump10-*): corroborated repeat runs of new programs 144 false / 13 true (one program
48 times); rule-layer false positives are mostly other instances of programs the ground truth labels as attack.

## Grid 2 (pre-registered before it runs)
Variants: F3, F3R1 (F3 + 1 corroborated repeat run per program per day), F3R3, F4, F5, F3B10 (F3 + budget 10), L0R1.
Choice: among variants that lose no attack found by A on any set and keep mean node recall >= 0.9 x A's, the one with
the fewest false positives; within 5 % of that, the one with fewer settings changed from 0.8.1.
Held-out: CLEARSCOPE_E5 once (pending disk) - release rule: attacks >= 0.8.1's and FP <= 0.8.1's.

## Grid 2 result and decision (before any held-out run)
| variant | attacks | TP | FP (per day) | precision | node recall | eligible |
|---|---|---|---|---|---|---|
| A (0.8.1) | 26/30 | 344 | 2,034 (28.6) | 0.145 | 0.291 | ref |
| F3 | 27/30 | 340 | 1,292 (18.2) | 0.208 | 0.290 | yes |
| F3R1 | 27/30 | 338 | 1,217 (17.1) | 0.217 | 0.287 | yes |
| F3R3 | 27/30 | 339 | 1,241 (17.5) | 0.215 | 0.287 | yes |
| F4 / F5 | 26/30 | 339 | 1,287 (18.1) | 0.208 | 0.288 | yes |
| F3B10 | 26/30 | 339 | 1,279 (18.0) | 0.210 | 0.288 | yes |
| **L0R1** | 26/30 | 337 | **1,189 (16.7)** | 0.221 | 0.285 | yes |

**Chosen: L0R1** (fewest false positives; F3R1 / F3R3 are within 5 % but change as many settings). Noted: F3R1 also
finds the ClearScope E3 attack (27/30) for 28 more false positives; the pre-registered rule does not reward that.
Product defaults: runtime LEARNED_DAILY_BUDGET = 0 (bundles before 0.9 included; learned_policy.policy = "0.9" bundles
keep their own; an endpoint setting overrides), REPEAT_CORROBORATIONS = 1; TrainConfig learned_daily_budget 0,
repeat_corroborations 1. Verified end to end: the runtime with defaults only on the 0.7 released bundles reproduces
L0R1 exactly on all 16 sets (res12-*.json). 0.7 released -> 0.9 on the same sets: false positives 5,670 -> 1,189
(-79 %), attacks 26 -> 26, precision 0.058 -> 0.221.
