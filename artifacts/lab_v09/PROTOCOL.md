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
