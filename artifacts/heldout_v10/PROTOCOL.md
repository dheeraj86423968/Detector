# Held-out check: CLEARSCOPE_E5 (0.9 alert policy + 0.10 incident grouping), run once

Written and committed 2026-11-09 before the CLEARSCOPE_E5 conversion finished, i.e. before any detector, model,
Runtime or trainer touched this data. CLEARSCOPE_E5 has never been scored by any version.

Context: 0.10 (= the 0.9 alert policy + fleet prevalence + recurring-incident grouping) was deployed to production on
2026-11-09 at the user's request, before this check. The check decides what we tell the user, and whether we recommend
keeping 0.10 or rolling back to the 0.8 image (`pdp/server:pre-v10-20261109`); rolling back is the user's call.

## Data (fixed in artifacts/heldout_v09/PREP_LOG.md before any survey)
Host `clearscope` (Android). train 2019-05-08..05-12, val 05-13, test 05-14, 05-15, 05-17. Ground truth = the
PIDSMaker list (appstarter_0515, tester_0517). lockwatch_0517 and firefox_0517 are not in that list
(`ground_truth_not_in_pidsmaker_list`): reported separately, never used for the decision.

## Bundle (same pipeline as the 0.8 held-out run, artifacts/lab_v08/heldout08.py, and the lab_v10 sets)
A 0.6-configured bundle trained on the baseline (train days + val day, GPU), upgraded with the product trainer to
0.7 released (`upgrade_bundle_07`, detector-3 max, layer 1 on): the bundle the 0.9/0.10 labs scored every set with.

## Variants (alert policy only, same bundle, same windows, one pass: scripts/heldout10.py)
- **R**   0.7 released: learned daily budget 20, near-alert score "final", no repeat cap.
- **A**   0.8.1: budget 20, near-alert score "own", no repeat cap.
- **N**   0.9 = 0.10's alert policy: budget 0 (no learned-only alerts), "own", repeat corroborations 1.
  0.10's fleet prevalence does nothing on a lone endpoint (no other baselines), so N is also 0.10's alert output.
Incidents (server code, pdp_server.incidents, via lab_v10 inc13.py): N with G0 (0.9: no recurring merge) and G2 (0.10: 7 days);
A with G0.

## Decision rules (fixed now)
1. 0.9 alert policy (lab_v09 release rule): N finds at least as many attacks as A, with no more false positives (node level).
2. 0.10 grouping: N/G2 loses no attack found by N/G0, buries no attack that N/G0 does not bury, and has no more
   false-positive incidents than N/G0.
Both pass -> keep 0.10 in production. Rule 1 fails -> tell the user and recommend rolling back to the 0.8 image. Only rule 2
fails -> recommend setting RECUR_NS to 0 (0.9 grouping). Results for R, A, N and every grouping are reported regardless.
