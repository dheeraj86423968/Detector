# Detector improvement round (0.4) - protocol, fixed 2026-11-06 before any change was tried

Goal: better detection metrics (precision / MCC / ADP, attacks found) without anything specific to one dataset or
client. No program names, paths, addresses or dataset names in detection logic; every parameter is either a
general constant fixed here or learned per endpoint from its own baseline.

Split
- Development (per-node inspection allowed): CADETS_E3, THEIA_E3, OPTC_H201.
- Held out: OPTC_H501, OPTC_H051. Only aggregate metrics, computed once after the changes are frozen.
  Caveat to report: their 0.3 aggregate results are already known (docs/BENCHMARK_OPTC.md).
- Label-free check on all five: alarms raised on benign baseline days (leave-one-day-out), no labels needed.

Measurement
- Same 25 trained bundles as the published 0.3 numbers (5 per dataset), learned scores cached once per bundle; the
  changes are re-run on top of the identical learned scores, so differences are due to the changes, not to retraining.
- Metrics: PIDSMaker node-level TP/FP/precision/recall/MCC, attacks detected, ADP; mean/min/max over the 5 bundles.
- Report 0.3 and 0.4 side by side for every dataset, development and held-out separately.

Acceptance
- A change ships only if it helps (or is neutral) on the development sets on average and does not lose an attack.
- The held-out result is reported as it comes out, good or bad; no further changes after looking at it.

## Frozen 0.4 configuration (2026-11-06 ~06:10, before any held-out run)

Chosen on the development sets (CADETS_E3, THEIA_E3, OPTC_H201; lab results r6/r7-*.json):
- layers: normalize_programs, full_paths, novel_instances=1, image_exec, local_multicast (layers re-fitted on the
  baseline days with these settings)
- policy: learned_alerts=false (the learned layer ranks, it raises no alerts of its own)
- ranking: severity tier (as the console grades incidents), ties by the fused learned score

Rejected on development data: follow_channels actor/address (THEIA +372 / +714 false positives, 0 true),
novel_instances=3 (dominated by 1), corroboration variants forward / threshold / evidence-only / budget 0 (all
dominated by ranking-only on MCC on all three sets). image_exec kept: THEIA +3 TP, 0 FP; neutral on CADETS and,
with local_multicast, on H201 (without local_multicast it added ~300 FP on H201 - the multicast taint bug).

Label-free benign-day check (all five, leave-one-day-out over the baseline days): novelty alarms 0.3 -> 0.4
CADETS 54->18, THEIA 293->61, H201 32->21, H501 35->19, H051 17->11; benign rule events: tainted_modify on H201
23476 -> 0, H051 38074 -> 0 (multicast), others unchanged.
