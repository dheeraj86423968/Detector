# 0.6 lab (2026-11-06): evasion resistance of layers 1-2, held-out check

PROTOCOL.md: split (development: CADETS, THEIA, OpTC H201; H501 / H051 aggregate only; new held-out: DARPA E3
ClearScope and FiveDirections), the acceptance rule (written before the results it decided), the decisions.
lab.py (from lab_v04, re-fits layers 1-2 with any LayerConfig and re-runs the alert policy on cached learned scores of
the 0.3 bundles in jobs.txt of lab_v04; `prior_drop` simulates a retrain): grids g1 (each new setting alone), g2
(connect_receives, late_exfil, combinations, retrain simulation), g3 (the frozen defaults vs 0.4: identical on all
five sets). fp_anatomy.py: false positives by (rule, key) on the development sets. official_v06.sh / v06b.sh: the
held-out run (0.5 bundle vs layers re-fitted with 0.6; v06b = the 0.6 half again after a crash of add_layers on a
pre-existing bug, fixed before any 0.6 result existed). Results: docs/BENCHMARK_HELDOUT.md.
