# 0.5 learned-detector lab (2026-11-06)

PROTOCOL.md: split, findings and the frozen configuration (written before the held-out run).

- d1lab.py / d1lab2.py: detector-1 trained with one structural-input variant (and, d1lab2, the mean of the 3 best
  epochs), epoch chosen by validation loss; test ADP of the selected model per seed and of the 3-seed ensemble.
  Logs: g1-* (input variants, lr 1e-4), g2-* (lr 1e-3), g3-* (weight averaging, seeds 0-2), g4-* (seeds 3-5);
  d1-*.json the same with per-epoch rows (per-epoch test ADP is a diagnostic, never used for selection).
- cache_seeds.py + seeds_rank.py: per-seed scores of the published bundles; label-free detector-2 seed combinations.
- cache_scores.py + learned_rank.py (jobs5.txt): per-window scores of the 15 retrained development bundles; fusion
  sweep that chose max.
- official_v05.sh: the official run - pdp_server.tools.retrain_detector1 (development: --reuse-detector1 for the max
  fusion; held out: detector-1 retrained + max fusion, run once) and tools.darpa_eval on all 25 bundles. Results:
  ../benchmark_e3/eval-*-v05.json, ../benchmark_optc/eval-optc-*-v05.json.

Run the lab scripts with the server image and the working tree mounted (/data volume, ground truth at /gt, the 0.4
lab (lab.py) at /lab0).

official_v05.log / jobs_v05.txt: the final run (bundle ids per endpoint). Held-out result, reported once: the learned
gains seen on CADETS / THEIA do not carry over to OpTC H501 / H051 (docs/BENCHMARK_OPTC.md "0.5").
