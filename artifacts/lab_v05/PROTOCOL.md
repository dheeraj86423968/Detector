# Learned-detector round (0.5) - protocol, 2026-11-06

Goal: better learned detectors (the layer-3 ranker), nothing specific to one dataset or client: one default
configuration for every endpoint, chosen on development data, no test labels in any training / selection step.

Split (as in 0.4, artifacts/lab_v04/PROTOCOL.md)
- Development (per-node inspection allowed): CADETS_E3, THEIA_E3, OPTC_H201.
- Held out: OPTC_H501, OPTC_H051 - aggregate metrics only, run once after the configuration below is frozen.
  Caveat to report: both were already used as held-out sets for 0.4, so they are "seen" at the aggregate level;
  nothing in this round was looked at on them before the final run.

Measurement
- Lab (d1lab.py / d1lab2.py): detector-1 trained on the endpoint's baseline days with the bundle's featuriser, epoch
  selection by validation loss only; test ADP / TP / FP of the selected model per seed and of the 3-seed ensemble
  (mean of threshold ratios, as the runtime). Per-epoch test ADP is logged as a diagnostic, never used to select.
- Product path (retrain_detector1 + darpa_eval): detector-1 of each published 0.4 bundle retrained with the frozen
  configuration (same seed set as the bundle's run), detector-2 / layers / policy unchanged, fusion re-calibrated
  on the validation day. The lab and the product path agree exactly (CADETS run 0: detector-1 ADP 0.383 both).

Findings on the development sets (detector-1 3-seed ensemble ADP; lab logs g1-*, g2-*, g3-*, g4-*)

| input | lr | CADETS | THEIA | H201 |
|---|---|---|---|---|
| window degrees (0.3/0.4) | 1e-4 | 0.13 | 0.55 | 0.11 |
| none | 1e-4 | 0.008 | 0.66 | 0.13 |
| batch role features (explicit, 4 columns) | 1e-4 | 0.36 | 0.94 | 0.11 |
| batch role features | 1e-3 | 0.017 | 0.32 | 0.07 |
| batch_scale (PIDSMaker reindexer input) | 1e-4 | 0.36 | 0.90 | 0.20 |
| batch_scale | 1e-3 | 0.36 | 1.00 | 0.25 |
| batch_scale + mean of 3 best epochs, seeds 0-2 / 3-5 | 1e-4 | 0.64 / 0.41 | 0.90 / 0.71 | 0.20 / 0.20 |
| **batch_scale + mean of 3 best epochs, seeds 0-2 / 3-5** | **1e-3** | 0.38 / 0.60 | 1.00 / 1.00 | 0.13 / 0.20 |

- The structural input is what detector-1 learns from (no input: CADETS 0.008). PIDSMaker's Velox gets it from the
  reindexer double-mean (x * (1 + 1/k) for nodes that send and receive in the 1024-edge batch); window degrees do
  not reproduce it. The explicit 4-column variant is as good at 1e-4 but collapses at 1e-3: batch_scale is robust.
- lr 1e-3 (PIDSMaker's tuned value for 6 of its 8 Velox datasets): >= 1e-4 on THEIA, equal within seed noise on
  CADETS / H201.
- Averaging the 3 lowest-validation-loss epochs: per-seed mean about equal to the best epoch, worst seed higher
  (min 0.09 vs 0.04); kept as a variance reduction that costs nothing at inference.
- Detector-1 on OpTC H201 stays near 0.2: the change does not help there.
- Published Velox CADETS ADP (0.94) uses PIDSMaker's test-ADP epoch selection; per-epoch test ADP of our runs
  reaches 0.85-0.90 at some epoch, the validation-selected model 0.35-0.85.
- Detector-2 seed combination (seeds_rank.py, per-seed cache of the published bundles): the current mean of
  max-normalised ratios is best or tied among 11 label-free alternatives (median, trimmed mean, percentile and
  robust-z normalisation) on CADETS and THEIA; unchanged. Single detector-2 seeds range 0.02-1.00 ADP; the 5-seed
  mean is what makes it usable.

## Frozen detector-1 configuration (before any held-out run)
velox_input = batch_scale, velox_lr = 1e-3, velox_out_dim = 256, velox_average_top = 3, 3 seeds; detector-2
unchanged.

## Fusion (decided on the development sets only, then frozen with the above - 2026-11-06 ~15:10, before any held-out run)
Cached per-window scores of the 15 retrained development bundles (learned_rank.py, jobs5.txt), learned-only ranking
ADP mean over 5 runs:

| fusion | CADETS | THEIA | H201 | mean |
|---|---|---|---|---|
| detector-1 alone | 0.41 | 0.98 | 0.18 | |
| detector-2 alone | 0.91 | 0.85 | 0.13 | |
| weighted 2:1 (0.2-0.4 default) | 0.37 | 1.00 | 0.18 | 0.52 |
| weighted 1:1 | 0.56 | 1.00 | 0.18 | 0.58 |
| weighted 1:2 | 0.75 | 0.93 | 0.13 | 0.60 |
| **max of the two ratios** | 0.83 | 0.95 | 0.17 | **0.65** |

Frozen: fusion_mode = max (no weight to choose; the stronger detector differs per dataset). Final: the 10 held-out
0.4 bundles get detector-1 retrained + max fusion (retrain_detector1), the 15 development bundles the max fusion
on their retrained detector-1 (--reuse-detector1); darpa_eval on all 25, held-out once.
