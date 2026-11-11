# Five training runs of the 0.10 configuration (written 2026-11-11, before any run 2-5 bundle exists or is scored)

Purpose: the S&P 2027 paper reports STRATA 0.10 from a single training run per host, while criticising published
learned PIDS for run-to-run instability (Bilot et al. report five-run means). This experiment measures how much the
0.10 results move across training runs. It is a measurement only: **no design, configuration, threshold or
evaluation change may be made because of these results**, on any host (dev or held-out).

## Runs
- **Run 1** = the existing 0.10 results: the bundles `v07rel` / `b07rel` under `/data/lab08/...` scored by
  artifacts/lab_v10 (adp13.py -> results/adp/adp-*.json, inc13.py -> inc13-final.json). Run 1's pre-existing numbers
  are used as run 1's numbers for every metric that was already reported for it.
- **Runs 2-5** = four new trainings per host, identical configuration, different random seeds only.
  Seed base b_r = 100 x (r - 1) (run 1 is b = 0): word2vec seed b_r, detector-1 (Velox) seeds b_r .. b_r+2,
  detector-2 (ORTHRUS) seeds b_r .. b_r+4. Run 2: 100, run 3: 200, run 4: 300, run 5: 400.
  (The product fixes the word2vec seed at 0; it is varied here too so that every random choice of the training
  pipeline changes between runs, as in a five-seed evaluation. Detector-3 and layers 1-2 are fitted by counting and
  have no seed.) Detector-2 GPU training is not bit-reproducible, so even an equal seed would not reproduce run 1.

## Training path (= run 1's, only the seeds change)
Code: the 0.10 tree (git 9b1b23f, `engine/` and `server/` exported unchanged), server image `pdp/server:v101rc`.
Per host and run: `Trainer(baseline store, train days, validation day, cfg6).run()` -> b06, then
`upgrade_bundle_07(b06, b07, baseline store, cfg7)` -> b07, with (as artifacts/heldout_v10/scripts/heldout10.py and
artifacts/lab_v08/heldout08.py)
`cfg8 = TrainConfig(device="cuda", <seeds>, <endpoint overrides>)`,
`cfg7 = cfg8 + {d3_breadth: False, layer_novelty: True}` (0.7 released detector configuration),
`cfg6 = cfg8 + {detector3: False, d3_breadth: False, layer_novelty: True, novelty_as_evidence: False, learned_alerts: False}`.
Train / validation days = those recorded in run 1's bundle manifest (asserted equal to the lab set definition).
Endpoint overrides = run 1's recorded detector settings: detector-2 hidden / output 128 for THEIA_E3, OPTC_H051,
OPTC_H201 (their benchmark endpoints' `train` settings; manifests of run 1 confirm 128); every other value default.

This is exactly run 1's path for TRACE, ATLASv2 h1/h2, CARBANAKv2 h1-h5, THEIA_E5 and CLEARSCOPE_E5. For the seven
original benchmark endpoints (CADETS_E3, THEIA_E3, CLEARSCOPE_E3, FIVEDIRECTIONS_E3, OPTC_H201/H501/H051) run 1's
bundle reached the same configuration through the product's upgrade lineage (featuriser and detector-2 from the
0.3 trainer, detector-1 retrained with the 0.5 defaults and the fusion re-calibrated by tools/retrain_detector1,
then upgrade_bundle_07); runs 2-5 train the same configuration in one step. Recorded as a caveat, not a change.

The alert policy is the 0.9/0.10 runtime default for every run (run 1's bundles predate the `policy: "0.9"` manifest
field and get the same defaults from the runtime: no learned-only alerts, own-score corroboration, one corroborated
repeat per program and day).

## Scoring (the 0.10 pipeline, unchanged)
lab_v10 adp13.py (copied to scripts/eval5.py; only additions: the bundle directory per run, and the per-detector
measures below, computed from the same rt.score() results) with the 0.10 configuration = variant **P2** (fleet
prevalence "drop", >= 2 other endpoints), then inc13.py with grouping **G2** (7-day recurring-incident merge,
0.10 server code). Fleet prevalence uses the other fleet members' run-1 bundle `layers.json` known_executables for
every run (a consistent set); for every new bundle it is checked that its own `layers.json` equals run 1's
(known_executables are fitted on the training days only and do not depend on the seed). Any difference is reported.

Metrics per host and run (test days, PIDSMaker/ORTHRUS node-level ground truth, as lab_v10):
- attacks detected, TP, FP, FP per test day, precision at the operating point (P2);
- ADP of the triage order (alert tier, then learned score) and ADP of the learned score alone;
- incidents, false incidents (no ground-truth alert), false incidents per host-day, buried attacks (G2);
- detector-1 alone and detector-2 alone (seed ensembles exactly as the runtime averages them: r1 = mean of the
  detector-1 seed ratios, r2 = weighted mean of the detector-2 seed ratios): node score = maximum over test windows;
  threshold = the maximum of that ensemble ratio over the validation-day nodes (replayed through the runtime from the
  validation-start state, detectors 1-2 only, as Trainer.calibrate_final does); alerted = above the threshold.
  Reported: attacks, TP, FP, ADP of the ranking. Also stored: the same at ratio 1.0 (each seed's own validation
  maximum), as a secondary number only.
- CLEARSCOPE_E5: also ADP with the third attack Bilot et al. count (lockwatch, `--gt-extra`), as in run 1.

Run 1's per-detector numbers do not exist; they are obtained by scoring run 1's bundles with the same eval5.py. That
re-scoring must reproduce run 1's operating-point numbers; any difference is reported (GPU inference is not
bit-exact), and run 1's original numbers stay the run-1 numbers.

## Summaries
- Per host: mean, sample sd, min, max over the completed runs (n reported).
- The 16 development sets (CLEARSCOPE_E5 excluded): per run, totals of attacks, TP, FP, false incidents and false
  incidents per host-day (71 host-days), for runs where all 16 sets completed; mean / min / max over those runs.
- CLEARSCOPE_E5 (held-out at 0.10, seen since): reported separately as a variance check; never pooled with dev sets.

## Order and resources
Priority: CADETS_E3, THEIA_E3, CLEARSCOPE_E3, THEIA_E5-theia, OPTC_H051, OPTC_H201, OPTC_H501, CLEARSCOPE_E5, then
TRACE_E3, FIVEDIRECTIONS_E3, ATLASV2 h1/h2, CARBANAKV2 h1-h5. At most two trainings at once; a training starts only
with >= 10 GB free GPU memory and >= 12 GB available RAM; containers run with --oom-score-adj 800 and a memory limit.
Bundles are deleted after scoring except manifest.json, calibration.json, layers.json (small). A host or run that
fails is reported as failed with its error; nothing is estimated or filled in.
