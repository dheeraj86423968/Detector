# Baselines for the S&P paper: ProvFusion, ORTHRUS and Velox on hosts without published results

Written before any scored run. Each section below is written (and committed where possible) before the runs it
governs. Nothing here is tuned on test data. Failed runs are reported as failed.

## Environment (all runs)
- Third-party code runs only inside docker image `baselines-pids:1` (python 3.9, torch 2.1.2+cu121, dgl 2.1.0,
  PyG 2.6.1; Dockerfile in `scripts/Dockerfile`), user uid 1000, `--oom-score-adj 800`, memory limit 28 GB,
  network `shared_network` (only to reach the PIDSMaker `postgres` container, read-only use of existing DBs).
- ProvFusion: github.com/Joney-Yf/ProvFusion @ a18be65 (mounted read-only). Its pinned environment is torch 1.13.1 /
  dgl 1.0.0; we use torch 2.1.2 / dgl 2.1.0 (one image for all three systems, disk budget). Deviation noted.
- PIDSMaker: /root/PIDSMaker @ 438a05a (mounted read-only), systems `orthrus_non_snooped` (= ORTHRUS without
  test-data featurisation and without k-means, as in Bilot et al.) and `velox`.
- Wrappers (ours, in `scripts/`): `pf_prepare.py` (ProvFusion data preparation without multi-GB intermediates, every
  algorithmic step is ProvFusion's code), `pf_gt.py` (ground truth to ProvFusion's .pt format), `pf_train.py`
  (calls ProvFusion's main unchanged), `pm_run.py` (calls PIDSMaker's main unchanged and dumps per-node results),
  `score.py` (metrics).

## Metrics (all runs)
- Node level, PIDSMaker definition: evaluated nodes = nodes of the test graphs; TP = alerted ground-truth node,
  FP = alerted other node; attack detected if >= 1 of its GT nodes is alerted. Reported at each system's OWN
  operating point: ProvFusion final vote (>= 4 of 7 detectors, thresholds from the validation day); ORTHRUS/Velox
  `y_hat` at PIDSMaker's `max_val_loss` threshold.
- ADP: PIDSMaker's `plot_detected_attacks_vs_precision` and our `adp13` (pdp_server.tools.darpa_eval.adp, stable
  sort). For ProvFusion the ranking score is its own (max over test graphs of the vote count, an integer 0..7, as in
  `method_12_with_different_normalization`). Because that score has massive ties and ProvFusion's ADP function
  breaks ties by putting ground-truth nodes first (`sort_with_preferred_index_np(scores, labels)`), we report for
  ProvFusion: (a) its own ADP as published (label-assisted tie order), (b) PIDSMaker's ADP (np.argsort tie order),
  (c) adp13 (node-id tie order), (d) **expected ADP under a uniformly random tie order (mean of 200 permutations,
  seed 0) = headline**, (e) worst case (benign first within ties). ORTHRUS/Velox scores are continuous; (b)/(c)
  are reported, ties are checked.
- Seeds: ProvFusion `--seeds s` (training seed; data preparation incl. word2vec fixed, seed 0 as in its config);
  PIDSMaker `--training.seed=s` (featurisation seed fixed 0). Mean and sd over seeds; the number of seeds is stated.
- PIDSMaker epochs: PIDSMaker evaluates every second epoch and by default keeps the epoch with the best TEST ADP
  (`best_model_selection: best_adp`). That is test-set selection, so our headline is the LAST evaluated epoch of the
  configured schedule (no selection). The best_adp pick is reported only as a labelled reference.

## Part 1: sanity reproduction, ProvFusion on E3 CADETS (published configuration)
- Data: PIDSMaker `cadets_e3` database, ProvFusion's own CADETS_E3 split (train 04-03,04,05,07,08,09,10; val 04-02;
  test 04-06,11,12,13), its graph construction (one graph per US/Eastern day, ORTHRUS edge fusion), word2vec
  featurisation (orthrus.yml of its data_preparation, seed 0, PYTHONHASHSEED=0).
- Config: README "Best hyperparameters" row CADETS_E3: `--encoder gatedge --decoder gat --loss_fn sce --optimizer adam
  --num_layers 2 --in_drop 0.2 --attn_drop 0.1 --replace_rate 0.0 --activation prelu --linear_prob --scheduler
  --use_cfg --seeds 1 --lr_f 0.001 --normalization_method percentile --num_hidden 64 --num_heads 2 --mask_rate 0.3
  --lr 0.0015 --max_epoch 5 --max_epoch_f 50 --weight_decay 0.001 --weight_decay_f 0.0001 --alpha_l 3
  --drop_edge_rate 0.0`, loss weights DATASET_WEIGHTS["CADETS_E3"].
- Labels: ORTHRUS CSVs (E3-CADETS 06/12/13); ProvFusion's refined CADETS CSVs contain exactly the same node UUIDs
  (checked: identical), so "refined" and "plain ORTHRUS" scoring coincide on this host.
- Published: TP/FP 24/1, ADP 1.00. "Roughly reproduces" = all 3 attacks detected at the operating point and
  FP <= 10; otherwise reported as not reproduced with the reason, before going further.
- If time allows also seeds 2-5 (published was one run).
