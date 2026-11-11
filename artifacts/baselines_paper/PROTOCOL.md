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

## Part 2: new hosts (written 2026-11-11 ~05:15, before any new-host run was scored)
Hosts and data:
- E3 FiveDirections: existing PIDSMaker DB `fivedirections_e3`; OUR split (method.tex rule, = the lab's): train
  04-04..04-07, val 04-08, test 04-09..04-11 (US/Eastern days); GT = ORTHRUS CSVs excel_0409 + firefox_0411 (2
  attacks; browser_0412 is outside the test days and is also excluded by PIDSMaker). Specs: `specs/*_FIVEDIRECTIONS_E3.json`.
- E3 TRACE: there is NO PIDSMaker TRACE database on this host (dump deleted for disk; a restored DB would be
  ~70-90 GB). We convert the lab's TRACE store (built from that dump with PostgresReplay-equivalent streaming) into a
  new DB with `scripts/conv_store.py` (mapping in its docstring); split train 04-02..04-08, val 04-09, test
  04-10..04-13; GT = the three ORTHRUS TRACE CSVs.
- (Part 3, if time) ATLASv2 h1 and CARBANAKv2 h1-h5: the same conversion of the lab's host stores; GT = the CSV rows
  whose index_id is in that host's registry.

PIDSMaker systems (ORTHRUS = `orthrus_non_snooped`, `velox`): configuration files unchanged; only the dataset entry
(days, database, GT files, timezone US/Eastern for converted sets) is replaced through `pm_run.py --spec`. Seeds
`--training.seed=0..4` (5 if time allows, else 3, else 1 - reported). Headline = last evaluated epoch (no test
selection); reference = PIDSMaker's own best_adp epoch pick (test-selected, optimistic).

ProvFusion on new hosts (no per-host tuning; nothing is looked at except training/validation data):
- Hyper-parameters = the published row of the closest dataset by OS family:
  - Linux (E3 TRACE) -> THEIA_E3. Its original row lacks num_hidden, so we use its complete raw-log ("regen, D") row:
    num_hidden 64, num_heads 8, mask_rate 0.3, lr 0.0015, max_epoch 20, max_epoch_f 50, weight_decay 0.001,
    weight_decay_f 1e-5, lr_f 0.001.
  - Windows (E3 FiveDirections, ATLASv2, CARBANAKv2) -> OPTC_h201 (the Windows row with the default lr_f):
    num_hidden 64, num_heads 2, mask_rate 0.5, lr 0.0015, max_epoch 500, max_epoch_f 10, weight_decay 1e-4,
    weight_decay_f 2e-6, lr_f 0.001.
  - Common flags as in the README; `--use_cfg` entry = the identical entry of all provenance datasets in configs.yml.
- Loss weights (DATASET_WEIGHTS, required per dataset): rule fixed in the next section from training data only.
- Seeds `--seeds 1..5` (1 = the published seed), 5 if time allows, else 3, else 1.

### Loss-weight rule for ProvFusion on new datasets (written 05:20, from CADETS TRAINING data only)
ProvFusion's DATASET_WEIGHTS are described as "manually tuned". On CADETS E3 training graphs no simple formula
reproduces them (checked: balanced N/(K n_c), N/(10 n_c), N/(11 n_c), sqrt(N/n_c); none matches, ordering is
similar). For a dataset without published weights we therefore use the standard balanced class weights that
PIDSMaker itself uses (`compute_class_weights`): w_c = N / (K n_c) over the edge-type labels of the TRAINING graphs
(after ProvFusion's DGL conversion), K = number of present classes among 0..9, capped at 30 (the cap in all
published vectors), 0 for absent classes and for class 10 (self loops), as in every published vector.
Environment amendment: the image's DGL is the CUDA build 2.2.1+cu121 (conda channel dglteam; data.dgl.ai is not
reachable from this host); the first CADETS attempt failed before training with DGL's CPU build.

### Amendment (05:55, disk; before any PIDSMaker result was looked at)
The disk floor (25 GB free) was reached during the first Velox FiveDirections run (PIDSMaker artifacts: edge
embeddings 8.7 GB + edge losses per evaluated epoch + ~150 MB of figures per epoch). From now on: (1) the heavy
figures are disabled (no effect on numbers); (2) while a run trains, only the newest epoch's edge losses are kept,
so PIDSMaker evaluates only the LAST epoch = our pre-registered headline. The best_adp reference (test-selected) is
dropped. (3) PIDSMaker on E3 TRACE needs ~18 GB of edge embeddings for 17.8 M fused edges and is not feasible with
the disk floor; it will be attempted only if space is freed by someone else.
