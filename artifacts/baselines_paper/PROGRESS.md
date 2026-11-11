# Progress (baselines for the S&P paper)

- 04:50 ProvFusion cloned (a18be65), image baselines-pids:1 built (torch 2.1.2/dgl 2.1.0/PyG 2.6.1).
- 04:59 ProvFusion CADETS E3 data preparation started (pf_prepare.py, PIDSMaker cadets_e3 DB).
- 05:07 ATLASv2 h1 converted to new DB bl_atlasv2_h1 (conv_store.py; 528,178 nodes, 1,326,856 fused edges = lab).
- 05:08 PIDSMaker Velox FiveDirections seed 0 started; ProvFusion FiveDirections data preparation started.
- 05:10 CADETS E3 ProvFusion data prepared (663 s; 0.94 GB merged; 68 of 72 GT ids in test graphs = ORTHRUS's 68).
- 05:14-05:20 image fixes: DGL had installed its CPU build (data.dgl.ai unreachable) -> DGL 2.2.1+cu121 from the
  dglteam conda channel + CUDA runtime libs; DGL now needs `--gpus all` even for CPU-only steps (graphbolt).
- 05:20 disk dropped to 25 GB free (PIDSMaker FiveDirections feat_inference 8.7 GB + my image build cache): pruned
  my own build-cache entries (+4 GB), dropped the partial bl_trace_e3 DB, started a watchdog that stops all bl-*
  containers below 26 GB free. TRACE conversion postponed until PIDSMaker FiveDirections artifacts are deleted.
- 05:34 **Sanity reproduction, ProvFusion CADETS E3, published config, seed 1: 3/3 attacks, TP 12 / FP 1
  (published 24 / 1), ProvFusion's own ADP 0.9999 (published 1.00); tie-neutral ADP 0.975 (sd 0.027), PIDSMaker
  ADP 0.966, adp13 0.982, worst-tie 0.904.** Our recomputation (pf_score.py) reproduces ProvFusion's printed
  per-detector and final counts exactly. Verdict: roughly reproduces (attacks and FP match; half the TP nodes).
  Results: results/provfusion_CADETS_E3_s1.json; scores: scores/provfusion_CADETS_E3_s1.csv.gz (join 100 %).
- 05:21 ProvFusion crashed on FiveDirections (ZeroDivisionError on nodes with empty labels): such nodes get a zero
  vector (pf_prepare.py; count logged).

## Node-level score files (scores/, for the anchoring step)
One gzip CSV per (system, host, seed): `scores/<system>_<HOST>_s<seed>.csv.gz`, system in {provfusion, velox,
orthrus_non_snooped (= ORTHRUS as re-evaluated by Bilot et al.)}. One row per node of the system's TEST graphs.
- `index_id`: join key = the framework index_id = PIDSMaker DB `index_id` = ORTHRUS GT CSV column 3 = the `uuid`
  field of our lab registry (`eval-test/registry.json` of the lab host). For converted hosts (TRACE, ATLASv2,
  CARBANAKv2) the DB was built from our registry, so the key is our uuid by construction.
- `score`: the system's own node ranking score (higher = more anomalous). Velox/ORTHRUS: PIDSMaker node score
  (max edge loss over test windows, src and dst) of the last training epoch. ProvFusion: 10 * vote + A123, where
  vote = max over test days of the number of its 7 detectors that fire (0..7, its ADP score) and A123 = max over test
  days of A1+A2+A3' (its "method 6" sum, label-free tie-break); `vote` and `a123_max` are also given separately.
- `alert`: 1 if the system alerts the node at its OWN operating point (Velox/ORTHRUS: PIDSMaker max-val-loss
  threshold; ProvFusion: vote >= 4 on some test day). `gt`: 1 if ground-truth node (the labels used in results/).
Join check (scripts/join_check.py): fraction of rows and of GT rows whose index_id is in the lab registry; results
are listed per file in results/join_rates.json.

## Log (continued)
- 05:47 watchdog stopped Velox FiveDirections s0 (evaluation) and CADETS s2/s3 at 25 GB free; FiveDirections
  ProvFusion prep had been OOM-killed (28 GB) at the 10 M-event day 04-09. Fixes: pm_run.py no-op figures,
  pm_run.sh keeps only the newest epoch's edge losses (protocol amendment), pf_prepare.py interns repeated strings
  of the event rows (same values/order).
- 05:49 Velox FiveDirections s0 (last epoch): 1/2 attacks, TP 1 / FP 10, ADP 0.064 (= PIDSMaker's printout).
- 06:02 ProvFusion CADETS s2 (published config, only the seed differs): 1/3 attacks, TP 1 / FP 9; ProvFusion's own
  printed ADP 0.637 (label-assisted tie order) vs tie-neutral 0.115, PIDSMaker ADP 0.084.
