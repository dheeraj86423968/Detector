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
