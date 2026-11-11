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
- 06:14 ProvFusion FiveDirections data prepared (762 s; 36,112 nodes with empty labels got zero vectors); loss
  weights by the rule: 30.0000,30.0000,0.1270,1.3154,30.0000,30.0000,30.0000,30.0000,3.4920,0.0000,0.0000. Seeds 1-5 queued (OPTC_h201 hyper-parameters).
- 06:11 Velox FiveDirections s1: 0/2 attacks, TP 0 / FP 6, ADP 0.019.
- 06:28 disk at 26 GB free: deleted the CADETS merged .pt (0.94 GB; regenerable deterministically) - CADETS seeds 4-5 deferred.
- 06:20 ProvFusion CADETS s3: 0/3 attacks, TP 0 / FP 13; ProvFusion-printed ADP 0.441 vs tie-neutral 0.0005.
- 06:24 ATLASv2 h1 ProvFusion data prepared (0.42 GB).
- 06:33 ProvFusion FiveDirections s1 (OPTC_h201 config): 2/2 attacks, TP 2 / FP 522 (174 FP per test day);
  tie-neutral ADP 0.008, ProvFusion-printed 0.090.
- 06:38 **disk floor breached briefly**: free space fell to 24.x GB during the Velox FiveDirections s2 evaluation
  (PIDSMaker pickles a 4 M-row edge-score table + THEIA prep); the watchdog stopped Velox s2 and the THEIA prep
  within 10 s. (The watchdog used rounded-up GB; it now uses bytes with a 25.6 GiB trigger.) Fixes: pm_run.py drops
  the edge-score table (not used by any metric); pm_run.sh waits with `docker wait` (a transient inspect failure
  had made the queue start ORTHRUS s0 while Velox s2 still ran; ORTHRUS s0 was stopped and restarted). Step-5 THEIA
  prep postponed until the PIDSMaker FiveDirections artifacts (12 GB) are deleted.
- 06:39 ProvFusion FiveDirections s2 finished (see results).
- 06:46 ORTHRUS (orthrus_non_snooped) FiveDirections s0 OOM-killed at 28 GB (TGN last-neighbour graphs, 29 GB anon); s1 stopped. ORTHRUS will run alone with a 40 GB limit after Velox s3-s4; ProvFusion queues pause while it runs.
- 07:09 free space fell to the watchdog trigger again (others' usage grew while mine was constant at ~14 GB);
  the watchdog killed Velox FiveDirections s3 (evaluation), s4 (start) and ProvFusion ATLASv2 s1-s4. Decision:
  delete the PIDSMaker FiveDirections artifacts (11.7 GB; regenerable in ~12 min) -> 38 GB free. Velox FiveDirections
  has 3 completed seeds (0, 1, 2); ORTHRUS FiveDirections is pending (needs 40 GB RAM and the artifacts again).
- 07:12 TRACE conversion started (bl_trace_e3).
- 07:13 first ATLASv2 PIDSMaker attempts failed at once (dataset-name vocabulary, see PROTOCOL amendment 07:25);
  restarted 07:23 as TCFMT_ATLASV2_H1.
- 07:17-07:23 ProvFusion ATLASv2 h1 s5 and s1: 0/10 attacks, FP 90 and 64 (one test day); tie-neutral ADP 0.0003,
  ProvFusion-printed 0.27 / 0.21.
- 07:30 CARBANAKv2 h1-h5 converted (bl_carbanakv2_h1..5; fused edges 3,567,640 / 2,974,345 / 2,939,711 / 1,569,353 /
  167,082 = lab manifests; DBs 0.04-0.81 GB). ProvFusion CARBANAKv2 queue: prep, then seeds 1-3 per host.
- 07:37 Velox ATLASv2 h1 s0: no alerts at its threshold (0/10, TP 0 / FP 0), ADP 0.077.
- Runners now start a GPU job only with >= 12 GB GPU and >= 12 GB RAM free and at most 2 of my GPU jobs running.
- 07:44 TRACE ProvFusion data prepared (1877 s, 5.21 GB merged; day graphs ~0.7 M nodes). TRACE ProvFusion seed 1
  started; needs ~27 GB RAM. Because of the disk floor, TRACE ProvFusion is limited to seeds 1-3, after which its
  merged data is deleted so the FiveDirections PIDSMaker artifacts can be rebuilt for ORTHRUS (40 GB RAM, alone).
- 07:44/07:49 Velox ATLASv2 s1/s2 failed (my edge-loss pruning raced with PIDSMaker's evaluation listing); fixed by
  evaluating only the last epoch (pm_run.py) and requeued.
- 08:30 ATLASv2 h1: ProvFusion 5 seeds, ORTHRUS 4 seeds, Velox 3 seeds done (summary.md).
- 08:33 ProvFusion data prepared for CARBANAKv2 h1-h5.
- 09:18 ATLASv2 h1 PIDSMaker complete (Velox 5 seeds, ORTHRUS 5 seeds). TRACE ProvFusion s1: 1/3 attacks, TP 1 /
  FP 4 (1 FP/day), tie-neutral ADP 0.19, ProvFusion-printed 0.48. CARBANAKv2 h1 ProvFusion s1: 1/1, TP 2 / FP 48,
  tie-neutral ADP 0.15, ProvFusion-printed 0.9999.
- Order from here (disk floor): TRACE ProvFusion s2, s3 -> delete TRACE merged data and DB -> PIDSMaker
  FiveDirections artifacts rebuilt, ORTHRUS s0-s2 (40 GB RAM, alone), Velox s3-s4 -> CARBANAKv2 PIDSMaker
  (3 seeds per system per host); ProvFusion CARBANAKv2 seeds 1-3 run in parallel; step 5 last.
- 10:54 TRACE ProvFusion s2: 2/3 attacks, TP 3 / FP 9, tie-neutral ADP 0.36 (printed 0.65). CARBANAKv2 ProvFusion s1 on h1-h5 and s2 on h1 done (summary.md).
- 12:27 TRACE ProvFusion s3 done; TRACE merged data (5.2 GB) deleted and bl_trace_e3 dropped (TRACE limited to 3 seeds). CARBANAKv2 h1 ProvFusion s1-s3 done; its merged data deleted.
- 12:45 **ORTHRUS (orthrus_non_snooped) on FiveDirections is infeasible on this host**: OOM-killed again with a
  40 GB limit in PIDSMaker's "Computing TGN last neighbor graphs" (42 GB anon RSS; earlier 29 GB at 28 GB limit).
  More than 40 GB cannot be given while keeping >= 12 GB free for the shared host (62 GB total). Remaining
  ORTHRUS FiveDirections seeds cancelled; Velox s3-s4 and then CARBANAKv2 PIDSMaker continue.
- 13:09 CARBANAKv2 h1-h5 ProvFusion seeds 1-3 complete (merged data deleted). 13:19 Velox FiveDirections s3 done.
- 14:21 Velox CARBANAKv2 h1 s0: 0/1, TP 0 / FP 6. 14:31 step-5 data prepared (THEIA 1.16 GB, OpTC H051 2.68 GB). From ~14:40 all my GPU jobs wait: other users hold ~38 GB of the GPU (< 12 GB free).
- 15:59 ORTHRUS CARBANAKv2 h1 s0 OOM-killed at 28 GB in the same TGN step (h1 has 1.30 M nodes; ATLASv2 h1 with 0.53 M nodes fit). Expected to fail likewise on h2/h3 (1.19 M / 1.06 M nodes); the queue records each attempt. ORTHRUS needs > 40 GB RAM above ~1 M nodes on this host.
- 16:22 ProvFusion THEIA E3 s1 (regen-D config): refined labels 3/3 attacks, TP 68 / FP 4, tie-neutral ADP 0.967 (printed 0.987); ORTHRUS labels 2/2, TP 59 / FP 13, ADP 0.933.
