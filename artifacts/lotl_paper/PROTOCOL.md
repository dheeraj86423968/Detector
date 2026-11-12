# Living off the land (LotL) counterfactual + bootstrap intervals for STRATA 0.10 (written before any scoring)

Written 2026-11-12 ~05:30 UTC, for the S&P paper. Committed before `lotl13.py` scores any set. Lab data only: a
counterfactual edit of recorded test data, applied in memory inside the lab evaluation. No attack is executed, no live
host or container of the product (production, staging, Postgres) is touched, no network access. Before this commit
the transform was only dry-run (`scripts/survey.py`: mapping table, no detector loaded, nothing scored), to debug the
label handling; the rule below is the one the dry run converged on.

## Question
STRATA's layer 1 alerts on a program that never ran during the host's baseline. 11 of the 26 attacks 0.10 detects on
the 16 development sets rest on that alone (`paper_analysis/evidence13.json`: classes novelty_gt, novelty_anchor).
What happens to detection when the attacker runs only programs that already ran on the host during its baseline?

## Setup (unchanged from lab_v10)
0.10 lab evaluation, variant P2 (`artifacts/lab_v10/PROTOCOL.md`, `scripts/eval13.py`, `adp13.py`): each of the 16
development sets (plus CLEARSCOPE_E5, reported per attack, not pooled) is scored with its released bundle (v07rel,
b07rel for CARBANAKv2 h1-h5 / THEIA_E5 / CLEARSCOPE_E5), 0.9 runtime defaults, fleet prevalence k=2 drop. Bundles and
models are NOT retrained or re-calibrated. Code: `scripts/lotl13.py` = a copy of `adp13.py` with the transform and the
variants below (no product code edited; product code mounted read-only).

## The transform (`scripts/lotl.py`)
Per attacked set, with layer 1's own parser and program identity (the bundle's `layers.json` settings):
1. **Target programs**: the program (layers.program_key) of every ground-truth process node seen in the test windows
   whose program layer 1 considers new (`NoveltyLayer.is_known` false; fleet prevalence ignored, i.e. "unseen in
   this host's baseline").
2. **Renamed nodes**: every process node in the test windows (ground truth or not) whose program is new to layer 1
   and is a target program (same key; a program recorded without a path matches by name, as layer 1 matches).
3. **Kind**: "shell" if the program's name (without .exe, case-folded) is a shell / interpreter / script host
   (`layers.INTERPRETER`, the list layer 2 uses for script execution, plus `cmd` / `command`) or the program is a
   script file (.sh .py .pl .rb .php .ps1 .vbs .js .wsf .hta .bat .cmd ...); else "process".
4. **Baseline frequency**: process nodes of the bundle's registry (ids < num_nodes, the baseline period) whose program
   (as layer 1 reads it) is in the bundle's `known_executables`; counted per program key of the full recorded path
   (a `c:\program files\...` program counts as itself, not as layer 1's truncated `c:\program`).
5. **Replacement**: a "shell" target -> the most frequent baseline shell / interpreter; if the host has none, the
   most frequent baseline process (flagged `fallback_to_process`). A "process" target -> the most frequent baseline
   process. Ties: lexicographically smallest key. Spelling: that program's most frequent recorded spelling (ties:
   smallest). A candidate is skipped (next most frequent taken) if its spelling contains a quote character (a
   malformed recording, FiveDirections) or if the relabelled label is not read back by layer 1 as that known program.
6. **Relabel**: the process label `subject <exe> <cmdline>` becomes `subject <replacement> <cmdline'>`
   (`subject None <replacement> <cmdline'>` where the collector records no image path, CADETS / ClearScope style):
   cmdline' = the original command line with every token that names the original program (argv[0], quoted or not,
   with or without path) replaced by the replacement (path if the token had one, else its file name). All other
   arguments are kept. Same uuid, type and display data.
7. Ground truth stays attached to the same nodes (uuids). Check: after relabelling, no renamed node is new to layer 1
   (`still_unknown` = 0, recorded per set).

**What is not changed**: every event, edge, edge type, timestamp and window; every file node (including the
executable image files of the attacker's programs and dropped payloads) and every network node; all node ids. The
labels are changed in the registry before the Runtime is built, so every consumer sees the new identity.

Consequences that are part of the counterfactual and are reported, not corrected:
- Linux / FreeBSD / Android collectors record `EXECUTE` edges from the image file: a dropped payload file written
  from an untrusted source and executed still raises `untrusted_exec` on that file edge (flow evidence intact; the
  optional taint-laundering variant addresses this).
- Windows EDR / OpTC record no EXECUTE: layer 2's `image_exec` links a process to an untrusted written file by the
  process's path. After relabelling the process path is a baseline program, so this link no longer forms (an
  attacker who runs a baseline program does not run the dropped file as itself).
- Layer 2 rule keys contain program names; per-key thresholds relaxed on the baseline (benign alarms of the
  replacement program) now apply to the attacker's processes.

## How program identity enters each detector (held fixed: bundles, models, calibrations)
- **Layer 1** (novelty): `executable(label)` -> program key vs `known_executables`; repeat runs; fleet prevalence.
- **Layer 2** (information-flow tags): tags are per node and flow along edges (identity-free), but program names
  enter rule keys / per-key thresholds (`untrusted_code_network`, `exfiltration`, `tainted_spawn`, `tainted_modify`
  keys = program or "parent -> program"), interpreter detection and the script argument (`script_exec`), the
  Windows `image_exec` path match, and `private_services` ("program|port" known service exception).
- **Detector-1** (Velox) and **detector-2** (ORTHRUS-style TGN): node features = word2vec (fitted on baseline labels)
  of the tokenised full label, i.e. program path AND command line. The TGN neighbour state holds no labels.
- **Detector-3** (behavioural likelihood): `behaviour.entity_keys(label)` -> the strict program key (path-less: the
  command name) is the context of P(object | program, operation); a relabelled process is judged against the
  replacement program's baseline behaviour (exact program -> its directory -> any program).
- **Propagation / corroboration / incidents**: graph and scores only; incident titles use the relabelled program.

## Variants (all on the same windows, one pass per set and transform)
- **P2**: 0.10 as released.
- **F3**: P2 + the learned-only fallback of lab_v09 grid 1/2 F3: learned-only alerts when the learned score is above
  3x the threshold (`learned_floor` 3.0), at most 20 per day (the pre-0.9 daily budget F3 was defined with).
- **L12**: layers 1-2 only (P2's layer hits, zero learned evidence: no corroboration, no learned alerts; =
  baselines_paper anchor13 A0).

Each set is scored once untransformed (`none`, reference) and once transformed (`lotl`). Reference check: P2 on
`none` must reproduce lab_v10 res13 P2 (attacks, TP, FP) exactly on every set; if not, stop and investigate before
reporting.

## Reported
Per attack (16 sets + CLEARSCOPE_E5): detected or not per variant and transform; the first alerting layer / rule of its
ground-truth nodes; set-level TP and FP per host-day. Evidence class of each attack under each variant/transform by
`paper_analysis/evidence13.py`'s rule applied to the new rows (rule_gt / rule_anchor / novelty_gt / novelty_anchor /
corroborated_unanchored / learned_only / missed).
Pooled over the 16 development sets: attacks /30, TP, FP, FP per host-day (71 days), precision, and false incidents
(lab_v10 `inc13.py`, grouping G2 = 0.10 shipped, per host-day).
Highlighted: the 11 novelty-only attacks; attacks rule-detected before that are missed after (and the reverse); how
many attacks F3 recovers over P2 under LotL, and its FP cost.
No decision rule: this is a measurement for the paper, not a release decision.

## Optional variant (iv) taint laundering (only if it is a clean transform; then documented here before it runs)
Copying each attacker-written payload through three intermediate files (layer 2's read attenuation 0.2 per file hop
lifts a fully untrusted payload to 0.6, above the 0.5 alarm level), or delaying its execution by 2 hours.

## Bootstrap confidence intervals (part 2, from existing lab_v10 results; no scoring)
0.10 (P2) on the 16 development sets: `res13-*.json` (attacks, TP, FP, days) and `inc13-final.json` (P2/G2 false
incidents). 10,000 resamples, seed 20261112, percentile 95 % intervals. Statistics are ratios of sums over the
resampled units: detection rate = attacks detected / attacks; FP per host-day = FP / days; false incidents per host-day
= FP incidents / days; precision = TP / (TP + FP). Two schemes:
- **host**: resample the 16 sets with replacement (clustered by set: ATLASv2 h1's 10 attacks move together);
- **family**: resample the 5 dataset families (DARPA E3: CADETS, THEIA, ClearScope, FiveDirections, TRACE; E5:
  THEIA_E5; OpTC: H051/H201/H501; ATLASv2: h1/h2; CARBANAKv2: h1-h5, which share one multi-host attack) with
  replacement, each draw contributing all its sets. Five clusters: the interval is crude and is reported as such.
Output: `results/bootstrap.md`, `results/bootstrap.json` (`scripts/bootstrap.py`).

## Resources
One scoring container at a time (GPU, `-m 18g`, oom-score-adj 800); TRACE alone with `-m 36g` when the host has the
memory (another job trains concurrently: `p5-*`, not touched). No heavy job 17:15-18:00 UTC (production backup). Keep
>= 25 GB free on /. Outputs in the scratch dir, copied to `results/`. Commit only `artifacts/lotl_paper/`, never push.

## Amendment 1 (2026-11-12 05:25 UTC; after reference + LotL scoring of 8 sets had started, before any laundering run)
Corrections: (a) the header's "~05:30" is wrong: this protocol was committed at ~05:05 UTC (commit ff59aa4), before
the first scoring run (05:06). (b) Resources: scoring containers run with oom-score-adj 1000 (not 800): the
concurrent p5-* containers use 800, so with 800 the kernel could have picked a p5 container under memory pressure.
Neither changes a definition.

**Variant (iv) taint laundering is implemented** (`scripts/launder.py`, `--transform launder` = LotL + laundering;
dry run `scripts/survey_launder.py`, no scoring). Definition:
- Payload = a file node F with a recorded path that, in the test windows, is written (a WRITE edge into F, any writer)
  and run by an attacker process P (a ground-truth process or a LotL-renamed one): an EXECUTE edge F -> P, or P an
  interpreter that reads F as its script argument (layer 2's own `_script_of` / `_same_file` test).
- Every WRITE edge into F is redirected to a new file T1 (`<F>.~1`, same directory) and followed (timestamps +1..+6 ns,
  same window, edges appended to the window) by three copies T1 -READ-> c1 -WRITE-> T2 -READ-> c2 -WRITE-> T3
  -READ-> c3 -WRITE-> F. c1..c3: new process nodes labelled with the most frequent baseline label of the host's most
  frequent baseline program (known to layer 1); T1..T3 new file nodes; one set of six nodes per payload. With layer 2's
  read attenuation 0.2 per file hop, a payload written at integrity 0 reaches 0.6 (alarm level 0.5).
- The new nodes are not ground truth (alerts on them count as false positives). Nothing else changes.
- The 2-hour delay alternative is not implemented: moving events changes window membership and order (not a clean
  transform), and layer 2's file integrity does not decay with time (only a process's data integrity does), so a
  delay would not launder a dropped file.
Dry run: payloads exist only where the collector records EXECUTE (CADETS 8, THEIA E3 4, ClearScope E5 1; TRACE not
surveyed yet); Windows sets have none (no EXECUTE events; layer 2's image_exec path link is already broken by the
LotL relabelling), so there laundering = LotL. All sets are scored with the same variants P2 / F3 / L12.
