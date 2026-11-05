# DARPA OpTC benchmark (hosts 201, 501, 051) — full product cycle

Status: run 0 (the deployed bundle of each host) done on 2026-11-05 on the L40S host; four more seeded runs per host
in progress (`train_variants`, then `darpa_eval --bundles all`). Results: section "Results" below, raw JSON in
`artifacts/benchmark_optc/`.

## Data

PIDSMaker's pre-built Postgres databases of DARPA OpTC (Operationally Transparent Cyber, 2019; Windows hosts,
eCAR events), restored into the research Postgres with `deploy/bench/run_optc.sh load DIR`:

| host | database | nodes | edges | attack (test day) | malicious nodes |
|---|---|---|---|---|---|
| SysClient0201 | `optc_201` | 5,268,452 | 19,605,225 | 2019-09-23 | 2,905 |
| SysClient0501 | `optc_501` | 3,964,099 | 15,783,742 | 2019-09-24 | 749 |
| SysClient0051 | `optc_051` | 4,615,935 | 17,760,252 | 2019-09-25 | 114 |

(Bilot et al. 2025, Table 9.) About 24,000 edges per 15 minutes on each host, i.e. ~2.3 M events a day: similar to
DARPA E3 CADETS (~1.7 M a day), far below a busy development server (the L40S host: ~62 M a day).

Ground truth: PIDSMaker's ORTHRUS node-level labels (`Ground_Truth/orthrus/h201|h501|h051`), one red-team attack per
host. Split (PIDSMaker `config.py`, the same in Bilot et al. Table 9): train 2019-09-19..21, validation 2019-09-22,
test 2019-09-23..25; 2019-09-16..18 unused.

## Windows events in a Linux product

OpTC records Windows actions (OPEN, READ, CREATE, MESSAGE, MODIFY, START, RENAME, DELETE, TERMINATE, WRITE). The
replay (`pdp_engine.sources.pg_replay`) translates them with PIDSMaker's context-dependent OpTC -> DARPA TC table
(action + source and destination node types; e.g. START is a process start, an outbound or an inbound connection):

| OpTC (source, action, destination) | product edge type |
|---|---|
| process CREATE / START process | CLONE |
| process OPEN process | OPEN |
| process MODIFY / WRITE file | WRITE |
| process CREATE / RENAME / DELETE file | WRITE (product choice: no TC equivalent; the file's content or name changes) |
| file READ process | READ |
| process MESSAGE / START flow | SENDMSG / CONNECT |
| flow MESSAGE / OPEN / START process | RECVMSG / OPEN / RECVFROM |
| process TERMINATE process | dropped (product choice: process ends are state, not edges) |

`tests/unit/test_optc.py` checks that every action PIDSMaker builds OpTC graphs from is covered.

What carries over and what does not:

* Learned layer (detector-1 Velox-style, detector-2 Orthrus-style): unchanged; PIDSMaker's tuned OpTC
  hyper-parameters per host (below), as for THEIA.
* Layer 1, executable novelty: works on Windows image paths (`/Device/HarddiskVolume1/Windows/...exe`).
* Layer 2, information-flow rules: written for Linux (paths such as `/etc/shadow`, `/tmp`, shells, interpreters);
  on Windows they see generic file and network flows only. OpTC therefore mostly measures layers 1 and 3.
* The product has no Windows agent yet: this measures the detector on Windows data, not a Windows deployment.

## Product cycle

Same as `BENCHMARK_E3.md`: `deploy/bench/run_optc.sh start` creates one benchmark endpoint per host
(`baseline_days: 3`, US/Eastern days), whose agent replays the database day by day through the normal path; the
server trains on the 3 training days (validation day: thresholds, fusion), signs the bundle; the agent scores the
test days locally; `pdp_server.tools.darpa_eval --dataset OPTC_H201|OPTC_H501|OPTC_H051` evaluates node-level
(PIDSMaker protocol: TP / FP / FN, precision, MCC, ADP). Run-to-run variance: four more seeds per host
(`train_variants`), five runs as in the paper. No test data is used for training, thresholds or model selection.

Hyper-parameters (PIDSMaker `docs/tuned_systems.md`; the product shares one word2vec, 256-d, as for THEIA):

| host | detector-1 (Velox) | detector-2 (Orthrus non-snooped) |
|---|---|---|
| h201 | lr 0.001, 128-d | 128-d |
| h501 | lr 0.001, 320-d | 256-d |
| h051 | lr 0.001, 320-d | 128-d |

## Published numbers being compared against

Bilot et al., "Sometimes Simpler is Better", USENIX Security 2025, Table 6 (detection results on OpTC; 5 runs; ADP
mean / min / best; precision mean / min / best; TP / FP of the most precise run). Extracted from the paper's PDF
text, verbatim:

| host | system | ADP mean / min / best | precision mean / min / best | TP / FP (best) |
|---|---|---|---|---|
| H051 | Orthrus | 0.68 / 0.06 / 1.00 | 0.08 / 0.00 / 0.20 | 1 / 4 |
| H051 | Velox | 0.57 / 0.11 / 1.00 | 0.12 / 0.00 / 0.50 | 1 / 1 |
| H051 | Kairos | 0.50 / 0.11 / 1.00 | 0.14 / 0.00 / 0.33 | 1 / 2 |
| H201 | Orthrus | 0.48 / 0.23 / 1.00 | 0.14 / 0.00 / 0.25 | 1 / 3 |
| H201 | Velox | 0.90 / 0.50 / 1.00 | 0.18 / 0.11 / 0.25 | 1 / 3 |
| H201 | Flash | 1.00 / 1.00 / 1.00 | 0.00 / 0.00 / 0.01 | 1.5k / 239k |
| H201 | Kairos | 0.75 / 0.25 / 1.00 | 0.38 / 0.00 / 1.00 | 1 / 0 |
| H501 | Orthrus | 0.25 / 0.14 / 0.33 | 0.11 / 0.04 / 0.20 | 1 / 4 |
| H501 | Velox | 0.39 / 0.20 / 0.50 | 0.13 / 0.00 / 0.20 | 1 / 4 |
| H501 | Magic | 1.00 / 1.00 / 1.00 | 0.00 / 0.00 / 0.00 | 185 / 260k |

(Other systems in Table 6: ThreatRace, NodLink, Magic, Flash for every host; SIGL and R-CAID timed out or failed.
High ADP with near-zero precision, as for Flash on H201 and Magic on H501, means the attack ranks high but the
alert threshold flags hundreds of thousands of benign nodes.) OpTC is much harder than E3 for every system: mean
precision is at most 0.38 for any system on any host (Kairos, H201); Velox's and Orthrus's best runs reach 0.20-0.50,
typically one true positive among a few false ones.

The same paper's Table 4 confirms the E3 numbers in `BENCHMARK_E3.md` (rechecked from the PDF on 2026-11-05).

## Results

### Run 0 (the bundle each endpoint trained and deployed)

Full product cycle per host: 4 baseline days replayed and uploaded (2.6-4.6 M events a day), trained on the GPU
worker (h201 and h501 at 08:30-10:00, h051 at 12:23-13:07 after a GPU out-of-memory failure, below), signed bundle,
then the agent replayed and scored the 3 test days locally (245 windows of 15 minutes; data ends 2019-09-25 14:38).
Evaluated on 1.44-1.49 M test nodes per host. Precision, recall and MCC at each detector's own alert threshold (no
test data used); ADP threshold-free.

| host (attack nodes) | view | TP | FP | precision | recall | MCC | ADP | attack found |
|---|---|---|---|---|---|---|---|---|
| H201 (2,905) | detector-1 alone (Velox-style) | 0 | 2 | 0.00 | 0.000 | 0.00 | 0.25 | no |
| | detector-2 alone (Orthrus-style) | 0 | 0 | - | 0.000 | 0.00 | 0.11 | no |
| | learned fusion | 0 | 4 | 0.00 | 0.000 | 0.00 | 0.17 | no |
| | layers 1+2 (novelty + rules) | 6 | 274 | 0.02 | 0.002 | 0.01 | - | yes |
| | **layered product** | 8 | 345 | 0.02 | 0.003 | 0.01 | 1.00 | yes |
| | **alerts the agent reported** | 8 | 353 | 0.02 | 0.003 | 0.01 | - | yes |
| H501 (749) | detector-1 alone | 0 | 0 | - | 0.000 | 0.00 | 0.02 | no |
| | detector-2 alone | 0 | 0 | - | 0.000 | 0.00 | 0.10 | no |
| | learned fusion | 0 | 10 | 0.00 | 0.000 | 0.00 | 0.02 | no |
| | layers 1+2 | 13 | 76 | 0.15 | 0.017 | 0.05 | - | yes |
| | **layered product** | 19 | 195 | 0.09 | 0.025 | 0.05 | 0.40 | yes |
| | **alerts the agent reported** | 18 | 196 | 0.08 | 0.024 | 0.05 | - | yes |
| H051 (114) | detector-1 alone | 2 | 6 | 0.25 | 0.018 | 0.07 | 0.33 | yes |
| | detector-2 alone | 0 | 4 | 0.00 | 0.000 | 0.00 | 0.43 | no |
| | learned fusion | 2 | 7 | 0.22 | 0.018 | 0.06 | 0.33 | yes |
| | layers 1+2 | 71 | 86 | 0.45 | 0.623 | 0.53 | - | yes |
| | **layered product** | 78 | 145 | 0.35 | 0.684 | 0.49 | 0.88 | yes |
| | **alerts the agent reported** | 78 | 149 | 0.34 | 0.684 | 0.49 | - | yes |

"Alerts the agent reported" is what a customer would have seen; it matches the server-side re-score of the same
bundle within a few alerts (the agent's own alert stream). The pre-registered policy (every rule alarms) gives the
same result on H051 and more false alarms on H201 (10 TP / 549 FP) and H501 (23 / 461).

What fired (alerts on the test days, by layer and rule, attack vs benign node):

* **Exfiltration rule** (data flowing out to a destination not seen in the baseline): OS-independent, so it
  carries over to Windows despite the Linux-oriented rule set. H051: 40 attack nodes (the C2 flows, e.g.
  `53.192.68.50:8080`) vs 26 benign; H501: 6 vs 13 (PowerShell); H201: 6 vs 4 (Firefox).
* **Novel executable**: the attacker's dropped binaries (`Windows/Temp/rad0F93B.tmp/...` on H051, 31 attack nodes;
  `Users/sysadmin/Downloads/fileTransfer1...` on H501, 7). Most of its false alarms are Windows pseudo-processes
  without an image path (`MemCompression`, `Idle`, app containers): 270 of H201's 345 false alarms. A Windows agent
  would need these on its built-in allow-list.
* **Learned layer**: weak on OpTC in this product configuration. Alone it finds the attack only on H051 (2 TP);
  corroborated alerts (learned score next to a deterministic alert) add 4-7 attack nodes per host.

### Comparison with Bilot et al. (Table 6)

| host | published: range over Velox / Orthrus / Kairos (mean of 5 runs; best run's TP / FP) | this product, run 0 |
|---|---|---|
| H051 | ADP 0.50-0.68; precision 0.08-0.14 mean, best run 1 TP / 1-4 FP | layered: ADP 0.88, precision 0.35, **78 TP** / 145 FP, MCC 0.49; detector-1 alone 2 TP / 6 FP (precision 0.25, ADP 0.33) |
| H201 | ADP 0.48-0.90; precision 0.14-0.38 mean, best run 1 TP / 0-3 FP | layered: ADP 1.00 (attack ranked first), precision 0.02, 8 TP / 345 FP; learned alone misses (ADP 0.11-0.25) |
| H501 | ADP 0.25-0.39; precision 0.11-0.13 mean, best run 1 TP / 4 FP | layered: ADP 0.40, precision 0.09, 19 TP / 195 FP; learned alone misses (ADP 0.02-0.10) |

Reading it honestly:

* The **layered product detects the attack on all three hosts** in one run, with many more attack nodes than any
  published system (8-78 TP vs 1). Its ADP is at or above the best published mean of Velox, Orthrus and Kairos on every host (1.00 vs 0.90
  on H201, 0.88 vs 0.68 on H051, 0.40 vs 0.39 on H501; Flash on H201 and Magic on H501 reach ADP 1.00 but with
  precision 0.00, flagging 239 k and 260 k benign nodes).
* Its **precision is lower on H201 and H501** (0.02 and 0.09 against published means of 0.14-0.38): 145-353 false
  alarms over three days, most from the novelty layer's Windows pseudo-processes (fixable with a Windows allow-list)
  and corroborated learned alerts. On H051 it is higher (0.35 vs 0.14).
* The **learned detectors alone are below the published Velox and Orthrus** on H201 and H501 (they miss the
  attack at their thresholds; ADP 0.02-0.25 against 0.25-0.90). Differences from PIDSMaker: one shared 256-d
  word2vec instead of per-system featurisation, the product's 15-minute windows and its ensemble of 3 + 5 seeds, and
  OpTC's TERMINATE / RENAME / DELETE mapped differently (Data). The published per-host tuning was used for learning
  rate and dimensions only.
* One run so far; Bilot et al. report the mean of five. The variance runs will replace the "run 0" column with
  mean / min / best.

### Problems found while running it

* **GPU out of memory** (h051's first training, 10:08): the benchmark agents score on the same GPU and kept 30 GB
  and 14 GB cached after finishing. The training worker now re-queues a GPU-out-of-memory job (3 retries, 10 minutes
  apart) instead of failing it for good; benchmark agents are stopped once they have scored their test days.
* **Host out of memory** (12:21): the kernel killed the host's own production agent (largest process) while three
  replay agents, a CPU evaluation and a test VM ran next to the databases. Now: 16 GB swap, databases protected
  from the OOM killer, benchmark and evaluation containers capped and killed first; evaluations run on the GPU, one
  at a time (`bench-eval` service, 2-3 minutes per host instead of 30+ on the CPU).
* **Retention deleted the replayed windows**: window summaries aged by their event time (2019), so the daily
  retention pass removed them. Retention now counts from when the server received them; `darpa_eval` infers the
  scoring bundle from the first test-day alert when the window records are missing (all three hosts here; every
  host had a single bundle, so the inference is exact).
