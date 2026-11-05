# DARPA OpTC benchmark (hosts 201, 501, 051) — full product cycle

Status: prepared 2026-11-05 (code, configuration, published numbers); runs once the data is loaded. Results: section
"Results" below, raw JSON in `artifacts/benchmark_optc/`.

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

(pending: filled from `darpa_eval` once the runs finish)
