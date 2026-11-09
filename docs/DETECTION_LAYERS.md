# Layered detection (0.3, revised in 0.4-0.10)

## 0.10 (2026-11-09): fleet prevalence and incident grouping

Asked for: "do the incident grouping and program prevalence" - the two next steps of the 0.9 review (most 0.9 false
positives were new-program alerts; analysts work incidents, not alerted nodes). Lab, protocol (variants and choice
rules written before each grid ran) and decision record: artifacts/lab_v10.

**Fleet prevalence (layer 1).** A program new on one endpoint but run during the baselines of at least two *other*
endpoints of its organisation (their bundles' known programs, i.e. training days only, never live activity) raises no
new-program alert. The server computes the list per endpoint (pdp_server.fleet) and sends it with the configuration
(only when it changes, by hash); the agent's layer 1 applies it (NoveltyLayer.set_fleet). The data-flow rules and the
learned layer still see everything such a program does. Settings (endpoint configuration): `fleet_prevalence`
drop (default) | evidence (alert only when the learned score corroborates, at most once per program and day) | off;
`fleet_min_endpoints` (default 2: one endpoint's poisoned baseline cannot make a program known); `fleet` (a label:
endpoints with the same label form a fleet; default: the organisation's live endpoints; benchmark / simulation
endpoints are alone). Lowering the strictness, the number of endpoints, or joining a fleet is a weakening (reason
required, audited).

**Incident grouping.** The same finding (same endpoint, same subject - the full path of the acting program of the
incident's top alert, or its address; findings with no recorded program never merge) coming back within 7 days of its incident's last alert joins that incident instead of opening a new
one (incidents.RECUR_NS; ids stay stable). Severity, tactics and status are recomputed over all its alerts, so new
open alerts reopen it and an attack joining it raises its severity.

**Also fixed:** the agent applied the allow list's trusted addresses and suppressed detections to the first model only;
a new model (early models being replaced, periodic retraining) ran without them until the allow list changed.

16 dev / seen sets (71 host-days), 0.9 -> 0.10:

| | attacks | true alerts | false alerts (per day) | precision | false incidents (per host-day) | incidents |
|---|---|---|---|---|---|---|
| 0.9 | 26/30 | 337 | 1,189 (16.7) | 0.221 | 284 (4.0) | 354 |
| **0.10** | 26/30 | 333 | **1,051 (14.8)** | 0.241 | **178 (2.51)** | 220 |

Prevalence acts where hosts share software (CARBANAKv2 h1-h5: 530 -> 399 false alerts); with one other host
(ATLASv2) or different OSes (DARPA E3) it changes little. Grouping is where the analyst's load drops: -37 % false
incidents, no attack lost or buried. FiveDirections' 166 false alerts are 6 incidents (2 per day). Variants not chosen:
prevalence from one other endpoint (P1: fewer false alerts, 973, but rejected - attack-node recall fell below the
floor, the attackers' Windows tools ran on other hosts too), evidence mode (P2e: +24 false alerts, no true one gained),
24 h and 2 h-gap grouping (194 / 208 false incidents). Held-out: ClearScope E5 is a single host (prevalence cannot act);
its incident metrics are reported with the 0.9 check once the disk is freed.

## 0.9 (2026-11-08): the false-positive fixes (0.8.1 corroboration + 0.9 alerting defaults)

Asked for: fix the false-positive blow-up of the released 0.7 configuration found on the 0.8 held-out hosts, then make
the best version much better on false positives. Lab, protocol (each grid's choice rule written before it ran) and
decision record: artifacts/lab_v09. Detection itself (detectors 1-3, propagation, layers 1-2) is unchanged; only
which scores turn into alerts.

**0.8.1 - circular corroboration.** A learned score "corroborates" a layer-1/2 alert when a window neighbour of the
alert is above the learned threshold. With 0.7's propagation, the alerted node's own suspicion flows to what it
touches, so its neighbours rose above the threshold *because of the alert* and then confirmed it. On CARBANAKv2 h1 one
alerted Windows Update process (`poqexec.exe`) wrote ~3,500 `winsxs` files: 3,478 corroborated alerts, none true.
Fix: a neighbour corroborates on its own score in the window (before propagation; runtime `NEAR_ALERT_SCORE = "own"`,
bundle `learned_policy.near_alert_score`). Evidence-rule corroboration (repeat runs, tainted rules) keeps the propagated
score: there the flagged node itself is the subject and suspicion from its parents is real evidence.

**0.9 - alerting defaults.** After 0.8.1 the alerts raised by the learned score alone were 779 alerts with 5 true
(0.6 % precise), and no attack on any of the 16 sets was found only by them; repeat runs of one new program were
corroborated dozens of times (one program 48 times). Defaults now: no learned-only alerts (`learned_daily_budget 0`;
the learned layer still corroborates layer-1/2 hits and ranks everything), and at most one corroborated repeat run per
new program per day (`repeat_corroborations 1`). Both apply to bundles trained before 0.9 through the runtime
defaults; an endpoint's own budget setting still overrides. Raising the corroboration threshold instead (1.5x / 2x)
lost ATLASv2 attacks and was rejected.

Development / seen data, 16 sets (none of it held-out any more), end to end through the runtime:

| set | 0.7 released: attacks, TP / FP | 0.8.1: TP / FP | 0.9: attacks, TP / FP (per day) |
|---|---|---|---|
| CADETS E3 | 3/3, 32 / 42 | 32 / 42 | 3/3, 31 / 16 (4.0) |
| THEIA E3 | 2/2, 111 / 127 | 110 / 124 | 2/2, 109 / 86 (28.7) |
| OpTC H201 | 1/1, 7 / 42 | 7 / 42 | 1/1, 6 / 19 (6.3) |
| OpTC H501 | 1/1, 19 / 132 | 19 / 102 | 1/1, 17 / 77 (25.7) |
| OpTC H051 | 1/1, 76 / 58 | 75 / 57 | 1/1, 75 / 53 (17.7) |
| ClearScope E3 | 0/1, 0 / 51 | 0 / 51 | 0/1, 0 / 0 |
| FiveDirections E3 | 2/2, 11 / 225 | 11 / 221 | 2/2, 11 / 166 (55.3) |
| ATLASv2 h1 | 8/10, 14 / 125 | 13 / 86 | 8/10, 12 / 49 |
| ATLASv2 h2 (no attack) | 0 / 36 | 0 / 36 | 0 / 26 |
| TRACE | 3/3, 9 / 81 | 9 / 80 | 3/3, 9 / 70 (17.5) |
| CARBANAKv2 h1 | 1/1, 5 / 3,756 | 5 / 285 | 1/1, 5 / 123 (15.4) |
| CARBANAKv2 h2 | 1/1, 40 / 220 | 40 / 220 | 1/1, 40 / 164 (18.2) |
| CARBANAKv2 h3 | 1/1, 2 / 269 | 2 / 222 | 1/1, 2 / 86 (12.3) |
| CARBANAKv2 h4 | 1/1, 3 / 64 | 3 / 64 | 1/1, 3 / 27 (3.9) |
| CARBANAKv2 h5 | 1/1, 18 / 313 | 18 / 274 | 1/1, 17 / 130 (11.8) |
| THEIA E5 | 0/1, 0 / 129 | 0 / 128 | 0/1, 0 / 97 (48.5) |
| **total** | **26/30, 347 / 5,670 (79.9 a day), precision 0.058, node recall 0.294** | 344 / 2,034 | **26/30, 337 / 1,189 (16.7 a day), precision 0.221, node recall 0.285** |

On the six 0.8 held-out hosts (CARBANAKv2 h1-h5, THEIA E5; now seen): 0.6 5/6, 58 TP / 488 FP; 0.7 released 5/6,
68 / 4,751; 0.9 5/6, 67 / 627. What is left: new-program alerts (Windows system programs that did not run during a
short baseline look exactly like living-off-the-land attack steps - mstsc, control, qwinsta - so they are not filtered
by name), rule alerts on other instances of programs the ground truth labels as attack, and corroboration of
processes recorded without a program or command line (FiveDirections). A learned-only floor of 3x the threshold (F3)
also found the ClearScope E3 attack (27/30) for 6 % more false positives; not chosen under the pre-registered rule.
Held-out: CLEARSCOPE_E5, prepared but not yet scored (see the decision record).

## 0.8 (2026-11-08): process-chain evidence ("breadth") - tried, not released as the default

Asked for: score process chains so that layer 1 ("new executable") can be dropped, then test on clean data. Lab,
protocol (written before any end-to-end result) and decision record: artifacts/lab_v08.

**Why 0.7 needed layer 1.** On TRACE, detector-3 scored each node by its single most unusual event. A busy host's
most unusual benign processes are single extreme events - a tool reading a directory it has never read (`du`, `df`,
`lsb_release`: 50-73 nats) - while the attack was many linked, moderately unusual steps (a program from /tmp that
starts `uname` and `sh`, connects out and writes files: ~22-25 nats each). One maximum per node always ranks the
benign singles first.

**Breadth evidence** (`behaviour.Breadth`, `TrainConfig.d3_breadth`): per process instance, the most unusual event of
each kind of activity - starting / being started by a process, network, writing files, reading files - within 4
hours, each capped at 10 nats (beyond that a rarity estimate says nothing more) and counted above a 4-nat floor
(everyday mild novelty); the process's evidence is their sum. Unusual in several ways at once is what attack steps
look like; one extreme event no longer outranks them. Objects (files, addresses) keep a capped maximum and rise by
propagation from the processes that touch them. Calibrated like 0.7 (10 benign validation nodes over the
threshold, the threshold never below one fully novel kind of activity), streamed over the validation day exactly as
the runtime scores. Tried and rejected offline (detector-3 alone, 10 sets): summing evidence along the process tree
(more false positives on every set), per-endpoint normalised caps (fewer attacks than caps in nats), six activity
groups instead of four, shorter or longer horizons (little difference).

Learning integrity (released): every entity an unreleased alert was raised on, whatever layer raised it, stays out of
detector-3's counts on retraining (with layer 1 off a new program is often caught by the learned layer alone).
Agent 0.8.0 (bundles require `detector-3-breadth`).

### Development / seen sets (end to end, same source bundles; 0.7 released re-run through the same harness)

| set | 0.7 released (layer 1 on): TP / FP (per day) / attacks | 0.8 (layer 1 off) |
|---|---|---|
| CADETS | 32 / 42 (10.5) / 3 of 3 | 33 / 29 (7.2) / 3 of 3 |
| THEIA | 111 / 127 (42.3) / 2 of 2 | 109 / 129 (43.0) / 2 of 2 |
| OpTC H201 | 7 / 42 (14.0) / 1 of 1 | 8 / 8 (2.7) / 1 of 1 |
| OpTC H501 | 19 / 132 (44.0) / 1 of 1 | 12 / 24 (8.0) / 1 of 1 |
| OpTC H051 | 76 / 58 (19.3) / 1 of 1 | 69 / 41 (13.7) / 1 of 1 |
| ClearScope | 0 / 51 (25.5) / 0 of 1 | 0 / 41 (20.5) / 0 of 1 |
| FiveDirections | 11 / 225 (75.0) / 2 of 2 | 4 / 40 (13.3) / 2 of 2 |
| ATLASv2 h1 | 14 / 125 / 8 of 10 | 10 / 111 / 8 of 10 |
| ATLASv2 h2 (no labelled attack) | 0 / 36 | 0 / 68 |
| TRACE | 9 / 81 (20.2) / 3 of 3 - all from layer 1 | 4 / 39 (9.8) / 3 of 3 - all from the learned layer |
| mean | 21 of 34 attacks, 41.2 FP/day, node recall 0.306 | 21 of 34 attacks, 29.7 FP/day, node recall 0.266 |

The same attacks on every set without layer 1, with 28% fewer false positives. Pre-registered acceptance rule 3
(node recall not below 0.7's) was **not met**: layer 1 alerted on each of an attack's new executables one by one
(TRACE 9 nodes vs 4) and corroboration added their neighbours (FiveDirections, ATLASv2 h1); 0.8 finds the same
attacks through fewer of their nodes. Corroboration at the 99.9th percentile instead of the threshold recovered
little (0.276) for 4 more false positives a day. ATLASv2 h2 is worse (68 vs 36; 12 of them are the multi-host
attack's payload.exe, which the ground truth labels only on h1).

### Held-out (scored once, after freezing): see docs/BENCHMARK_HELDOUT.md "0.8"

| | 0.6 | 0.7 released (production) | 0.8 |
|---|---|---|---|
| CARBANAKv2 h1-h5 + THEIA E5 (6 attacks) | 5 of 6, 488 FP | 5 of 6, 4,751 FP | 4 of 6, 603 FP |

**Decision (pre-registered rule): not released.** 0.8 missed the CARBANAKv2 h3 attack, which only layer 1 caught;
its learned alerts on that host (all false) ran at the daily budget. Breadth stays in the product, off by default
(`train.d3_breadth`, per endpoint); layer 1 stays on, and turning it off is a weakening change as in 0.7. What 0.8
showed: breadth replaces layer 1 on TRACE and keeps every attack on the development / seen sets with fewer false
positives, but new programs on Windows EDR telemetry are still a signal the learned layer alone does not catch.

**Found on the held-out data about the released 0.7 configuration:** corroboration next to layer-1 alerts produced
3,511 false positives on CARBANAKv2 h1 (470 a day), and on these hosts 0.7 found the same attacks as 0.6 with ten
times its false positives. Not tuned here (this data is now seen); open.

## 0.7 (2026-11-07): learned detection first, rules on top

Asked for: the learned part as the primary detector, recall first, and no stand-alone naive rules such as "new
executable seen" - the learned model has to catch that. Lab, protocol and decision record: artifacts/lab_v07
(PROTOCOL.md was written before any result and records, before the held-out run, that one acceptance rule failed).

**Detector-3: behavioural likelihood** (`pdp_engine.behaviour`, bundle files detector-3.npz / -vocab.json). Per
endpoint, from its own baseline, a hierarchical Witten-Bell model of P(object | program, operation, direction):
programs back off exact program -> program directory -> any program, objects back off exact object -> directory or
remote address -> class (top directory + extension, address class + port bucket, "process"). A known program doing
what it has done before scores ~0; a program doing something new for it scores by how new it is and by how often this
program does new things at all (an installer writes new files all the time; a web server never starts a program from
/tmp). A program with plenty of history doing an operation it has never done (a web server starting a process) pays
for that once per process instance. Novelty is paid once per process instance and window: the j-th new file the same
installer run writes into one directory costs at most log(1 + j). GUIDs, hex ids, random tokens and digit runs are
generalised. A never-seen program is judged by its directory and the endpoint - this is how the new-executable case
is covered without alerting on every update. Fitting is counting (seconds to minutes on a CPU); unreleased alerts'
programs and addresses stay out of the counts (`learning.exclude_nodes`).

**One learned score.** max(detector-1/2 fusion, detector-3), each in units of a threshold that lets 10 benign
validation nodes through (`calibration_budget`, 0.3-0.6 used the validation maximum), then **learned-seeded
propagation**: every unusual data-flow edge (detector-3 edge score >= 0.4 x its threshold; OPEN excluded) carries
0.95 x the source's suspicion (clipped at 3x) to its destination, two hops per window, carried across windows - a
download, the file it wrote and the process that ran it rise together, while a suspicious process does not taint every
library it reads. The final threshold is calibrated after propagation by replaying the validation day through the
runtime itself (`Trainer.calibrate_final`).

**Alerting (released configuration).** Learned alerts are on (at most 20 per endpoint per day, in stream order).
Layer 2 (the information-flow rules) alerts as before. A learned score corroborates a rule hit, or alerts next to a
rule alert, only above the learned threshold itself (`corroboration_at_threshold`; the 99.9th percentile of the 0.7
score added hundreds of false positives next to rule alerts). Layer 1 (new executable) was to be dropped - it was
the source of most false positives on the development sets (CADETS 14 of 15, OpTC H201 14 of 18) and added no
attack there - but on the held-out TRACE host it was the only layer that caught the attacks (below), so it stays as a
safety net (decision by the user, 2026-11-07). Console setting changes that turn detector-3, propagation, layer 1
or learned alerts off, or raise the learned thresholds, are weakening changes (reason required, audited); the floor
is "the learned layer or the data-flow rules can alert".

**Collector.** The eBPF collector traces data on connected sockets (read/write/send/recv/sendfile/splice/io_uring,
agent 0.7.0; docs/DEPLOYMENT.md): a download over HTTPS now links the remote endpoint to the process that read it.

### Result of the configuration frozen before the held-out run (layer 1 off; end to end: bundle upgraded with
`upgrade_bundle_07`, test days scored by the runtime, streaming)

0.6 = the 0.6 layer defaults on the same bundles, scored by the same code.

| set | 0.7 TP / FP (per day) / attacks | 0.6 TP / FP / attacks |
|---|---|---|
| CADETS (development) | 33 / 28 (7.0) / 3 of 3 | 33 / 40 / 3 of 3 |
| THEIA (development) | 112 / 113 (37.7) / 2 of 2 | 108 / 136 / 2 of 2 |
| OpTC H201 (development) | 14 / 52 (17.3) / 1 of 1 | 18 / 193 / 1 of 1 |
| OpTC H501 (seen before) | 18 / 132 / 1 of 1 | 16 / 59 / 1 of 1 |
| OpTC H051 (seen before) | 78 / 105 / 1 of 1 | 73 / 72 / 1 of 1 |
| ClearScope (seen before) | 0 / 51 / 0 of 1 | 0 / 45 / 0 of 1 |
| FiveDirections (seen before) | 5 / 45 / 2 of 2 | 1 / 47 / 1 of 2 |

What it achieved: the same attacks on the development sets with about half the false positives (20.7 vs 39.9 per day
on average), and one more attack on the telemetry-poor sets, which detector-3 reaches where the rules see nothing.
What it did not achieve: the recall gain that was the goal. Mean ground-truth node recall on the development sets is
0.480 vs 0.469 (the pre-registered target was 1.5x); the learned detectors find few attack nodes the data-flow layer
misses. Known weaknesses: corroboration adds many false positives on OpTC H501/H051 (96 and 70); the streaming daily
budget can be used up by benign anomalies before an attack arrives (ClearScope: found by an after-the-fact top-20,
missed live).

### Held-out (run once, docs/BENCHMARK_HELDOUT.md "0.7") and the released configuration

| | ATLASv2 h1 (Windows EDR, 10 attacks) | ATLASv2 h2 (no attack) | TRACE (Linux, 3 attacks) |
|---|---|---|---|
| 0.6 | 4 of 10, 46 FP | 26 FP | 3 of 3, 69 FP (4 days) |
| 0.7 as frozen (layer 1 off) | 8 of 10, 139 FP | 39 FP | **0 of 3**, 10 FP |

TRACE: 0.6 caught all three attacks through layer 1; the information-flow layer had no baseline addresses there, and
detector-3 scored the attack processes (programs started from /tmp, a dropped `tcexec` running `uname` and `sh`) in
the top 0.1% of nodes but at 0.4-0.8 of a threshold set by a busy host's ten most unusual benign nodes per day - one
maximum score per node cannot tell one strange benign event from a chain of moderately strange attack steps. Three
changes were then measured on all sets (TRACE and ATLASv2 count as seen from here on, so their numbers below are no
longer held-out results): new-program hits as evidence only (false positives exploded through corroboration),
per-activity detector-3 thresholds (`d3_grouped`, no TRACE detection, 635 false positives on THEIA), and the released
one, layer 1 alerting with corroboration at the learned threshold:

| set | released 0.7: TP / FP / attacks |
|---|---|
| CADETS / THEIA / OpTC H201 (development) | 32 / 42 / 3 of 3; 111 / 127 / 2 of 2; 7 / 42 / 1 of 1 (22.3 FP per day on average; 0.6: 39.9) |
| OpTC H501 / H051, ClearScope, FiveDirections (seen) | 1 of 1 (132 FP), 1 of 1 (58), 0 of 1 (51), 2 of 2 (225) |
| ATLASv2 h1 / h2, TRACE (seen after the held-out run) | 8 of 10 (125 FP), 0 FP-only (36), 3 of 3 (81) |

Open: the learned layer does not yet catch TRACE-style new-program attacks on a busy host by itself (evidence
accumulation along a process chain, instead of one maximum per node, is the next thing to try); corroboration and the
daily budget still produce many false positives on FiveDirections and ATLASv2 h1.

## 0.6 (2026-11-06): resistance to evasion, poisoning, tampering and misuse

A code review of the engine, the agent and the control plane (three independent read-only audits) looked for ways
an attacker on a host, or an insider with console access, could make an attack invisible without anyone noticing.
Everything below is general (no program, path, address or dataset names in the logic beyond OS conventions such as
autostart locations and interpreter names).

**Layers 1-2: evasion paths closed** (`LayerConfig`; on for new fits, a layers.json fitted earlier keeps its
behaviour until re-fitted with `tools.add_layers`):

| setting | evasion it closes |
|---|---|
| `strict_program_key` | `/tmp/fedcba9876543210` matched any hex-named baseline program (the file name was collapsed to `{id}`); `/tmp/LS` matched `/tmp/ls` (POSIX paths were case-folded). Now only directory components collapse, only Windows programs are case-folded |
| `strict_addresses` | `1.2.3.4%x` or `[2001:db8::1]` failed to parse and so counted as a local, trusted address |
| `script_exec` | `python3 /tmp/payload.py`, `bash x.sh`, `powershell -File x.ps1`: the interpreter is a known program and the script is only *read*, so a downloaded script never raised `untrusted_exec` and its C2 never `untrusted_code_network`. The script argument read by a known interpreter is now executed code |
| `socket_io` | `read()` / `write()` on a socket (DARPA-style READ / WRITE edges to a netflow) were not receive / send: no download taint, no exfiltration check |
| `persistence` | new alarm `untrusted_persistence`: a process holding untrusted code or data writes an autostart location (cron, systemd / init, shell rc files, `authorized_keys`, `ld.so.preload`, desktop autostart, launchd, Windows Tasks and Startup folders); new files there were invisible to `tainted_modify` (pre-existing files only) - "cron persistence not detected" was an open limitation |
| `late_exfil` | connect first, then read `/etc/shadow`, then write to the socket: exfiltration was checked only at send time with what had been read before |
| (always) | the untrusted-file memory of `image_exec` is bounded (a flood of distinct paths could exhaust the agent's memory and turn detection off); an overflowing learned score ranks first instead of last |

Not adopted (lab_v06): `connect_receives` (taint a process on any connection to an untrusted address, for
collectors that see `connect()` but not `read()` on sockets) added 150-2000 false positives on OpTC; the stricter
retrain rules (`recurring_trust`, `relax_min_days`: what is new since the previous model must recur on two days)
added 56 on THEIA in a retrain simulation. Both remain available, off by default.

**Learning integrity** (`pdp_server/learning.py`): a model is retrained on the endpoint's recent days, so an attacker
active before the first model or between retrainings would become "normal". Now
- everything an alert of the endpoint points at - the programs of new-program / untrusted-exec alerts, alerted
  remote addresses, the (rule, key) of rule alerts - stays out of the new model's known programs, trusted addresses
  and relaxed thresholds, unless an administrator resolved that alert as benign (false positive or closed, or an
  allow-list entry). Open, acknowledged, true-positive alerts and analyst verdicts release nothing. Only alerts about
  activity up to the end of the learned days count. The bundle manifest records what was excluded;
- false-positive verdicts become benign training windows only when an administrator gave them (or an allow-list
  entry); before 0.6 any analyst's verdict - or a whole incident marked false positive in one click - taught the next
  model the attack.

**Collector**: the eBPF collector recorded exec paths as passed to `execve()`: `execve("ls")` from `/tmp` looked like
the system `ls` (a bare name matches a known program), and `./x` never met the taint of the file the download wrote
as `/tmp/x`. Relative and dotted paths are now resolved like opened files; `fexecve` of a memfd is named by its image
(`/memfd:name (deleted)`), not `/dev/fd/N`.

**Endpoint signal integrity** (agent 0.6.0, `pdp_server/integrity.py`, docs/PROTOCOL.md "Integrity of the endpoint
signal (0.6)"): heartbeat sequence numbers (replay), collector liveness and a canary (a stopped or detached collector
on a live agent), window / alert sequence numbers with gap detection (alerts dropped on the host), the loaded model's
id, digest and signing key compared with the server's (a swapped model or key), the local configuration digest,
clock skew, guarded scoring (a window that crashes the detector is skipped and reported instead of crash-looping),
bounded ingest. **Misuse resistance** (docs/CONSOLE_API.md "Misuse resistance (0.6)"): typed and range-checked
settings; changes that weaken detection need a reason, are audited with a before/after diff and notified to the
organisation as `detection_weakened`; program approvals only through the allow list, full paths, interpreters only
with an explicit confirmation; per-endpoint detection posture; scoped hunts; bounded, audited exports; rate limits.

**What remains** (no change in 0.6): a root attacker who fully emulates the agent is not detectable without host
attestation; the live eBPF collector of agent <= 0.6 does not trace `read()` / `write()` on TCP sockets, so a
download over HTTPS taints only through layer 1 (a new program) - the file it wrote is not untrusted content (built
for the next agent release on 2026-11-07, not yet released: read / write / send / recv on connected sockets become
READ / WRITE / RECVFROM / SENDTO / ... edges to the connect's netflow node, which `socket_io` already treats as
receive / send - docs/DEPLOYMENT.md §1 "Data on connected sockets"; the strace / auditd collectors still lack them);
taint decays with a one-hour half-life and attenuates per file hop (Morse / CAPTAIN design: an
attacker who waits, or copies a payload three times, launders layer-2 taint - layer 1 still flags a new program);
approvals and known programs are by path, not by content hash.

## 0.5 (2026-11-06): the learned detectors

Layers 1-2 and the alert policy are unchanged; 0.5 changes how detector-1 (Velox) is trained and how the two
learned detectors are fused. Nothing is per dataset or per client: one default for every endpoint, chosen on the
development sets only (protocol, lab scripts and logs: `artifacts/lab_v05/`).

| change | setting (`TrainConfig`) | why |
|---|---|---|
| Detector-1 structural input = the published Velox's reindexer input: per 1024-edge batch a node that both sends and receives gets its features scaled by 1 + 1/k (k = its in-count in the batch) | `velox_input = "batch_scale"` (`models.batch_role_scale`) | Velox has no message passing; the only structure it sees comes from PIDSMaker's GraphReindexer double scatter-mean, which our port had replaced with window degrees. Without any structure detector-1 is useless (CADETS ADP 0.008); window degrees do not reproduce it (0.13); batch_scale does (0.36-0.60) |
| Learning rate 1e-3 (was 1e-4) | `velox_lr` | PIDSMaker's tuned value on 6 of its 8 Velox datasets; >= 1e-4 on THEIA, equal within seed noise on CADETS / H201 |
| The weights of the 3 epochs with the lowest validation loss are averaged | `velox_average_top = 3` | same mean ADP as the single best epoch, worst seed better (0.09 vs 0.04); no inference cost |
| Fusion = max of the two detectors' threshold ratios (was 2:1 weighted mean) | `fusion_mode = "max"` | the stronger detector differs per dataset (CADETS: detector-2, THEIA: detector-1); max has no weight to choose and was best on the development mean (0.65 vs 0.52 for 2:1) |

Detector-2 (ORTHRUS) is unchanged: the 5-seed mean of max-normalised ratios was best or tied among 11 label-free
seed combinations (median, trimmed mean, robust-z, percentile normalisation). Published Velox's CADETS ADP (0.94)
uses test-ADP epoch selection; ours selects by validation loss only, as a product must.

**Compatibility**: 0.5 bundles name detector-1's weights `detector-1-bs-s<k>.npz` and list `requires:
["detector-1:batch_scale", "fusion:max"]` in the manifest. 0.4 agents find no weights they can load and keep their
previous bundle; 0.5.0 agents check `requires` and refuse a bundle that needs a feature they do not know. Older
bundles keep working unchanged in 0.5 agents (window-degree input, weighted fusion). Existing endpoints get 0.5 on
their next retrain, or without detector-2 GPU time:
```
docker exec pdp-worker-train-1 python -m pdp_server.tools.retrain_detector1 --endpoint <id> --bundles <current bundle> --deploy
```
(detector-1 retrained on the bundle's own baseline, detector-2 / layers / policy copied, fusion re-calibrated on the
validation day; about 4-9 min per endpoint on the L40S on the benchmark data).

### Result (5 runs per dataset; details in docs/BENCHMARK_E3.md and docs/BENCHMARK_OPTC.md, "0.5")

Learned-only ranking ADP (node level, mean over runs; 0.4 -> 0.5):

| dataset | detector-1 | fused (learned ranker) | product ADP | alerts (TP / FP) |
|---|---|---|---|---|
| CADETS (dev) | 0.12 -> **0.41** | 0.30 -> **0.83** | 1.00 -> 1.00 | unchanged |
| THEIA (dev) | 0.26 -> **0.98** | 0.71 -> **0.95** | 1.00 -> 1.00 | unchanged |
| H201 (dev) | 0.15 -> 0.18 | 0.13 -> 0.17 | 0.80 -> **1.00** | unchanged |
| H501 (held out) | 0.02 -> 0.07 | 0.02 -> 0.09 | 0.61 -> 0.60 | unchanged |
| H051 (held out) | 0.20 -> **0.03** | 0.18 -> **0.08** | 0.86 -> 0.83 | unchanged |

On DARPA E3 the learned ranker went from weak to good. **The held-out OpTC hosts do not confirm the gain**: H501
improves slightly, H051 gets worse, and their held-out mean is about flat (fused 0.10 -> 0.08, product ADP 0.74 ->
0.72). On Windows OpTC both learned detectors stay close to useless before and after (ADP <= 0.26). Alerts, MCC,
precision and recall are identical on all 25 bundles, because since 0.4 the learned layer only orders alerts within
a severity. H501 / H051 had already been used as held-out sets for 0.4; nothing in this round looked at them before
the single final run.

## 0.4 (2026-11-06): what changed and why

Every change is general (no program names, paths, addresses or dataset names in the detection logic). Each one comes
from a failure seen in the 0.3 benchmarks and is either a bug fix or a change in how alerts are counted and ranked:

| change | setting (layers.json / policy) | the 0.3 failure it fixes |
|---|---|---|
| Program identity: Windows NT and drive spellings, letter case, per-run GUID / hex directories and version directories are one program; a process recorded without a path matches a known program by name | `normalize_programs` | `PING.EXE` vs `ping.exe`, `.../Temp/<GUID>/dismhost.exe`, `taskkill` vs `.../taskkill.exe` alerted as new programs |
| One new-program alert per program per day; later runs are evidence (`novel_executable_repeat`) | `novel_instances: 1` | one new tool run in a loop raised one alert per process: 251 for `PING.EXE` on OpTC H201, 31 for one installer on THEIA |
| Windows paths with spaces read in full | `full_paths` | the process label separates path and command line by a space, so every program under `C:\Program Files` was the one program `.../Program` (1,902 of 60,275 processes on H201): layer 1 could never flag a new program there |
| Windows paths in their real folders; Windows credential stores are sensitive | `full_paths` | `tainted_modify` keys were all `@ /Device/HarddiskVolume1`; only Linux credential stores were known |
| Multicast and limited broadcast are local traffic | `local_multicast` | IPv6 neighbour discovery (`ff02::1:ff..`), LLMNR (`224.0.0.252`), mDNS and SSDP were untrusted remote sources: every Windows process receiving them was tainted (23,476 and 38,074 benign `tainted_modify` events on H201 / H051 baselines) |
| A process started from a file written with untrusted content counts as executing it | `image_exec` | collectors without an EXECUTE event (Windows) never raised `untrusted_exec` |
| The learned layer ranks; it raises no alerts of its own unless the endpoint turns them on | bundle `learned_policy.learned_alerts: false`; endpoint setting `learned_alerts` overrides | corroborated and learned-only alerts were 3-5 % precise on every dataset (e.g. THEIA: 232 alerts, 9 attack nodes) |
| Triage order = the severity the console shows (critical data-flow rules, then untrusted exec / new program with a rule, then the other alerts, then learned-only), ties by the learned score | `pdp_engine.runtime.alert_tier` | 0.3 ranked new-program and rule alerts as one tier ordered by the learned score, so ADP depended on detector noise (THEIA min 0.77) |

Existing bundles keep their 0.3 behaviour until their layers are re-fitted (`tools.add_layers`, seconds per
endpoint, no retraining): the settings change keys and benign thresholds. Agents need 0.4.0 to apply them (0.3
agents ignore the new keys). The learned detectors themselves are unchanged.

**Tried and rejected on the development data**: following an alarmed channel (flagging later traffic between the
alarmed process, or any process, and the alarmed address) added 372-714 false positives on THEIA, where a benign
Firefox exfiltration alarm spread over all its traffic; `novel_instances: 3` and the corroboration variants
(data-flow-forward neighbours only, the fusion threshold instead of the 99.9th percentile, evidence rules only,
no learned-only budget) were all below ranking-only on MCC on all three development sets.

### How it was evaluated

Protocol fixed before any change was tried (artifacts/lab_v04/PROTOCOL.md, with the lab scripts and outputs): development sets CADETS E3, THEIA E3 and
OpTC H201 (per-node inspection allowed); OpTC H501 and H051 held out, run once after the configuration was frozen.
Their 0.3 aggregate results were already known (docs/BENCHMARK_OPTC.md). All numbers re-use the 25 trained bundles of
the published 0.3 results (5 per dataset), so the differences come from the changes, not from retraining. A
label-free check on the baseline days of all five datasets (leave-one-day-out) points the same way: new-program
alarms on benign days fall 30-80 % (CADETS 54 -> 18, THEIA 293 -> 61, H201 32 -> 21, H501 35 -> 19, H051 17 -> 11).

Results: docs/BENCHMARK_E3.md and docs/BENCHMARK_OPTC.md, "0.4".

## Background (0.3)

Why: the 0.2 product alerted on one signal, the fused score of two learned detectors (Velox, ORTHRUS) above the
maximum benign validation score. On DARPA E3 that was not reliable (docs/BENCHMARK_E3.md): across five training runs
detector-2 alone ranged from ADP 0.09 to 1.00 on THEIA, one run produced 25,378 false positives, and detector-1
detected nothing on CADETS. The literature reaches the same conclusion under honest protocols:

* Bilot et al. (USENIX Security 2025) re-ran 8 PIDS - all unstable across training runs.
* Moon et al. (arXiv 2609.33532, preprint) - checkpoint selection on test labels inflates published ADP by
  0.16-0.33; ORTHRUS re-sets its threshold from unlabelled test scores; the original Velox gets degree-dependent
  inputs through a reindexer buffer-reuse defect.
* Guerra et al. (NDSS 2027) - an executable-novelty allowlist matches or exceeds the learned baselines on key
  operating-point metrics.
* Xiao et al. (industrial evaluation) - learned PIDS lose 27-38 % AUC across hosts and platforms.

0.3 therefore puts deterministic, explainable layers first and keeps the learned detectors as a ranker whose
false-positive volume is bounded by construction.

## The three layers

Code: `engine/pdp_engine/layers.py` (layers 1-2), `engine/pdp_engine/runtime.py` (`AlertPolicy`),
`engine/pdp_engine/models.py` (`batch_role_scale`, `window_degrees`), `engine/pdp_engine/trainer.py`.

### Layer 1 - executable novelty

A process alerts when its program (exe path; the process name when the collector records no path, as DARPA CADETS)
never ran during the baseline (training + validation days) and has not been approved since. Deterministic, one alert
per process. **Approvals**: Console -> alert -> "Approve program", or Endpoint -> Detection layers; the list is part
of the endpoint configuration (`approved_executables`), the agent applies it on its next poll without a new bundle,
and open novelty alerts for that program are resolved as false positives. Blind spot: attacks that use only programs
the host already runs (living off the land, masquerading under an existing path) - layer 2 covers those.

### Layer 2 - information-flow tags with benign-calibrated alarms

After Morse (tag propagation with attenuation and decay) and CAPTAIN (NDSS 2025: tag initialisation, propagation and
alarm thresholds adapted to benign data). This is a compact re-implementation in that spirit, not a port of either
system. Tags are propagated along the data-flow edges of the stream in time order:

| node | tag | initial value / propagation |
|---|---|---|
| netflow | integrity | 1 if the remote address is local or was contacted during the baseline, else 0 |
| file | integrity | 1 (pre-existing content); lowered to the writer's integrity on WRITE |
| file | confidentiality | 1 for credential / secret stores (`/etc/shadow`, `~/.ssh/`, shell history, browser logins, ...) |
| process | code integrity | integrity of the executed file; inherited on fork without exec |
| process | data integrity | min of the data it consumed (+0.2 per file hop), recovers with a 1 h half-life; inherited on fork |
| process | confidentiality | max of the data it read (-0.25 per write hop) |

| alarm | fires when | role in 0.3 |
|---|---|---|
| `untrusted_exec` | a file with untrusted content is executed | alarm |
| `untrusted_code_network` | a program loaded from an untrusted file talks to an untrusted address | alarm |
| `exfiltration` | a process that read sensitive data sends to an untrusted address | alarm |
| `tainted_spawn` | a process holding untrusted data starts a program | evidence (see below) |
| `tainted_modify` | a process with untrusted code/data writes a named file that existed in the baseline | evidence |

**Benign calibration** (`fit_layers`): the engine replays the baseline days; every (alarm, key) that fires there -
key = program, parent -> program, or program @ target directory - gets its own threshold just below the lowest tag
value it reached on benign data (margin 0.05). A benign routine stays quiet; the same alarm with a key never seen in
the baseline, or a strictly more untrusted value, still fires. The calibration replay is *leave-one-day-out*: an
address is trusted on a day only if it also occurs on another baseline day, and a file is pre-existing only if it was
seen on an earlier day - otherwise every baseline address is trusted in hindsight and no benign alarm is ever
observed (this was the first version's flaw, caught by the label-free validation-day check). Fitting takes ~4 s on
DARPA E3. Both collector layouts are handled: DARPA's one node per process (fork, then EXECUTE into the same node) and
the live collectors' one node per exec image (EXECUTE into the new image, then CLONE from the old one).

### Layer 3 - learned ranker (Velox + ORTHRUS), fixed

* **Detector-1 structural input** (0.5: `models.batch_role_scale`, `velox_input = "batch_scale"`): per 1024-edge
  batch, a node that both sends and receives has its features scaled by 1 + 1/k (k = in-count in the batch) - the
  input the published Velox gets from PIDSMaker's reindexer. 0.3-0.4 used `models.window_degrees` (log1p of each
  node's out-/in-degree and distinct successors / predecessors appended to the features), which old bundles keep.
  Per-edge-type counts are deliberately excluded - they would contain the label being predicted. 0.5 also trains
  detector-1 at lr 1e-3 and averages the weights of its 3 lowest-validation-loss epochs.
* **Fusion** (0.5: `fusion_mode = "max"`): the fused score is the max of the two detectors' threshold ratios;
  0.2-0.4 bundles use the 2:1 weighted mean, recorded as `calibration.fusion.mode`.
* **Seed ensembles**: detector-1 averages 3 seeds, detector-2 averages 5 seeds (`orthrus_aggregate = "mean"`; 0.2
  kept only the seed with the lowest validation loss, which keeps all of that seed's variance).
* **Bounded alerting** (`AlertPolicy`): the fused score alerts on its own only
  - as **corroborated** - a node marked by an evidence rule, or a window neighbour of a layer-1/2 alert, whose score
    is above the validation-day 99.9th percentile of fused scores; or
  - as **learned** - above the fusion threshold, at most `learned_daily_budget` (default 20) per UTC day, highest
    first. A false-positive storm like the 25,378-node THEIA run is capped at 20 alerts a day.
  - With the endpoint setting `learned_alerts: false` the learned layer raises no alerts at all and only orders them
    (deterministic mode; on DARPA E3 this is the higher-MCC operating point, see the results below).
* Every alert carries its layer, rule and an analyst-facing reason (`alerts.layer/rule/reason/reasons`); the SIEM
  exporter maps deterministic detections to high severity (rules >= 8, novelty/corroborated >= 7).

## Pre-registration and the one revision

All layer parameters above were fixed before any test-day evaluation. The first test-day run of layers 1-2 (CPU,
deterministic) showed two rules - `tainted_modify` (THEIA: 1013 nodes, 2 true) and `tainted_spawn` (221 nodes, 13
true) - flagging long-lived processes that had ever received untrusted data, the dependency explosion Morse and
CAPTAIN describe. They were then made **evidence** (alert only when the learned score corroborates). This revision
was decided after seeing test-set results, so it is optimistic on DARPA E3: every evaluation reports the
pre-registered policy (all five rules alarm on their own) next to the revised one, computed on the same learned
scores, and the revised policy is checked on independent data (the live client suite, which played no part in the
decision). Results: docs/BENCHMARK_E3.md, "0.3 layered detection". In short (5 runs per dataset, mean):

| | CADETS MCC | CADETS ADP | THEIA MCC | THEIA ADP | attacks | client suite |
|---|---|---|---|---|---|---|
| 0.3 layered product | 0.41 | 0.99 (min 0.98) | 0.45 | 0.91 (min 0.77) | all, every run | 58/64, no layer-1/2 FP |
| layers 1+2 only | 0.42 | – | 0.61 | – | all | |
| 0.2 best configuration | 0.17 | 0.57 (min 0.06) | 0.14 | 0.87 (min 0.61) | | 43/64 |
| best published (Bilot et al.) | – | 0.94 (min 0.85) | – | 0.72 (min 0.42) | | |

The learned layer's alerts add mostly false positives (on THEIA ~280 false for ~9 true); run it ranking-only
with the endpoint setting `learned_alerts: false` where precision matters more than the last few percent of recall.

## Upgrading endpoints

Bundles trained by 0.3 contain `layers.json` and a `learned_policy`. Pre-0.3 bundles keep alerting exactly as before
(fused score above threshold) until upgraded - retrain, or add the layers to the current bundle in seconds:
```
docker exec pdp-worker-train-1 python -m pdp_server.tools.add_layers --endpoint <id> --deploy
```
Agents must be 0.3 to load a bundle *trained* by 0.3 (detector-1's input width and seed files changed; an older
agent refuses it at load time and keeps its previous bundle). A pre-0.3 bundle upgraded with `add_layers` loads in an
old agent but is scored without the layers - upgrade the agent first.

Agents must be 0.5.0 to load a bundle trained (or upgraded with `retrain_detector1`) by 0.5: detector-1's weight
files are renamed and the manifest's `requires` lists the new features; an older agent keeps its previous bundle.

Agents must be 0.7.0 to load a 0.7 bundle (manifest `requires`: `detector-3`, `propagation`); an older agent keeps its
previous bundle. Bundles trained from 0.7 on are 0.7 bundles; an existing bundle is upgraded without GPU retraining
(detector-3 fitted on the bundle's training days, thresholds and propagation calibrated on its validation day, layers
re-fitted with the 0.7 defaults) with:
```
docker exec pdp-worker-train-1 python -m pdp_server.tools.upgrade_07 --endpoint <id> --deploy
```
