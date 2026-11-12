# Lab 0.15: layer 2 alerts once per program, counterpart and day - and then parses programs correctly

Written 2026-11-12 after lab_v14's decision record, before any run of this lab. Engine option added (off):
`rule_instances` (`pdp_engine.layers`: INSTANCE_RULES, REPEAT_RULES).

## Why

lab_v14 showed that parsing `c:\program files\...` correctly in layer 2 finds one attack nothing found before and
makes 26 instead of 21 of the detected attacks visible to the deterministic layers alone - and that it cannot be
released as it is, because layer 2 alerts on every process instance: one browser self-update became 1,477
`untrusted_exec` nodes. Layer 1 has alerted once per new program and day since 0.4.

**The option.** The layer-2 alarms that alert on their own (`untrusted_exec`, `exfiltration`,
`untrusted_code_network`, `untrusted_persistence`) alert `rule_instances` times (1) per (alarm, program identity,
counterpart) and UTC day; the counterpart is the remote address of a network alarm (an executed file or an autostart
directory is already part of the alarm's key). Later instances that day are `<alarm>_repeat` evidence: they alert
only when the learned score corroborates, at most once per program, alarm and day (the 0.9 cap for layer-1 repeats).
A different program, a different remote address, or the next day alerts in full. Fixed design choices, not tuned:
N = 1 (as layer 1), the day as the period (as layer 1), the address as the counterpart (so that a second, different
destination of a program that already raised a false alarm that day still alerts).

## What was seen before writing this (disclosed)

All of lab_v14's results on the same 16 sets, including which programs produce the instance storms. This lab is a
development result by construction.

## Variants (same harness as lab_v14: one pass per set, shared windows and learned scores; layers from lab_v14's
re-fits - the option does not change what is fitted)

- **Z0** released (reference; lab_v14: R0 = Z0).
- **C0** released configuration + `rule_instances` 1.
- **C1** C0 + `rule_key_norm`.
- **C2** C1 + `rule_backslash_paths`.
- **C3** C2 + `version_names`.
- **C4** C3 + `backslash_paths` (layer 1).

## Decision rule (fixed before the runs)

A variant is **accepted** if, against Z0 over the 16 sets,
- no attack Z0 detects is lost,
- no attack-day is lost: on every test day on which Z0 alerts on a ground-truth node of an attack, the variant
  alerts on a ground-truth node of that attack too,
- FP nodes <= Z0's (1,051), and
- no dataset family has more than +10 % and +5 FP nodes.

TP nodes are reported but do not decide: the option turns repeat instances of one finding into evidence on purpose,
so the count of alerted ground-truth *nodes* must fall where an attack runs the same program many times; what must
not fall is the attacks and the days on which they are seen (the two rules above).

Among accepted variants: the most attacks detected; then the most attacks found by the deterministic layers alone;
then the fewest FP nodes; within 1 % of each other the one with fewer options. The chosen variant becomes the
default for newly fitted models. If none is accepted, nothing changes.

Reported whatever happens: per set and family, attacks, deterministic-alone, attack-days, TP, FP, alert rows.

## Limits, stated in advance

- Development result on seen sets, second look after lab_v14; no unseen set is available.
- An attacker who can first trigger a benign false alarm of program P towards address A can then use P towards A
  the same day with the repeat treated as evidence (it still alerts when the learned score corroborates, and the
  first alarm is in the analyst's list). Recorded as a cost.
- `rule_backslash_paths` changes layer 2's keys on backslash telemetry: thresholds and allow-list entries keyed
  `c:\program` no longer match until the model is re-fitted. It applies to newly fitted models only.

## Decision record (2026-11-12; results/, lab_v14 scripts/summ17.py with tag res18)

| variant | attacks | deterministic alone | attack-days (lost) | TP | FP | alert rows | rule |
|---|---|---|---|---|---|---|---|
| Z0 (released) | 26 | 21 | 39 | 333 | 1,051 | 1,483 | ref |
| C0 cap only | 22 | 21 | 35 (4) | 228 | 906 | 1,214 | **rejected**: 4 attacks lost |
| C1 + `rule_key_norm` | 22 | 21 | 35 (4) | 226 | 892 | 1,192 | rejected: 4 attacks lost |
| C2 + `rule_backslash_paths` | 24 | 22 | 37 (2) | 233 | 1,038 | 1,353 | rejected: 2 attacks lost |
| C3 + `version_names` | 24 | 22 | 37 (2) | 233 | 1,021 | 1,336 | rejected: 2 attacks lost |
| C4 + `backslash_paths` | 24 | 22 | 37 (2) | 233 | 1,191 | 1,511 | rejected: 2 attacks lost |

**No variant accepted; the option is withdrawn** (removed from the engine in the commit that carries lab_v16's
protocol). All lost attacks are on ATLASv2 h1 (m2, m3, m4, s2): the dataset runs the same payload ten times on one
day; with one alarm per program and day, nine runs are evidence, and the four attacks that are found through a
learned score next to a deterministic alert lose the alert they stood next to. A per-day cap merges separate attack
runs. It does stop the instance storm (C2: 1,038 FP against lab_v14's 2,838 for the same parsing).
