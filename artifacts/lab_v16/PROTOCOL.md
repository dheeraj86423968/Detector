# Lab 0.16: an untrusted file that is executed alerts once per version; then layer 2 parses programs correctly

Written 2026-11-12, before any run of this lab; after lab_v14's decision record and after the first three sets of
lab_v15 (ATLASv2 h1, CADETS E3, CARBANAKv2 h1) had shown that lab_v15's option fails its rule (the remaining sets
of lab_v15 were still running). Engine option added (off): `exec_once`; lab_v15's `rule_instances` is removed from
the engine.

## Why

lab_v15's cap - any layer-2 alarm once per (alarm, program, counterpart) and day - lost four of ATLASv2 h1's ten
attacks in the first set scored: that dataset runs the same payload ten times on one day, the cap makes nine of
those runs evidence, and the attacks found through a learned score next to an alert lose their anchor. A cap per
day merges separate attacks. The storm it was meant to stop has a narrower cause: one file with untrusted content
(a self-updated `msedge.exe`) is executed again and again.

**The option.** `untrusted_exec` alerts once per *version of the executed file's content*: the engine counts the
writes to each file; an execution of a file whose current version already alerted is `untrusted_exec_repeat`
evidence (alerts only when the learned score corroborates, at most once per program and day). A file written again
- a new download, a new payload at the same path - is a new version and alerts again, also on the same day. The
other alarms are unchanged (per process, as before). Nothing is tuned: there is no count and no period.

## Variants (harness and layers of lab_v14; the option does not change what is fitted)

- **Z0** released (reference; R0 = Z0 in lab_v14).
- **E0** released configuration + `exec_once`.
- **E1** E0 + `rule_key_norm`.
- **E2** E1 + `rule_backslash_paths`.
- **E3** E2 + `version_names`.
- **E4** E3 + `backslash_paths` (layer 1).

## Decision rule (fixed before the runs; written knowing lab_v14's numbers, see Limits)

A variant is **accepted** if, against Z0 over the 16 sets,
- no attack Z0 detects is lost,
- no attack-day is lost (every test day on which Z0 alerts on a ground-truth node of an attack, the variant does),
- FP nodes: <= Z0's (1,051) if the variant detects no more attacks than Z0 and no more by the deterministic layers
  alone; <= 1.10 x Z0 (1,156) if it does (the limit of lab_v12 and lab_v13 for a change that adds detection), and
- no dataset family has more than +25 % and +20 FP nodes.

TP nodes are reported and do not decide (repeat runs of one file are one finding by design; attacks and
attack-days are what must not fall).

Among accepted variants: the most attacks detected; then the most found by the deterministic layers alone; then the
fewest FP nodes; within 1 % the one with fewer options. The chosen variant becomes the default for newly fitted
models (a fitted `layers.json` keeps its behaviour). If none is accepted, nothing changes.

## Limits, stated in advance

- Third look at the same question on the same 16 seen sets (lab_v14, lab_v15, this). The option's design and this
  rule were written knowing that correct parsing adds about 90 exfiltration and 40 other non-exec false-positive
  nodes on CARBANAKv2 and finds ATLASv2 m1; the family limit was widened from lab_v14's (+10 % and +5) for that
  reason. Whatever this lab shows is a development result; it needs a set nobody has looked at before it can be
  called more than that, and none is available on this host (disk).
- An untrusted file that alerted and is not rewritten stays quiet on later runs, on later days too: the first alert
  is the finding and must be handled. If the file node is dropped by registry compaction and comes back, it is
  treated as before this option (a fresh node).

## Decision record (2026-11-12; results/, lab_v14 scripts/summ17.py with tag res19)

| variant | attacks | deterministic alone | attack-days (lost) | TP | FP | alert rows | rule |
|---|---|---|---|---|---|---|---|
| Z0 (released) | 26 | 21 | 39 | 333 | 1,051 | 1,483 | ref |
| **E0** `exec_once` | 26 | 21 | 39 (0) | 331 | 1,035 | 1,442 | **accepted, chosen** |
| E1 + `rule_key_norm` | 26 | 21 | 39 (0) | 329 | 1,027 | 1,432 | accepted |
| E2 + `rule_backslash_paths` | **27** (+ATLASv2 m1) | **26** | 40 (0) | 334 | 1,216 (+15.7 %) | 1,630 | rejected: FP > 1,156; CARBANAKv2 399 -> 550 |
| E3 + `version_names` | 27 | 26 | 40 (0) | 334 | 1,199 (+14.1 %) | 1,613 | rejected: FP > 1,156; CARBANAKv2 399 -> 533 |
| E4 + `backslash_paths` | 27 | 26 | 40 (0) | 336 | 1,368 (+30 %) | 1,789 | rejected |

E0 and E1 are accepted and tie on attacks and on attacks found by the deterministic layers alone; E1's FP is within
1 % of E0's, so the variant with fewer options is chosen: **E0. `exec_once` is on for newly fitted models**
(`LayerConfig.exec_once`); a fitted `layers.json` keeps the behaviour it was fitted with. Its effect on these sets is
small by itself (FP -16, alert rows -41, TP -2: repeat starts of the same untrusted file); what it changes is that
executing an unchanged untrusted file can no longer flood an endpoint.

**E3 is not adopted, and the bar is not moved.** It misses the limit set in advance by 43 nodes (1,199 against
1,156) and exceeds the family limit on CARBANAKv2. It is nevertheless the variant that detects more: one attack
nothing found before (ATLASv2 m1), 26 instead of 21 of the detected attacks found by the deterministic layers alone,
one more attack-day; `exec_once` took its cost from lab_v14's +1,770 false-positive nodes to +148. What remains is
correct parsing showing what programs under `Program Files` do: `exfiltration` by `msedgewebview2.exe`, `perl.exe`
(Git), `python3.11.exe`, `winword.exe`, and `untrusted_exec` of TightVNC's `tvnserver.exe` (5 ground-truth nodes, 27
others on CARBANAKv2). The options stay in the engine, off (`rule_key_norm`, `rule_backslash_paths`,
`version_names`); whether +14 % false-positive nodes is worth one more attack and deterministic detection of five
is the product owner's decision, and on Windows endpoints the released default means layer 2 cannot attribute
anything to a program under a directory with a space in its name.

All of this is a development result on seen sets (see Limits).

## Exploration recorded here (scripts/explore_net.py; CPU, deterministic layers only, no decision rests on it)

Alarm `unusual_network` (engine option `net_profile`, off): a process connects to an untrusted address although its
program contacted none on any baseline day. On the recorded test data: 146 ground-truth / 324 other process nodes
over 14 sets. On the LotL counterfactual (lotl_paper: the attacker's new programs relabelled as baseline programs):
83 / 302, and it reaches attacks the released detector loses there (ATLASv2 m5, m6, s3 through `cmd.exe`,
`winword.exe`, `plugin-container.exe`; CARBANAKv2 h1 through `cmd.exe` / `powershell.exe`).
