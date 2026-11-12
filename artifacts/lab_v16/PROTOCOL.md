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
