# Lab 0.14: program identity in the deterministic layers

Written 2026-11-12, before any run of this lab. Engine options added (all off): `rule_key_norm`,
`rule_backslash_paths`, `version_names` (`pdp_engine.layers`).

## What was looked at before writing this (disclosed)

The released detector's alert rows on all 16 development / seen sets (lab_v12 `rows15b`, variant Z0), by layer, rule
and program, and the missed attacks' ground-truth nodes. Findings that motivate the lab:

1. Attack recall is at what this telemetry allows: the four attacks found by nothing are one exploited process each
   with no distinctive recorded behaviour (ATLASv2 m1: one `plugin-container.exe`; s1: one `winword.exe`), or come
   from collectors without program paths (ClearScope E3) or are found by no system (THEIA E5).
2. A large part of the node-level "false positives" is attack activity the ground-truth files do not list
   (ATLASv2 `payload.exe` 43 nodes, OpTC Metasploit payloads in `rad*.tmp`, FiveDirections / CADETS `whoami`,
   `netstat`, `tasklist`, CARBANAKv2 `java-update.exe`). Node FP counts are therefore an upper bound on false
   alarms, and a change that lowers them by suppressing such alerts is not an improvement. The rule below guards
   against that only through "no attack lost" and the TP floor; it is a limit of these labels.
3. Layer 1 compares programs by identity (`program_key`: Windows spelling, GUID / hex-id / version directories).
   Layer 2 does not: the benign thresholds are keyed by the raw path, so a program that updates itself into a new
   version or GUID directory (OneDrive, Defender signature updates in `temp\{guid}\`) never matches its own
   baseline; on backslash telemetry layer 2 also cuts `c:\program files\x\y.exe` to `c:\program`, so all such
   programs share one key. And neither layer sees a version inside a name
   (`microsoft.outlookforwindows_1.2024.501.300_x64__...`, `am_delta_patch_1.409.123.0.exe`), which is what made
   the layer-1 backslash fix cost +27.5 % false positives in lab_v13.

## Variants (16 sets, released bundles, one scoring pass per set; learned scores and windows shared)

Every variant's layers are re-fitted with the product's `fit_layers` from the days in the released bundle's
`layers.json` `fit_days`, with that bundle's own configuration plus the options listed (Sigma off, as released).
Fleet prevalence (P2, drop) uses the other members' layers re-fitted under the same variant.

- **Z0**  released layers, as scored in lab_v12 / lab_v13.
- **R0**  control: re-fit, no option. Expected to equal Z0; if the released layers were fitted by an older trainer
  and R0 differs, R0 is reported next to Z0 and the options are judged against **R0** (the same fit code), with the
  difference stated.
- **N1**  `rule_key_norm`: layer-2 thresholds looked up by program identity.
- **N2**  N1 + `rule_backslash_paths`.
- **N3**  N2 + `version_names` (both layers' program keys).
- **N4**  N3 + `backslash_paths` (layer 1; lab_v13's K, now with version collapsing).

## Decision rule (fixed before the runs)

Against the reference (Z0, or R0 as above), summed over the 16 sets, a variant is **accepted** if
- no attack the reference detects is lost,
- TP nodes >= 97 % of the reference's,
- FP nodes <= 97 % of the reference's (it must be a real reduction, not noise), and
- no dataset family (DARPA E3, OpTC, ATLASv2, CARBANAKv2, THEIA E5) has more than +10 % and +5 FP nodes.

Among accepted variants the one with the fewest FP nodes is chosen; within 1 % of each other, the one with fewer
options. An accepted variant becomes the default **for newly fitted models** (a fitted `layers.json` keeps the
behaviour it was fitted with). If none is accepted, nothing changes.

Reported whatever happens: per set and per family TP / FP / attacks / attacks found by the deterministic layers
alone for every variant, and which alerts each option removed or added (by rule and program), so that removed
alerts can be read for attack activity.

## Limits, stated in advance

- Development result: all 16 sets are seen, and finding 3 came from reading their false positives. No unseen set is
  available (CADETS E5 needs ~38 GB of download; 42 GB are free on this host).
- Looking up thresholds by identity can only relax more alarms than the raw key does, never fewer; version
  collapsing lets a program named like another version of a known program in the same directory count as that
  program in layer 1. Both are recorded as costs of the options in docs/DETECTION_LAYERS.md if they are released.

## Decision record (2026-11-12; results/, scripts/summ17.py)

Control: the re-fit with no option reproduces the released `known_executables`, `trusted_ips`, `thresholds` and
`private_services` of all 16 bundles, and R0 = Z0 on every set. Reference = Z0 = R0.

| variant | attacks | found by deterministic layers alone | TP | FP | rule |
|---|---|---|---|---|---|
| Z0 = R0 (released) | 26 | 21 | 333 | 1,051 | ref |
| N1 `rule_key_norm` | 26 | 21 | 331 | 1,030 (-2.0 %) | **rejected**: FP not <= 97 % (1,019) |
| N2 + `rule_backslash_paths` | **27** (+ATLASv2 m1) | **26** | 340 | 2,838 | **rejected** (FP) |
| N3 + `version_names` | 27 | 26 | 340 | 2,821 | rejected (FP) |
| N4 + `backslash_paths` (layer 1) | 27 | 26 | 340 | 2,990 | rejected (FP) |

**No variant accepted: nothing changes.** What the runs show:

- N1 does what it was built for (CARBANAKv2 h1 `untrusted_exec` 23 -> 4 false positives: OneDrive and Defender
  updates in new version / GUID directories now match their baseline) but the total effect, -21 FP and -2 TP, is
  below the bar set in advance.
- N2 is the finding of this lab. With `c:\program files\...` cut to `c:\program`, layer 2 on backslash telemetry
  could never match a started program with a file written from an untrusted source (`image_exec`), nor key any
  alarm of such a program correctly. Parsed correctly, layer 2 finds an attack nothing found before (ATLASv2 m1: the
  exploited `plugin-container.exe` reads sensitive data and sends to an untrusted address), and the five attacks
  that only a learned score next to an alert had found are now found by the deterministic layers themselves
  (21 -> 26 of the detected attacks). It also alerts on TightVNC's `tvnserver.exe` on CARBANAKv2 (5 ground-truth
  nodes).
- The cost is one mechanism: layer 2 alerts on every process instance. One Edge self-update on CARBANAKv2 h1
  (browser files written from an address not seen in the baseline) makes each of the 1,477 `msedge.exe` processes
  started afterwards an `untrusted_exec`; N2 adds 1,812 false-positive nodes from only 33 distinct (set, rule,
  program) combinations. Layer 1 has alerted once per program and day since 0.4 for exactly this reason; layer 2
  never got the same treatment because the bug hid the cases where it matters.
- `version_names` (N3) changes little on top (-17 FP); layer-1 backslash parsing (N4) still adds false positives
  (+169 over N3), as in lab_v13.

Follow-up (its own protocol, lab_v15, written before it runs): layer 2 alerting once per (rule, program,
counterpart) and day, with these options on top.

## Exploration recorded here (scripts/explore_drop.py, explore2.py; results/ex2-*.json; no decision rests on it)

Context of the released layer-1 new-program alerts (first runs, no fleet filter; 88 ground-truth / 556 other nodes):
the new process talks to an untrusted address: 46 / 33; its file was written in the stream by a program without a
drop-and-run history in the baseline: 11 / 57 (mostly Windows updater chains); its parent is also new: 5 / 72.
"New program + unknown address" is by far the most precise context (58 % against 14 % for a new program alone).
