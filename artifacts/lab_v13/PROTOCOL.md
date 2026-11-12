# Lab 0.13: clean test of the layer-1 Windows path fix (`backslash_paths`)

Written 2026-11-12, before any run of this lab.

## Why

`layers.executable` recognises a Windows program path with spaces only in forward-slash form. EDR telemetry that writes
backslashes (ATLASv2, CARBANAKv2, FiveDirections E3) has every program under `c:\program files\...` cut at the first
space to the one program `c:\program`: once any program there ran during the baseline, a new program there is not new
to layer 1. The fix (`backslash_paths`, in the code since 0.12, off) was scored once as variant ZK of lab_v12 and
rejected (FP 1,051 -> 1,567), but that comparison was confounded (lab_v12/PROTOCOL.md, "Decision record, ZK"):
1. fleet prevalence used the other fleet members' known programs fitted with the old parser, so re-keyed programs stopped
   matching the fleet;
2. the known programs were re-fitted on the training days only, while the released layers were fitted on training +
   validation days.

## Design (same 16 development / seen sets, same released bundles, same harness as lab_v12 `eval15.py`)

One scoring pass per set; the layer-2 hits, the learned scores and the windows are shared by all variants. Variants
differ only in layer 1 (the set of known programs, how a process label is parsed, the fleet's program keys):

- **Z0**  released 0.10 behaviour as scored in lab_v12 (released bundle's layer 1, fleet from the released bundles).
- **R0**  control: known programs re-fitted from the days in the bundle's `layers.json` `fit_days` (training +
  validation) with the old parser; fleet from the other members' re-fitted sets. Must equal Z0 on every set (TP, FP,
  attacks); if it does not, the harness is wrong and nothing below is interpreted.
- **K**   the same re-fit with `backslash_paths` on, on this set and on every fleet member.

Sigma is off in all variants (as released). Layer 2 is unchanged (its per-program keys use the old parser; changing
them needs re-fitted thresholds and is not part of this test).

## Decision rule (the lab_v12 ZK rule, unchanged; fixed before the runs)

K is accepted as the default for newly fitted models if, summed over the 16 sets, against Z0:
- no attack that Z0 detects is lost, and
- FP nodes <= 1.10 x Z0 (Z0 = 1,051 -> limit 1,156).

Reported regardless of the outcome: per-set TP / FP / attacks for Z0, R0, K, and attacks found by the deterministic
layers alone.

## Limits, stated in advance

- All 16 sets have been seen in earlier labs; this is a second look at the ZK question. It is a development result,
  not a held-out one, whatever it shows. No unseen set with backslash paths is available.
- Only three dataset families contain backslash paths (ATLASv2, CARBANAKv2, FiveDirections E3); on the others K must
  equal R0 by construction, which is checked.

## Decision record (2026-11-12; results/, scripts/)

Control: the old-parser re-fit reproduces the released `known_executables` of all 16 bundles exactly
(`log-prep16-*.log`), and R0 equals Z0 on every set (TP, FP, attacks). The harness is sound.

| variant | attacks | lost | found by deterministic layers alone | TP | FP | rule |
|---|---|---|---|---|---|---|
| Z0 (released 0.10) | 26 | - | 21 | 333 | 1,051 | ref |
| R0 (control) | 26 | 0 | 21 | 333 | 1,051 | = Z0 |
| K (`backslash_paths`, all members re-fitted) | 26 | 0 | 21 | 336 | 1,340 (+27.5 %) | **rejected** (limit 1,156) |

K changes only the sets with backslash paths and spaces: CARBANAKv2 h1 83 -> 183, h2 131 -> 202, h3 72 -> 120,
h4 24 -> 76, h5 89 -> 102; ATLASv2 h1 49 -> 52, h2 26 -> 28. FiveDirections E3 (backslash paths, none cut) and the
nine other sets are identical to R0, as required by construction. Of the +289 FP nodes, 194 are new-program alerts
and 98 are learned scores corroborating next to them.

**Outcome: `backslash_paths` stays off by default.** The confounds of lab_v12's ZK explained part of its increase
(1,567 there, 1,340 here) but not all of it: with every fleet member re-fitted the same way, parsing these paths
correctly still costs more false positives than the rule allows, and finds no additional attack on these sets.

What the extra alerts are (reported, not used to change anything here): programs under `Program Files` that the old
parser hid behind the single program `c:\program` - mostly application updates in per-version directories
(`windowsapps\microsoft.outlookforwindows_1.2024.501.300_x64__...\olk.exe`, `google\googleupdater\126.0.6441.0\
updater.exe`, `edgeupdate\download\{guid}\124.0.2478.80\...`, Defender platform versions). `program_key` collapses a
directory that is only a version (`{v}`) but not a version embedded in a package directory name.

The weakness itself remains and is restated: on telemetry with backslash paths, a program under `c:\program files`
is not new to layer 1 once any program there ran in the baseline. Layer 2 and the learned layer still see what such
a program does.

Hypothesis for a later lab (not tested here; it needs its own protocol and, to count as more than a development
result, a set with such paths that has not been looked at): K together with a program key that collapses the
version part of package directory names.
