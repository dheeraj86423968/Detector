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
