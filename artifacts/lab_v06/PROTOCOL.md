# 0.6 robustness round - protocol, written 2026-11-06 before any change or any look at the new data

Goal (user): detector more robust and effective, resilient against manipulation and unintended usage. Nothing
dataset- or client-specific.

Data
- Development: CADETS_E3, THEIA_E3, OPTC_H201 (per-node inspection allowed). OPTC_H501 / H051 were held out in 0.4
  and 0.5: from now on development data at the aggregate level only (regression check), never per node.
- New held out, never seen by this project: DARPA E3 TRACE (Linux), CLEARSCOPE (Android), FIVEDIRECTIONS (Windows),
  PIDSMaker databases and the orthrus ground truth. Nothing is inspected on them (not even event counts per program)
  until the configuration is frozen; then 0.5 and 0.6 are both run once with the product defaults (no per-host
  train overrides: what a new client gets) and reported as they come out.
- Chronological product split (a product validates after it trains): TRACE train 04-02..08, val 04-09, test
  04-10..13 (= PIDSMaker); CLEARSCOPE train 04-03..05, 07..09, val 04-10, test 04-11, 12; FIVEDIRECTIONS train
  04-03..07, val 04-08, test 04-09..11. (PIDSMaker's CLEARSCOPE / FIVEDIRECTIONS splits validate on an earlier day
  and train on days after the test days; not reproducible in a live product.)

Manipulation resistance is tested with deterministic unit / scenario tests (attacker actions on a synthetic or
replayed stream: the alert must still fire), not with the labelled datasets. No live attack simulation (user).

Split as run (per-day event counts checked, nothing else): FIVEDIRECTIONS has no data on 04-03, so train 04-04..07,
val 04-08, test 04-09..11. CLEARSCOPE as above. TRACE_E3 downloaded (11.5 GB dump) but not restored: it needs about
as much disk again restored than is free; not used.

Acceptance rule for the 0.6 layer settings (written 21:20, after grid 1 on CADETS / THEIA, before the OpTC sets and
grid 2): the new settings exist to close evasion paths found by code review, which the DARPA labels cannot show. A
setting is adopted as a default if, on every development set (CADETS, THEIA, H201; H501 / H051 aggregate only), it
keeps every attack detected, does not lower mean MCC by more than 0.01 and does not add more than 5 % false
positives (or 3 alerts, whichever is larger). Otherwise it is either reworked (once) or left off by default.

## Development results and decision (2026-11-06 ~22:00, before any held-out result)
Grids 1-2 (g1-*, g2-*, r1-*, r2-*): mean over 5 bundles, layers re-fitted, learned ranking only.
- strict_program_key, strict_addresses, script_exec, socket_io, persistence, late_exfil: identical metrics on all
  five development sets (CADETS 29 TP / 15 FP, THEIA 100 / 81, H201 6 / 18, H501 10 / 50, H051 72 / 50; same ADP) ->
  adopted (they close the review's evasion paths at no measured cost).
- recurring_trust + relax_min_days=2 on every fit: THEIA +30 / +44 FP, H501 +9 FP -> failed; reworked once (only for
  what is new since the previous model, on a retrain). Retrain simulation (previous model without the last two
  baseline days): THEIA 81 -> 137 FP (MCC 0.684 -> 0.598) -> failed again; off by default.
- connect_receives: H201 18 -> 216 FP, H501 50 -> 2142, H051 50 -> 199 (untrusted_exec / tainted_spawn on
  everything written after any new connection) -> failed; off by default. Its purpose (downloads read() over TCP
  that the eBPF collector does not see) needs socket read/write tracing in the collector instead (follow-up).
Frozen 0.6 layer defaults: the six adopted settings on; the three others off. Learning integrity (alert exclusions,
admin-verified feedback) on. Held-out: ClearScope / FiveDirections, 0.5 (as trained by the product, 0.4 layer
config) vs 0.6 (same bundles, layers re-fitted with the 0.6 defaults), run once.
