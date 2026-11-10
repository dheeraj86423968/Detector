# Lab 0.11: analyst workload (new-program review digest) and training capacity

User request (2026-11-10): "fix the capacity part to optimize usage. and try to fix the alert volume part", after the
pre-release review: 0.10 shows 2.5 false incidents per host-day in the console's incident list (practitioners expect
< 0.1 alarms per host-day), and one GPU worker trains one endpoint at a time.

## Part 1: alert volume (presentation only, no detection change)

**Data.** The 16 dev / seen sets of lab 0.10 (rows13-*.json.gz: every alert row the 0.10 agent reports, P2 =
the released fleet prevalence), 71 host-days, 26 of 30 attacks detected. No alert is added or removed by this part.

**Honesty note.** There is no unseen held-out set left (ClearScope E5 was used for 0.10; CADETS E5 needs ~38 GB of
download plus conversion space, more than the 25 GB disk floor allows today). The exploration below was run on the
same 16 sets the grid is scored on, so the result is a development result. It is reported as such, not as a held-out
confirmation. CADETS E5 is the held-out check once the disk clean-up the user has to run frees the space.

**Exploration (sev14.py, before this protocol was written).** Of the 178 false incidents of 0.10 (product grouping
incl. 7-day recurrence), 143 are titled by a new-program alert, 118 hold nothing but new-program alerts and 91 are a
single alert. Severity (incidents.summarise): 140 medium, 23 high, 15 critical; channels notify at >= high by
default, so the false incidents that notify are 38 (0.54 per host-day). Six detected attacks reach only medium
incidents (CARBANAKv2 h1, FiveDirections x2, TRACE x3). Simulated on incident summaries: folding the new-program-only
incidents without a recognised behaviour into one review item per endpoint and day keeps every detected attack
visible (>= 10 % ground-truth share in some incident or digest) and gives 1.2 - 1.6 false items per host-day.

**Design (fixed, not a variant).** A *weak* incident: every alert is new-program evidence (layer novelty: rules
novel_executable, novel_executable_repeat, fleet_known_executable; in the "+learned" variants also layer corroborated
with rule learned_near_alert or novel_executable_repeat, i.e. a learned detector agreeing with a new program), no
behaviour recognised by behaviours.analyse, no data-flow rule, and fewer than 3 distinct new programs (a chain of three
or more new tools stays its own incident: that is the typical shape of hands-on-keyboard activity). The weak incidents
of one endpoint whose first alert falls on the same UTC day become one incident ("review digest", severity low, the
earliest incident's id). Everything else is unchanged.

**Variants.** D0 = 0.10 (no digest). D2 = digest of new-program-only weak incidents. D4 = D2 with the "+learned"
weak definition.

**Metrics** (product code: pdp_server.incidents.group + summarise, lab script inc14.py): items in the incident list
(incidents incl. digests), false items (no ground-truth alert) per host-day, false items at >= medium per host-day
(the "needs attention" list), false items at >= high (notified by default), attacks with an item, buried attacks
(every item holding the attack < 10 % ground truth), attacks whose only items are digests.

**Rule.** Accepted: no detected attack lost, no attack buried that D0 does not bury. Among accepted variants the
fewest false items per host-day; within 5 % of that, the more conservative one (D2, then D4). If none is accepted:
no change.

## Part 2: training capacity (engineering; no change to what is trained)

Measured before the change (prof.py, OpTC H051 replay baseline, 2.3 M nodes, the production image): one training
keeps one CPU core at ~99 % and the L40S at 25 - 40 % with 3 - 10 GB of GPU memory and 3.5 GB of host memory;
detector-2 (5 seeds x 12 epochs, ~67 s per epoch here) is ~85 % of the time (scripts/prof.py, stopped after the first
detector-2 epochs once this was clear). Change: the GPU worker runs several
jobs at once (pdp_server.worker --slots, one process per job, admission by free GPU / host memory, one job per
endpoint). Measured after: wall time of N trainings run together vs one at a time, and that a bundle trained in a
slot is the same as one trained alone (same seeds and data).

## Decision record, part 1 (16 dev / seen sets, 71 host-days; results/inc14.json.gz, scripts/inc14.py)

| variant | items | of which digests | false items (per host-day) | false at >= medium | false at >= high | attacks with an item | buried | attacks only in a digest |
|---|---|---|---|---|---|---|---|---|
| D0 (0.10) | 220 | 0 | 178 (2.51) | 178 (2.51) | 38 (0.54) | 26 | 1 | - |
| D2 | 150 | 47 | 110 (1.55) | 69 (0.97) | 38 (0.54) | 26 | 1 | TRACE firefox_0410 |
| **D4** | **140** | 56 | **100 (1.41)** | **52 (0.73)** | 38 (0.54) | 26 | 1 | TRACE firefox_0410 |

Both variants accepted (no detected attack lost; the one buried attack, CARBANAKv2 h3, is buried in D0 too). Fewest
false items: D4 (100); D2 (110) is not within 5 %: **D4 is chosen** (PDP_INCIDENT_DIGEST=new_programs_and_learned).
The attack only in a digest: TRACE firefox_0410, whose only alert is a single new program ("cache"); in 0.10 it was one
medium incident among 25 false medium incidents on that host. Notified incidents (>= high, the channel default) are
unchanged by construction. The largest cuts are on hosts with many first-seen programs: THEIA E5 (a desktop session
starting) 28 -> 6 false items, TRACE 25 -> 6, CADETS 10 -> 5.

## Decision record, part 2 (results/capacity, scripts/concur.sh)

ATLASv2 h1 replay baseline, the production image, same seeds: alone 819 s; three copies at once 1,110 s for all three
(988 - 1,104 s each): **2.2x the throughput** (3 x 819 = 2,457 s one after another). Each copy: 3.2 - 3.3 GB host
memory, 1.4 GB GPU memory peak; the GPU ran at 32 % alone. Bundles: detector-1 (3 seeds), detector-3 and the final
threshold are identical in all four runs; detector-2 weights and the fusion threshold differ - **between the three
parallel runs as much as from the solo run**, i.e. detector-2 GPU training is not bit-reproducible run to run
(pre-existing; it is also why the 0.10 replay's retrained bundles differed in corroboration, Jaccard 0.61). Released:
pdp_server.worker --slots, auto = 4 on the L40S host.
