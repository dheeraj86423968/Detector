# Lab 0.10: program prevalence and incident grouping (written before any variant was scored)

User request (2026-11-09): "do the incident grouping and program prevalence" - the two next steps named in the 0.9
review: most of 0.9's 1,189 false positives (16 sets) are new-program alerts (556, 14 % precise), and analysts work
incidents, not alerted nodes.

## Part 1: program prevalence (detection change, pre-registered)

Layer 1 alerts on a program that never ran during *this* endpoint's baseline. A program that ran during the baseline
of other endpoints of the same organisation is not new to the organisation. Fleet prevalence = for each program key
(layers.program_key, the key layer 1 already uses), the number of *other* endpoints of the organisation whose baseline
(the known_executables of their current bundle, i.e. training days only) contains it; a program recorded without a
path matches by name, as layer 1 already does.

Fleets in the lab (an organisation = hosts recorded in one environment; every member's baseline ends before any
member's first test day, checked 2026-11-09):
CARBANAKv2 h1-h5 (5 hosts), OpTC H201/H501/H051 (3), ATLASv2 h1/h2 (2), DARPA E3 engagement CADETS / THEIA E3 /
ClearScope E3 / FiveDirections E3 / TRACE E3 (5; different OSes, little overlap expected). THEIA E5 is alone (fleet
of one: unchanged by construction).

Variants (runtime only, same 0.7 released bundles and 0.9 defaults as res12, same code path as the agent):
- **P0**  0.9 as released (reference).
- **P1**  a new program known on >= 1 other endpoint raises no alert.
- **P1e** such a program becomes evidence (rule fleet_known_executable): it alerts (layer "corroborated") only when
  its learned score is above the corroboration threshold, at most once per program and UTC day (as repeat runs).
- **P2 / P2e** the same with >= 2 other endpoints (ATLASv2 has one other host: P2 = P0 there).

Acceptance (16 dev / seen sets): no attack found by P0 lost on any set; mean ground-truth node recall >= 0.9 x P0's.
Choice: among accepted variants, the fewest false positives; within 5 % of that, the most conservative one
(P2e, then P2, then P1e, then P1). If none is accepted: no prevalence change.

## Part 2: incident grouping (presentation; exploration first, then a pre-registered grid)

Every alert row the agent would report (per window; real-time duplicates of the same node and rule within 2 h
dropped, as the agent does) is stored with the agent's one-hop window context and grouped by the server's own code
(pdp_server.incidents.group). Metrics per set: incidents, false-positive incidents (no ground-truth node among its
alerts) per day, true incidents, attacks with an alert in some incident, and **buried attacks**: detected attacks
none of whose incidents is titled by a ground-truth alert (the incident's top alert by the console's own ranking is
a false positive, so the analyst sees a benign title).

Grid 1 = the product grouping (G0) on P0 and on the chosen prevalence variant, to see what incidents look like.
Grouping variants are written down here before grid 2 runs, with the rule: no attack buried that G0 does not bury,
no detected attack lost; fewest false-positive incidents.

Amendment (2026-11-09, after the first test run on ATLASv2 h1, before any grouping comparison): "topped by a
ground-truth alert" is not usable - the attack incidents there are topped by the attacker's address (an exfiltration
alert on the netflow node), which the ground truth does not label, so every attack looked buried. **Buried** is
redefined as: every incident holding the attack's alerts has less than 10 % ground-truth alerts.

### Grid 2 grouping variants (written 2026-11-09 after grid 1 on CARBANAKv2 h1-h5 and OpTC H051 only)
Grid 1 observation: one benign finding recurring hours apart (the same program or address) becomes a new incident each
time (CARBANAKv2 h2: zoom.exe in 3 incidents, ucpdmgr.exe in 2; 73 incidents from 207 alerts).
- **G0** product grouping (30 min gap, provenance split, same-program merge).
- **G1** G0, then incidents of one endpoint with the same subject (the acting program of the incident's top alert, or
  its address for a network node - what the console titles) are merged when the next starts within 24 h of the last
  alert of the previous one. Ids stay stable (later alerts join the earlier incident).
- **G2** G1 with 7 days.
- **G3** G0 with a 2 h gap instead of 30 min.
Rule: no detected attack lost, no attack buried that G0 does not bury (on the chosen prevalence variant), fewest
false-positive incidents; within 5 % of that, the smaller change (G3, then G1, then G2).

## Decision record (16 dev / seen sets, before any held-out run)

### Part 1: prevalence (res13-*.json, summ13.txt)
| variant | attacks | TP | FP (per day, 71 days) | new-program FP | precision | mean node recall | rule |
|---|---|---|---|---|---|---|---|
| P0 (0.9) | 26/30 | 337 | 1,189 (16.7) | 556 | 0.221 | 0.285 | ref |
| P1 | 26/30 | 322 | 973 (13.7) | 393 | 0.249 | 0.250 | rejected (recall < 0.257) |
| P1e | 26/30 | 325 | 1,003 (14.1) | 393 | 0.245 | 0.259 | accepted |
| **P2** | 26/30 | 333 | **1,051 (14.8)** | 457 | 0.241 | 0.275 | accepted |
| P2e | 26/30 | 333 | 1,075 (15.1) | 457 | 0.237 | 0.275 | accepted |

Fewest FP among accepted: P1e (1,003); P2 is within 5 % (1,051 <= 1,053) and more conservative: **P2 is chosen**
(fleet_prevalence "drop", fleet_min_endpoints 2). It acts where an organisation has several hosts with a shared
software base (CARBANAKv2 h1-h5: 530 -> 399 FP); OpTC, ATLASv2 and the E3 hosts are nearly unchanged (different OSes
or few shared programs; with one other host ATLASv2 cannot reach 2). Product path checked: Runtime.set_fleet_programs
with the server's key computation reproduces the lab variants exactly (verify13.py, CARBANAKv2 h4, P2e and P1).

### Part 2: incidents (inc13-all.json, rows13-*.json.gz)
| | alert rows | incidents | FP incidents (per host-day) | true incidents | attacks | buried |
|---|---|---|---|---|---|---|
| 0.9 (P0 / G0) | 1,619 | 354 | 284 (4.00) | 70 | 26 | 1 |
| P2 / G0 | 1,469 | 325 | 256 (3.61) | 69 | 26 | 1 |
| P2 / G1 (24 h) | 1,469 | 233 | 191 (2.69) | 42 | 26 | 1 |
| **P2 / G2 (7 days)** | 1,469 | **215** | **174 (2.45)** | 41 | 26 | 1 |
| P2 / G3 (2 h gap) | 1,469 | 268 | 208 (2.93) | 60 | 26 | 1 |

No variant loses a detected attack or buries one G0 does not (the one buried attack, CARBANAKv2 h3, is buried in 0.9
too). Fewest FP incidents: G2, nothing within 5 %: **G2 is chosen** (incidents.RECUR_NS = 7 days).

Refinement while reviewing the product code (after the choice, before release): the subject that decides "same
finding" is the acting program's full path (not its file name: a masquerading copy elsewhere is a different finding),
and findings with no recorded program ("process", "unnamed file") never merge. It can only keep incidents apart. Grid 2
re-run with the shipped code (inc13-final.json): G0 325 / 256, G1 237 / 194, **G2 220 / 178 (2.51 per host-day)**,
G3 268 / 208 incidents / false-positive incidents; no attack lost or newly buried; G2 still chosen.

0.9 -> 0.10 per set (shipped code):

| set | days | attacks | false alerts 0.9 -> 0.10 | true alerts 0.9 -> 0.10 | false incidents 0.9 -> 0.10 | incidents 0.9 -> 0.10 |
|---|---|---|---|---|---|---|
| ATLASV2_EDR-h1 | 1 | 8/10 | 49 -> 49 | 12 -> 12 | 6 -> 3 | 11 -> 5 |
| ATLASV2_EDR-h2 | 1 | 0/0 | 26 -> 26 | 0 -> 0 | 6 -> 2 | 6 -> 2 |
| CADETS_E3 | 4 | 3/3 | 16 -> 16 | 31 -> 31 | 14 -> 10 | 17 -> 13 |
| CARBANAKV2_EDR-h1 | 8 | 1/1 | 123 -> 83 | 5 -> 5 | 56 -> 24 | 60 -> 28 |
| CARBANAKV2_EDR-h2 | 9 | 1/1 | 164 -> 131 | 40 -> 39 | 43 -> 19 | 73 -> 28 |
| CARBANAKV2_EDR-h3 | 7 | 1/1 | 86 -> 72 | 2 -> 2 | 14 -> 8 | 15 -> 9 |
| CARBANAKV2_EDR-h4 | 7 | 1/1 | 27 -> 24 | 3 -> 3 | 12 -> 10 | 13 -> 11 |
| CARBANAKV2_EDR-h5 | 11 | 1/1 | 130 -> 89 | 17 -> 14 | 18 -> 14 | 22 -> 18 |
| CLEARSCOPE_E3 | 2 | 0/1 | 0 -> 0 | 0 -> 0 | 0 -> 0 | 0 -> 0 |
| FIVEDIRECTIONS_E3 | 3 | 2/2 | 166 -> 166 | 11 -> 11 | 6 -> 6 | 11 -> 10 |
| OPTC_H051 | 3 | 1/1 | 53 -> 53 | 75 -> 75 | 5 -> 3 | 8 -> 6 |
| OPTC_H201 | 3 | 1/1 | 19 -> 19 | 6 -> 6 | 11 -> 10 | 12 -> 11 |
| OPTC_H501 | 3 | 1/1 | 77 -> 70 | 17 -> 17 | 10 -> 10 | 13 -> 12 |
| THEIA_E3 | 3 | 2/2 | 86 -> 86 | 109 -> 109 | 19 -> 6 | 24 -> 9 |
| THEIA_E5-theia | 2 | 0/1 | 97 -> 97 | 0 -> 0 | 39 -> 28 | 39 -> 28 |
| TRACE_E3-trace | 4 | 3/3 | 70 -> 70 | 9 -> 9 | 25 -> 25 | 30 -> 30 |
| **total** | 71 | 26/30 | 1189 -> 1051 | 337 -> 333 | 284 -> 178 | 354 -> 220 |

## Held-out
CLEARSCOPE_E5 once (pending disk), a single host: prevalence cannot act on it (fleet of one); incident metrics are
reported.
