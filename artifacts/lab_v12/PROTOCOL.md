# Lab 0.12: an industry rule set as the deterministic fallback (written before any variant was scored)

User request (2026-11-10): "keep working on making our detector better. you can use rules if you want. use the best
ones. it should be reliable enough that if even something gets passed by learned model rule should flag it, no
duplicates. so that we propose learned as add-on while rules do the regular part as a fallback just in case. this
does not mean compromise on the learned part. that is main thing"

## Where 0.10 stands (16 dev / seen sets, rows13 P2, before this protocol)

30 attacks, 26 detected. By the layers that put a ground-truth node on the analyst's screen:
- deterministic layers (novelty, data-flow rules) find 21 attacks;
- 5 attacks are found *only* through learned corroboration (ATLASv2 h1 m2, m3, m4, s2; FiveDirections firefox):
  if the learned detectors miss, nothing else catches them;
- 4 attacks are found by nothing (ATLASv2 h1 m1, s1; ClearScope E3; THEIA E5).
The ATLASv2 attacks are textbook techniques (Office and the Equation Editor spawning regsvr32 that loads scrobj.dll
from a URL, Firefox exploitation), which public detection rules describe.

## The rule set

SigmaHQ (github.com/SigmaHQ/sigma), release **r2026-07-01** (commit 552f3fee), Detection Rule License 1.1 (rules
keep their title, id and author; attribution in the product's notices). The community's largest maintained rule
set, used by commercial SIEM/EDR products. Only the core `rules/` folder (not emerging-threats, threat-hunting, DFIR
or compliance), products windows and linux, the categories our telemetry records:

| Sigma category | provenance event | fields |
|---|---|---|
| process_creation | CLONE parent -> child process (and a process first seen in a window) | Image, CommandLine, ParentImage, ParentCommandLine |
| image_load | a process READs a .dll / .so / .sys file | Image, ImageLoaded |
| file_event | a process WRITEs a file | Image, TargetFilename |
| network_connection | a process CONNECTs / sends to a remote address | Image, DestinationIp, DestinationPort, Initiated=true |

Fields the telemetry does not have (OriginalFileName, Hashes, User, IntegrityLevel, Signed, ...) evaluate to "no
match". A rule is **excluded** when a negated part of its condition (a filter) uses such a field (it would fire more
than its authors intended), when it uses unsupported modifiers (base64offset, i) or aggregations, or when its status
is deprecated / unsupported. Windows paths are matched in Windows form (`c:\windows\system32\x.exe`; NT device paths
converted), case-insensitively, as Sigma specifies.

## Layer semantics (product code: pdp_engine.sigma, inside the deterministic layers)

- A match is a hit of layer `rules`, rule `sigma`, keyed `<rule id>:<program key of Image>`; the alert's reason names
  the Sigma rule title and level. A process_creation rule whose positive selection names ParentImage or
  ParentCommandLine also marks the parent process (the compromised one).
- **No duplicates:** one alert per node and window whatever the number of matching rules and layers (the runtime
  merges reasons per node); each (rule, program, UTC day) alerts once, repeats are dropped; a process is evaluated
  once per event kind and counterpart.
- The learned layers are unchanged (detectors 1-3, corroboration, ranking).

## Variants (runtime only, same 0.7 released bundles, 0.10 defaults incl. fleet prevalence P2)

- **Z0** 0.10 as released (reference).
- **Z1** + Sigma, levels high and critical.
- **Z2** Z1, and a (rule, program) pair that matched during the endpoint's own baseline (training days) is evidence:
  it alerts only when the learned score corroborates it (as the dependency-prone data-flow rules do).
- **Z3** Z2 with level medium added.

## Metrics (eval15.py, inc14-style grouping with the 0.11 digest)

Attacks detected (any layer); **attacks found by the deterministic layers alone** (a ground-truth node alerted with a
novelty or rules reason, Sigma included) - the fallback coverage the request asks for; attacks found only by learned
corroboration; TP and FP nodes; FP per day; false incident-list items per host-day and false incidents at >= high
(notified by default); Sigma rules that fired, with their TP/FP.

## Rule

Accepted: no attack Z0 detects is lost; FP nodes <= 1.15 x Z0's; false incidents at >= high per host-day <= Z0's +
0.25. Among accepted variants: the most attacks found by the deterministic layers alone; tie: fewest FP nodes. If none
is accepted: no change, report why. Product default = the chosen variant.

**Honesty note.** No unseen held-out set is available (CADETS E5 needs disk space the user has to free). These 16 sets
are development data; the result will be reported as such, and the held-out check is CADETS E5 when it becomes
possible. Sigma rules were written by third parties without knowledge of these datasets, which limits (but does not
remove) the risk of fitting: the choice among variants is still made on these sets.

## Amendment 1 (2026-11-10, while writing the layer, before any lab set was scored)

Writing the Sigma field mapping exposed a layer-1 bug: `layers.executable` recognised a Windows path with spaces only
in forward-slash form, so EDR telemetry that writes backslashes (ATLASv2, CARBANAKv2) had every program under
`c:\program files\...` cut to the one program `c:\program`. Layer 1 therefore could not tell such programs apart
(a new program there counted as known when any program there ran during the baseline). The Sigma layer parses these
paths correctly (`executable(..., backslash_paths=True)`); layer 1 is unchanged in Z0-Z3.

Added variant, scored after the Z choice, on top of the chosen Z:
- **ZK** layer 1 with `backslash_paths` (known programs re-fitted from the same baseline days with the fixed parser).
Rule for ZK: no attack the chosen Z detects is lost, FP nodes <= 1.10 x the chosen Z's; accepted -> released with it.

## Decision record, iteration 1 (16 dev / seen sets, 71 host-days; results/iter1, Sigma bare_names "prefix")

| variant | attacks | lost | found by deterministic layers alone | TP | FP | rule |
|---|---|---|---|---|---|---|
| Z0 (0.10) | 26 | - | 21 | 333 | 1,051 | ref |
| Z1 | 26 | 0 | 22 (+ATLASv2 m4) | 356 | 1,803 (+72 %) | rejected (FP) |
| Z2 | 26 | 0 | 22 (+ATLASv2 m4) | 352 | 1,272 (+21 %) | rejected (FP > 1,209) |
| Z3 | 26 | 0 | 22 (+ATLASv2 m4) | 362 | 1,365 (+30 %) | rejected (FP) |

**No variant accepted: no change.** Most of the added false positives come from the three OpTC hosts (H201 19 -> 70,
H501 70 -> 119, H051 53 -> 101 under Z2), mainly two rules ("Suspicious Process Parents", "System File Execution
Location Anomaly"; Z1: 265 and 131 alert rows, 0 true).

## Amendment 2 (after iteration 1, before iteration 2; this is a second look at the same data and is reported as such)

Reading the false positives of iteration 1 showed a field-mapping error, not rule noise: OpTC records many processes
by name only ("taskhostw.exe", "dwm.exe"), and the layer passed them as Image = "\taskhostw.exe" - a location that
does not exist, which the location rules then read as "system program running outside system32". The folder is
unknown, so the faithful mapping is Image (and ParentImage) **absent** for a process recorded without a folder (its
command line is still matched). Iteration 2 = the same variants and the same acceptance rule, with bare_names
"absent". No rule is removed or changed by hand. Because the change was found by looking at iteration 1's false
positives on these sets, iteration 2 is development evidence only; the held-out check remains CADETS E5.

## Decision record, iteration 2 (results/iter2, Sigma bare_names "absent")

| variant | attacks | lost | deterministic alone | TP | FP | rule |
|---|---|---|---|---|---|---|
| Z0 (0.10) | 26 | - | 21 | 333 | 1,051 | ref |
| Z1 | 26 | 0 | 22 (+ATLASv2 m4) | 354 | 1,529 (+45 %) | rejected (FP) |
| Z2 | 26 | 0 | 22 (+ATLASv2 m4) | 351 | 1,224 (+16.5 %) | rejected (FP > 1,209) |
| Z3 | 26 | 0 | 22 (+ATLASv2 m4) | 361 | 1,313 (+25 %) | rejected (FP) |

**No variant accepted: the default stays Z0.** The threshold is not moved after the fact. The field-mapping fix
removed most of OpTC's location false positives (Z2 OpTC FP 202 -> 243 instead of 290), but SigmaHQ high/critical
rules still cost about one false positive per true node they add on these sets (Z2: +18 TP, +173 FP), and add one
attack to what the deterministic layers find on their own. The four attacks found only by learned corroboration
(ATLASv2 m2, m3, s2: Firefox plugin-container exploitation; FiveDirections firefox: no program paths) and the four
found by nothing are out of reach of rules that need program paths, registry or signature fields this telemetry
lacks. ZK is therefore scored on top of Z0.

## Decision record, ZK (results/zk, on top of Z0)

ZK: attacks 26 (none lost or gained), found by the deterministic layers alone 21, TP 333 -> 336, **FP 1,051 -> 1,567
(+49 %)**: rejected (limit 1,156). Most of the increase is on CARBANAKv2 (h2 131 -> 341, h1 83 -> 195, h4 24 -> 98).
The comparison is confounded and does not show that correct path parsing is harmful: (1) fleet prevalence still
used the other members' known programs, fitted with the old parser, so on CARBANAKv2 the re-keyed programs stopped
matching the fleet; (2) the known programs were re-fitted on the training days only, while the released bundles'
layers were fitted on training + validation days (TRACE and THEIA E5, which have no backslash paths, changed too).
A clean test needs every fleet member re-fitted the same way. **Layer 1 stays as released (backslash_paths off)**;
the bug is recorded as open (docs/DETECTION_LAYERS.md 0.12).

## Outcome

No detection default changes in 0.12. Released: the Sigma layer as an endpoint setting (`sigma`: off by default |
high | medium), with bare_names "absent", baseline matches as evidence (bundles fitted from 0.12 on record them),
Sigma levels mapped to incident severity, and the compiled SigmaHQ r2026-07-01 rule set with its licence notice.
