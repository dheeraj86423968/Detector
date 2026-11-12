# Lab 0.17: an alarm that does not depend on the program being new (living off the land)

Written 2026-11-12, before any run of this lab. Engine option (off): `net_profile`, alarm `unusual_network`
(`pdp_engine.layers`).

## Why

The detector's known weak side (artifacts/lotl_paper, 0.10): when the attacker's programs are relabelled as programs
the host already runs, detection falls from 26 to 18 of 30 attacks, because 11 detected attacks rest on layer 1
("a program that never ran here") alone. Layer 2's alarms need untrusted content or sensitive data; nothing
deterministic looks at *what a known program normally does*.

**The alarm.** `unusual_network`: a process sends or connects to an untrusted address (not local, not seen in the
baseline, not on the allow list - layer 2's existing notion) although its program did so on no baseline day. It is
calibrated like every layer-2 alarm: the baseline replay (leave-one-day-out trust) records which programs do contact
unknown addresses - browsers, updaters, mail and chat clients - and those stay quiet. No list of programs, no
threshold to choose.

## What was seen before writing this (disclosed)

lab_v14 to lab_v16 on the same 16 sets, and a CPU exploration of this alarm with the deterministic layers only
(lab_v16 `explore_net.py`): 146 ground-truth / 324 other process nodes on the recorded data, 83 / 302 on the LotL
counterfactual, where it reaches ATLASv2 m5, m6, s3 and CARBANAKv2 h1, which the released detector loses there.
On that evidence it is too noisy to alert by itself; the main variant makes it evidence.

## Variants (lab_v16 harness; layers re-fitted with the alarm, which is switched per variant at scoring time)

- **Z0** released 0.10 behaviour (sanity: on LotL data it must reproduce lotl_paper's P2, 18 attacks).
- **D0** the current default for new models (released configuration + `exec_once`): the reference.
- **U1** D0 + `unusual_network` as **evidence** (alerts only when the learned score corroborates, like
  `tainted_spawn` / `tainted_modify`).
- **U2** D0 + `unusual_network` alerting by itself.
- **F0** D0 + `rule_key_norm`, `rule_backslash_paths`, `version_names` (lab_v16's E3; not a default - here to see what
  correct parsing does under LotL).
- **U3** F0 + `unusual_network` as evidence.

Each variant is scored on the recorded test data ("none") and on the LotL counterfactual ("lotl": lotl_paper's
`lotl.py`, registry labels only, models not retrained), 16 sets each.

## Decision rule (fixed before the runs)

U1 or U2 is **accepted** as the default for newly fitted models if, against D0,
- on the recorded data: no attack and no attack-day is lost, and FP nodes <= 1.10 x D0's;
- on LotL data: it detects at least two attacks more than D0 does there, and loses none that D0 detects there.

If both are accepted: the one detecting more attacks on LotL data; if equal, fewer FP nodes on the recorded data.
U3 is judged the same way against F0 and reported; it can only become an option (F0 is not a default).
If none is accepted, nothing changes.

## Limits, stated in advance

- The LotL data is a counterfactual relabelling of recorded attacks (the attacker's file and network activity is
  unchanged); it measures dependence on program novelty, not a real LotL intrusion. Models are not retrained.
- Development result on seen sets; the alarm's design followed an exploration on them.
- An attacker who uses a program that already contacts unknown addresses (a browser, an updater) is not seen by
  this alarm; an attacker present during the baseline can make a program "normally" contact unknown addresses.

## Decision record (2026-11-12; results/, lab_v14 scripts/summ17.py with tags res20-none / res20-lotl)

Sanity: Z0 on LotL data detects 18 attacks, as lotl_paper's P2.

| variant | recorded data: attacks / deterministic alone / TP / FP | LotL data: attacks / deterministic alone / TP / FP | rule |
|---|---|---|---|
| Z0 (released 0.10) | 26 / 21 / 333 / 1,051 | 18 / 9 / 273 / 1,010 | - |
| D0 (default: + `exec_once`) | 26 / 21 / 331 / 1,035 | 18 / 9 / 273 / 994 | ref |
| U1 `unusual_network` as evidence | 26 / 21 / 334 / 1,057 (+2.1 %) | 19 / 9 / 286 / 1,016 | **rejected**: +1 attack on LotL data, 2 required |
| U2 `unusual_network` alerting | 26 / 21 / 344 / 1,249 (+20.7 %) | **22 / 17** / 295 / 1,202 | **rejected**: FP above +10 % |
| F0 (identity options, not a default) | 27 / 26 / 334 / 1,199 | 20 / 16 / 276 / 1,158 | ref for U3 |
| U3 F0 + `unusual_network` as evidence | 27 / 26 / 338 / 1,236 | 20 / 16 / 290 / 1,195 | rejected: no attack gained on LotL data |

No attack and no attack-day is lost by any variant on either data.

**No variant accepted: the default does not change.** What the lab shows:

- Alerting by itself (U2), the alarm recovers four of the eight attacks that relabelling hides (ATLASv2 m5, m6, s3;
  CARBANAKv2 h1) and the deterministic layers then find 17 instead of 9 attacks without any new program - at 214
  more false-positive nodes on the recorded data (+20.7 %; CARBANAKv2 +145: Store apps, Git's perl, Python).
- As evidence (U1) it costs almost nothing (+22 FP) and gains almost nothing (+1 attack): the learned score does not
  rise on a relabelled process's first unknown contact, so it rarely corroborates. The alarm is only as useful as
  it is allowed to alert.
- Correct program parsing in layer 2 (F0) by itself raises LotL detection from 18 to 20 and deterministic-only
  detection there from 9 to 16: the second lab in which the rejected-by-limit identity options are the more robust
  detector.

`net_profile` stays in the engine, off. Like the identity options it is a trade the numbers describe and the limit
set in advance refuses: more detection that does not depend on program novelty, for 15 - 20 % more false-positive
nodes on these (incompletely labelled, lab_v14 "What was looked at", item 2) sets.
