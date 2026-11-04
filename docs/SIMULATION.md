# Adversarial simulation

`sim/pdp_sim` runs randomised campaigns of attacks against the deployed detectors and reports how well the
detection pipeline (detector-1, detector-2 and the 2:1 fusion) holds up. It uses the *real* engine runtime and
bundle of an endpoint, so results describe exactly what the agent would alert on.

## Attack sources

| source | families | notes |
|---|---|---|
| synthetic graph-level (`attacks.py`) | `web_backdoor` (DARPA E3 CADETS Nginx backdoor), `browser_dropper` (E3 THEIA Drakon dropper / Firefox backdoor), `lotl_recon` (living off the land), `priv_esc_lateral`, `exfiltration`, `ransomware`, `script_c2` (OpTC-style scripted implant) | generators are parameterised and random (names, drop paths, C2 addresses, counts); process labels follow the endpoint's own label style |
| transplants (`transplant.py`) | `transplant:<dataset>_<attack>` | real attack subgraphs extracted from the DARPA TC research databases with the ORTHRUS ground truth and the attack time windows (every event touching a ground-truth node). Files under `sim/attacks/*.json`; produce with `python -m pdp_sim extract` |

An attack is a small provenance subgraph attached to an existing *host* process of the endpoint (role-matched:
web server, browser, shell, or any busy process). Malicious nodes = the new entities marked malicious plus the
host, mirroring how the DARPA ground truth counts the compromised server process.

## Evasion

| level | mimicry padding edges | label camouflage | slow-and-low spread |
|---|---|---|---|
| none | 0 | 0 | 0 |
| low | 50 | 25 % | 2 min |
| medium | 200 | 50 % | 15 min |
| high | 600 | 75 % | 60 min |
| extreme | 1500 | 100 % | 180 min |
| stealth | 0 | 100 % | 0 (half of the optional events removed) |

Finding on CADETS: padding and spreading do not reduce detection (node scores are the maximum edge loss, which
added benign edges cannot lower, and spreading gives more windows in which to exceed the threshold); camouflage
and footprint minimisation are the effective evasions, so `stealth` is the level to track.

Padding follows the PIDSMaker / Goyal et al. mimicry construction: benign OPEN/READ/WRITE structures between
attack processes and the endpoint's own benign files, bound to the real file nodes by label. Camouflage renames
attack processes to frequent benign process labels and places dropped files under existing directories.
Spreading stretches the attack across windows. Explicit values can be given instead of a level name
(`{"padding": 300, "camouflage": 0.5, "spread_s": 1800}`).

## Injection and scoring

Attacks are injected into the fused windows of a benign day (default: the validation day of the bundle, or any
held-out day; benchmark endpoints replay held-out days from the research database). Window boundaries are kept
so the clean and injected passes align; each affected window is re-fused from the merged event stream, which is
what the agent's window builder would have produced. Every pass starts from the bundle's initial state
(`Runtime.reset`), so passes are independent. Several attacks are placed per pass, at least `horizon_windows + 1`
windows apart.

Detection of an attack = any malicious node above the fused threshold in the placement window or the next
`horizon_windows` windows (also recorded for each detector alone). Time-to-detect is measured from the attack's
first event to the close of the first alerting window. Node recall is the fraction of malicious nodes flagged.

## Metrics

* detection rate overall, per family, per evasion level and per family × level, with Wilson 95 % intervals
* median time-to-detect with bootstrap 95 % intervals
* false positives per endpoint-day on the clean pass, and collateral false positives (benign nodes alerted in an
  attack pass but not in the clean pass)
* `spec_hash` (spec without seed) for regression tracking between campaigns on different bundles

## Running

Console → Simulation → New campaign (queued as a `sim` job on the training worker), or standalone:

```
python -m pdp_sim run --store <window store> --bundle <bundle dir> --spec spec.json --out result.json --device cuda
python -m pdp_sim extract --dataset CADETS_E3 --gt-dir <PIDSMaker>/Ground_Truth/orthrus --out sim/attacks
```

Spec fields: `days`, `runs`, `attacks_per_pass`, `families`, `evasion_levels`, `seed`, `horizon_windows`, `fp_budget`.
Unit tests: `PYTHONPATH=engine:sim python tests/unit/test_sim.py`.

- See `docs/SANDBOX.md` for the phase-5 live sandbox (strace collector + attack-shaped workloads) and `pdp_server.tools.sandbox_eval`.
