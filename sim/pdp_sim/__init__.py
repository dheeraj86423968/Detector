"""pdp_sim: randomised adversarial simulation against the deployed detectors.

Attack sources
  * synthetic graph-level attack families (attacks.py) modelled on DARPA TC E3/E5 and OpTC behaviours,
    living-off-the-land, privilege escalation / lateral movement, exfiltration and ransomware
  * transplants of real DARPA attack subgraphs (transplant.py) taken from the research databases
Evasion (evasion.py): mimicry padding (Goyal et al. 2023), label camouflage, slow-and-low spreading.
Injection (inject.py) places an attack into the fused windows of a benign day; the campaign runner
(campaign.py) scores clean and injected passes with the real Runtime and reports detection rate,
time-to-detect, false positives per endpoint-day and robustness against evasion strength with
confidence intervals.
"""
