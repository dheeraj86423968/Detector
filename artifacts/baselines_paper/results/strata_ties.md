# STRATA 0.10 triage ADP under different tie orders

Order = alert tier x 1e6 + our learned score (P2 = 0.10 as released; res13/adp13), `darpa_eval.adp`. From anchor13.py's per-node dumps
(the pass reproduces res13/adp P2 exactly on every set). Random = mean (sd) of 20 random permutations within ties; worst = ground-truth
nodes last within every tie; best = first. 'GT tied' = share of ground-truth nodes whose key equals that of at least one benign node
(alerted = how many of those are alerted).

| set | GT nodes | ADP stable (reported) | random mean (sd) | worst | best | GT tied with benign | of which alerted |
|---|---|---|---|---|---|---|---|
| ATLASV2_EDR-h1 | 48 | 0.214 | 0.215 (0.001) | 0.214 | 0.219 | 0.48 | 3 |
| ATLASV2_EDR-h2 | 0 | 0.000 | 0.000 (0.000) | 0.000 | 0.000 | 0.00 | 0 |
| CADETS_E3 | 68 | 1.000 | 1.000 (0.000) | 1.000 | 1.000 | 0.28 | 0 |
| CARBANAKV2_EDR-h1 | 63 | 0.061 | 0.061 (0.000) | 0.061 | 0.061 | 0.40 | 0 |
| CARBANAKV2_EDR-h2 | 81 | 0.483 | 0.483 (0.000) | 0.483 | 0.483 | 0.32 | 4 |
| CARBANAKV2_EDR-h3 | 26 | 0.043 | 0.043 (0.000) | 0.043 | 0.043 | 0.65 | 0 |
| CARBANAKV2_EDR-h4 | 21 | 0.130 | 0.133 (0.003) | 0.130 | 0.136 | 0.48 | 1 |
| CARBANAKV2_EDR-h5 | 21 | 1.000 | 1.000 (0.000) | 1.000 | 1.000 | 0.43 | 5 |
| CLEARSCOPE_E3 | 41 | 0.200 | 0.188 (0.016) | 0.167 | 0.200 | 1.00 | 0 |
| CLEARSCOPE_E5-clearscope | 34 | 1.000 | 1.000 (0.000) | 1.000 | 1.000 | 0.50 | 2 |
| CLEARSCOPE_E5-clearscope-3att | 51 | 0.668 | 0.668 (0.000) | 0.668 | 0.668 | 0.37 | 2 |
| FIVEDIRECTIONS_E3 | 108 | 1.000 | 0.136 (0.077) | 0.077 | 1.000 | 0.81 | 10 |
| OPTC_H051 | 114 | 0.709 | 0.840 (0.145) | 0.709 | 1.000 | 0.34 | 24 |
| OPTC_H201 | 2905 | 0.749 | 0.749 (0.000) | 0.749 | 0.749 | 0.36 | 0 |
| OPTC_H501 | 749 | 1.000 | 0.929 (0.124) | 0.666 | 1.000 | 0.08 | 11 |
| THEIA_E3 | 118 | 1.000 | 1.000 (0.000) | 1.000 | 1.000 | 0.11 | 12 |
| THEIA_E5-theia | 66 | 0.001 | 0.000 (0.000) | 0.000 | 0.001 | 1.00 | 0 |
| TRACE_E3-trace | 35 | 0.127 | 0.131 (0.006) | 0.123 | 0.175 | 0.60 | 6 |

Mean over the 8 hosts with published results (E5 ClearScope with 2 attacks): stable 0.707, random 0.713, worst 0.661, best 0.744.
Mean over all 17 sets (E5 ClearScope 2 attacks): stable 0.513, random 0.465, worst 0.437, best 0.533.

Ties come from nodes with the same tier and the same learned score (e.g. alerted nodes whose clipped/missing score is equal, and the large
block of unalerted nodes with score 0). The reported (stable) value uses node-id order inside ties, which is label-independent but
arbitrary; on FiveDirections and OpTC H501 it is far from the random-order expectation.
