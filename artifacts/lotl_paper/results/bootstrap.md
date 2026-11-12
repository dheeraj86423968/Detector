# Bootstrap 95 % intervals, STRATA 0.10 (P2), 16 development sets

10,000 resamples, seed 20261112, percentile intervals; every statistic is a ratio of sums over the resampled units (sets or families). Inputs: artifacts/lab_v10/results/res13-*.json, inc13-final.json (P2/G2 = 0.10 grouping). Totals: 26/30 attacks, TP 333, FP 1051, 71 host-days, 178 false incidents.

| statistic | point | host bootstrap (16 sets) | family bootstrap (5 families) |
|---|---|---|---|
| detection rate | 0.867 | [0.750, 1.000] | [0.727, 0.963] |
| fp per host day | 14.80 | [10.24, 22.17] | [10.51, 28.59] |
| false incidents per host day | 2.51 | [1.72, 3.74] | [1.89, 5.24] |
| precision | 0.241 | [0.112, 0.370] | [0.105, 0.342] |

Family scheme: every family holds at least one attack, so every draw has a defined detection rate; with 5 clusters there are only 126 distinct resamples and the percentile interval understates uncertainty: read it as a sensitivity check, not a calibrated 95 % interval.
Host scheme: CARBANAKv2 h1-h5 count as 5 attacks (one multi-host campaign, as res13 counts it); in the family scheme they move together. ATLASv2 h1 holds 10 of the 30 attacks; a draw without it shifts the rate strongly.

| family | sets | attacks found | TP | FP | days | false incidents |
|---|---|---|---|---|---|---|
| ATLASv2 | 2 | 8/10 | 12 | 75 | 2 | 5 |
| DARPA E3 | 5 | 10/11 | 160 | 338 | 16 | 47 |
| CARBANAKv2 | 5 | 5/5 | 63 | 399 | 42 | 75 |
| OpTC | 3 | 3/3 | 98 | 142 | 9 | 23 |
| DARPA E5 | 1 | 0/1 | 0 | 97 | 2 | 28 |
