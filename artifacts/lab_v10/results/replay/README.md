# Real agent replay of the 16 lab sets (replay10-*), 2026-11-09/10

Run with `artifacts/lab_v10/replay/replay10.py run` (image pdp/server:v101rc). Each set was enrolled as its own endpoint,
uploaded its baseline, received a freshly trained bundle and scored the test days locally in the agent. Scored with
`compare10.py` -> `compare10.json`.

| | Lab (0.10, P2) | Replay |
|---|---|---|
| Attacks found (of 30) | 26 | 26 |
| TP nodes | 333 | 333 |
| FP nodes | 1,051 | 1,155 (+10%) |
| Incidents (false) | 220 (178) | 222 (180) |

- Raw db-replay (9 sets: E3 CADETS/THEIA/ClearScope/FiveDirections, OpTC x3, ATLASv2 h1/h2): 18 att, TP 261, FP 485 -> 543.
- Stored fused edges (7 sets: TRACE, E5 THEIA, CARBANAKv2 h1-h5): 8 att, TP 72, FP 566 -> 612.
- Jaccard of alerted node sets per layer over all sets: novelty 1.00 (identical on all 16), rules 0.90 (identical
  on 12; differ on E3 THEIA, OpTC H201/H501, CARBANAKv2 h3, cause not isolated), corroboration 0.61 (bundles were
  retrained; learned scores differ by training run).
- 7 sets match the lab's TP/FP exactly. Training on the L40S: 1-108 min per host, median 27.
- The agent never flushes its last open window, so that window is rules-only; no TP was lost overall.
