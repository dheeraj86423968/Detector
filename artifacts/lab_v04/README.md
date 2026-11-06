# 0.4 detection lab (2026-11-06)

PROTOCOL.md: development / held-out split and acceptance rule (fixed before any change was tried), the frozen
configuration and what was rejected. cache_scores.py: per-window learned scores of the 25 published 0.3 bundles
(GPU, once). lab.py: layers 1-2 and the alert policy re-run on the cached scores for a set of variants (v6/v7.json:
the development ablations, final.json: the one held-out run); r6-*/r7-*.json and final-*.json are their outputs.
benign_check.py: the label-free benign-day check. Run with the server image and the working tree mounted
(/data volume, ground truth at /gt). The official numbers (docs/BENCHMARK_*.md, "0.4") come from tools.add_layers +
tools.darpa_eval on the same bundles and reproduce the lab results exactly.
