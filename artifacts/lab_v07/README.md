# 0.7 lab (2026-11-07): learned detection first

PROTOCOL.md: goal, data split, acceptance rule (written first), decision record before the held-out run, and what
happened after it. Run scripts with run.sh (server image, working tree mounted, /data volume, ground truth at /gt).

- bl.py, run_bl.py, run_v2..v4.py: detector-3 prototype (behavioural likelihood) and propagation variants on cached
  learned scores (cache_scores.py / cache_val.py of the 0.5 bundles, jobs05.txt). parity.py: production module
  (pdp_engine.behaviour) == prototype.
- combine.py / combine_topk.py: unions with the information-flow alerts (l2nodes.py); the top-K-per-day numbers are
  after-the-fact (not achievable live) and were not used for decisions.
- prod07.py: the product path end to end (upgrade_bundle_07 + Runtime, streaming) - prod07-<variant>-<set>.json:
  v07r (frozen 0.7), v07r-corr1, v07b (novelty as evidence), v07c (per-activity thresholds), v07l (layer 1 alerting),
  v07l-corr1 (released).
- heldout_eval.py / heldout.sh: the held-out run (once) - heldout-*.json; seen07{b,c,l,ls}-*.json: the variants on
  those hosts afterwards. diag_trace.py: the post-hoc TRACE diagnosis.
