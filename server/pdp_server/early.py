"""Early-model milestones, shared by the training worker and the console (kept free of heavy imports).

Detection does not wait for the full baseline: while an endpoint learns, a model is trained on whatever activity it
has recorded so far - after 1 hour, after 6 hours, then once a day - and replaced by the final model when the
baseline (7 days + 1 validation day) is complete.
Which layers may alert from an early model (tools/maturity_eval.py, DARPA CADETS E3, all 3 attacks detected at
every level): with 1 hour of baseline the data-flow rules gave 30 alerts (29 on the attack) while new-program and
learned alerts were 10,742 and 170,389 - so models trained on less than a day alert from the rules only. From one
day on all layers alert: 140 false alerts at 1 day, 66 at 3 days, 66 with the full week."""
EARLY_MILESTONES_H = [1, 6] + [24 * d for d in range(1, 60)]
EARLY_MIN_WINDOWS = 4          # one hour of 15-minute windows: 3 to train on, 1 to calibrate on
EARLY_RULES_ONLY_BELOW_H = 24
