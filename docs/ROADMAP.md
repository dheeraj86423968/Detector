# PDP roadmap (agreed 2026-11-04)

Work is done **strictly in this order**. Each item lists the problem as measured, what "done" means, and its status.
Update the status line when an item lands (commit hash). Constraints that apply throughout: no attack simulation,
no rollout to clients yet, Windows parked, every new console route org-scoped with a tenancy_e2e probe.

## Before the first client

### 1. Agent footprint on busy hosts — status: done (agent 0.3.4 / 0.3.6, 2026-11-04)
Measured on the L40S host (dheeraj-gpu-machine), 11 h into baseline: local sqlite spool 9 GB (5.3 GB + 3.8 GB WAL),
agent RSS 5 GB, model bundle 1.1 GB (450 MB compressed), agent image 1.9 GB, registry 1.2 M entities (most seen once).
Quiet VM (client-vm-02): 47 MB spool after 5 h, 27 MB bundle.
Done when:
- uploaded events leave the spool promptly during baseline; the spool has a hard size cap (oldest dropped, counted,
  reported); WAL checkpointed;
- registry / bundle size no longer grow with one-off entities (short-lived files, process instances);
- CPU-only agent image (target ~300-500 MB);
- re-measured on the host: spool < 1 GB, RSS and bundle substantially down, detection on DARPA unchanged.

Result (same host): spool 9.5 GB -> 0.55 GB (finished rows deleted at once, compact rows, 1 GB cap, WAL truncated);
memory 5.1 GB -> 2.9 GB between windows (peak ~4.2 GB while scoring a 1 M-event window); image 1.86 -> 1.11 GB
(no PyG/SciPy: pure-torch TransformerConv, bit-identical); download 450 -> 370 MB (slim archive). Unbounded growth
removed: registry compaction drops entities unseen for 6 h that hold no pending work or rule state and are not a
neighbour of a kept entity (host simulation: 1.32 M -> 455 k); disk records of dropped post-baseline entities are
deleted once the final model is loaded; the per-event edge-type history is gone; the open window is replayed
from the spool after a restart instead of being saved as JSON on every batch. Detection: identical alerts on
CADETS without compaction (old vs new code); with compaction at 24 h / 6 h / 2 h all 3 attacks and the same 32
true positives, 1-3 benign alerts swapped (tests/unit/test_compaction.py proves exact equality when dropped entities
never return).
Still open (not blocking): the model bundle still scales with the baseline's entity count (370 MB on this host;
the server could drop rows of entities that ended before the baseline did); 300-500 MB image would need an
inference runtime other than PyTorch (libtorch_cpu alone is 467 MB).

### 2. Real-time rules — status: todo
Scoring runs on 15-minute windows, so an alert can come 15+ minutes late; ransomware finishes in that time.
Done when the deterministic rules (downloaded program executed, mass rename/encrypt, persistence write, etc.) are
evaluated per event as it arrives and reported within seconds; learned layers stay window-based; console shows the
alert immediately and the window result later enriches the same incident.

### 3. Notifications and export — status: todo
Alerts are only visible in the console. Done when: per-org notification settings; e-mail (SMTP) and Slack/Teams
webhooks for incidents above a severity and for agent offline / collector lost; generic webhook + syslog (CEF) export
for SIEMs; test-send button; rate limiting/digest so a noisy host does not spam.

### 4. Agent updates and health — status: todo
No upgrade command (re-running the installer leaves a stray token). Done when: agents auto-update from our registry
(org setting: auto / pinned version), rollout is staged, failed update rolls back; console shows agent health
(collector lost, disk nearly full, behind on scoring, version) and it feeds item 3 notifications.

### 5. Our own operations — status: todo
Done when: staging stack; CI runs unit + stack_e2e (99) + tenancy_e2e (90) on every commit; scheduled backups of the
platform DB, telemetry needed for training and bundles, with a tested restore; monitoring/alerting of our own
services (Prometheus + Grafana or equivalent); load test with ~50 simulated endpoints and the training queue.

## Soon after

### 6. Storage and training capacity — status: todo
Raw events ~180 B each in Postgres until the final model (~1 GB for a quiet client, ~90 GB for a busy host).
Done when raw events are partitioned per day (cheap drop) or moved to compressed files; per-org fair training queue;
early (rules-only) models train on CPU so big hosts never block small ones.

### 7. Learn from analyst decisions — status: todo
"Benign" verdicts feed the next retrain, not only the allowlist; periodic (monthly) retrain on recent benign activity
so models do not go stale after software updates.

### 8. Incident triage workflow — status: todo
Incident status (new / investigating / resolved / benign), assignee, notes, history; weekly per-org summary
(e-mail/PDF).

### 9. Learning progress per endpoint — status: todo
Console shows "day N of 8, X MB uploaded, early detection on", expected upload volume and local disk use.

### 10. Login security — status: todo
MFA (TOTP), per-org SSO (Google / Microsoft OIDC), console audit log, per-org data retention setting.

## Later
- Response actions (opt-in kill process / network isolate).
- Search past activity (threat hunting over recorded provenance).
- Kubernetes DaemonSet install, ARM64, kernels without BTF. (Windows parked.)
- Measured detection coverage against the harmless attack suite, tracked per release.
