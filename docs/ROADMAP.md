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

### 2. Real-time rules — status: done (agent 0.3.7, 2026-11-04)
Scoring runs on 15-minute windows, so an alert can come 15+ minutes late; ransomware finishes in that time.
Done when the deterministic rules (downloaded program executed, mass rename/encrypt, persistence write, etc.) are
evaluated per event as it arrives and reported within seconds; learned layers stay window-based; console shows the
alert immediately and the window result later enriches the same incident.

Result: the agent runs layers 1-2 on every batch of spooled events (Runtime.rules) and posts the alerts they raise
on their own immediately; the window is scored with those hits (no second pass), so window results are unchanged:
CADETS test days give identical alerts with rules run on 5000-event slices vs whole windows; synthetic stream
(tests/unit/test_realtime.py) identical per window, the download-and-execute alert available 17 events after the
execution instead of at window close. Real-time alerts are not re-sent with their window or after a restart
(tests/unit/test_agent_realtime.py). They join the window's incident (incidents group by time). Learned and
corroborated alerts still come with the window.

### 3. Notifications and export — status: done (server 0.6, 2026-11-04)
Alerts are only visible in the console. Done when: per-org notification settings; e-mail (SMTP) and Slack/Teams
webhooks for incidents above a severity and for agent offline / collector lost; generic webhook + syslog (CEF) export
for SIEMs; test-send button; rate limiting/digest so a noisy host does not spam.

Result: org-scoped channels (notify_channels) for e-mail, Slack, Teams, signed webhooks and syslog CEF, managed in
Console → Notifications (test button, delivery history, last error); events: incidents at/above a severity (and
escalations), agent offline/back, collector or spool event loss; webhook/syslog can also take every alert (SIEM
feed, replaces the server-wide exporter, whose env settings become an internal-org feed). The `notifier` service is
the only backend service with egress; it refuses destinations resolving to internal addresses (SSRF guard for the
hosted service). At most 20 messages per channel and hour plus one hourly digest. Tests: tests/unit/test_notify.py
(19), tests/e2e/notify_e2e.sh (27, against the live stack). Open: e-mail needs an SMTP relay configured on this
server (PDP_SMTP_URL) - not set yet, so the console offers Slack/Teams/webhook/syslog only.

### 4. Agent updates and health — status: done (agent 0.3.8, server 0.6, installer 0.6; 2026-11-04)
No upgrade command (re-running the installer leaves a stray token). Done when: agents auto-update from our registry
(org setting: auto / pinned version), rollout is staged, failed update rolls back; console shows agent health
(collector lost, disk nearly full, behind on scoring, version) and it feeds item 3 notifications.

Result: org policy auto / pinned / manual (Console > Endpoints > Agent updates); staged per organisation (one
endpoint first, the rest after 30 min on the version); the agent gets a 15-minute pull credential and hands it to
the host's updater (installed by install.sh, runs as root before each start), which pulls, switches and rolls
back after repeated unconfirmed starts; a failed version pauses the organisation's rollout. `install.sh --upgrade`
installs the updater on an enrolled host without a token. Health (disk, event loss, behind, failed update, needs
--upgrade) on the endpoint page and as agent_health notifications. Verified on client-vm-02: 0.3.8 -> 0.3.9
self-update via the registry (confirmed in 1 s), deliberately broken 0.3.10 rolled back after 4 starts, rollout
held. tests/unit/test_updater.py (10), test_agent.py update checks. The L40S host keeps its hand-made unit
(updated by hand); 0.3.9/0.3.10 were rollout test builds, 0.3.11 is the release.

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
