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

### 5. Our own operations — status: done (2026-11-04)
Done when: staging stack; CI runs unit + stack_e2e (99) + tenancy_e2e (90) on every commit; scheduled backups of the
platform DB, telemetry needed for training and bundles, with a tested restore; monitoring/alerting of our own
services (Prometheus + Grafana or equivalent); load test with ~50 simulated endpoints and the training queue.

Result (docs/OPERATIONS.md): staging stack (deploy/staging.sh: own project, volumes, ports 9445/9446, known admin
password); tests/run_unit.sh (server + agent images, also in CI) and tests/run_e2e.sh (stack 96, tenancy 90,
notify 27 checks, all passing on staging); encrypted daily backups (backup service: database, CA / KMS, current
models; deploy/restore.sh, rehearsed into staging: identical data, same CA, enrolment through the restored KMS);
/metrics + Prometheus/Grafana profile + `platform` operator notifications; load test with 50 simulated agents
(9 M events/hour, 2180 requests, 0 errors, p95 95 ms for event uploads, 15 ms for status polls).

## Soon after

### 6. Storage and training capacity — status: done (server 0.6, agent 0.3.12; 2026-11-04)
Raw events ~180 B each in Postgres until the final model (~1 GB for a quiet client, ~90 GB for a busy host).
Done when raw events are partitioned per day (cheap drop) or moved to compressed files; per-org fair training queue;
early (rules-only) models train on CPU so big hosts never block small ones.

Correction to the premise: raw events were already deleted once their day was cut into windows (one open day
stays), but row by row - on a busy host 60 M rows a day, slow and bloating. Result:
- raw events of new endpoints are partitioned by UTC day; after a day is windowed its partitions are dropped as
  tables (partially covered ones deleted, emptied ones dropped); partitions are created on upload
  (tests/e2e/partitions_check.py on staging's PostgreSQL). Existing endpoints keep their table until they finish.
- early models below one day are rules-only bundles (layers 1-2, no learned detectors; same rule alerts as the full
  model restricted to rules, tests/unit/test_rules_only.py): job kind `train_rules` on the CPU worker, seconds
  instead of a GPU run (23 min and 1.1 GB on the L40S host), a bundle of a few KB, no learned state on the agent.
  Only for agents >= 0.3.12 (older agents get the previous minimal model); agents now survive a model they cannot
  load (they keep / reload the current one).
- the job queue is fair between organisations: the organisation whose last job of that kind started longest ago
  goes first (tests/e2e/queue_check.py: ABAAAA instead of AAAAAB).
- fixed on the way: the early-model scheduler retrained the 6 h milestone every minute (milestone vs measured hours).
Open: one GPU worker still runs one final training at a time; scale `worker-train` (or add GPUs) when many clients
finish their baseline the same day.

### 7. Learn from analyst decisions — status: done (server 0.6, agent 0.3.13; 2026-11-04)
"Benign" verdicts feed the next retrain, not only the allowlist; periodic (monthly) retrain on recent benign activity
so models do not go stale after software updates.

Result: protected endpoints are retrained on fresh activity: after PDP_RETRAIN_DAYS (30) days, after
PDP_RETRAIN_FP (20) false-alarm verdicts, or from the console's Retrain button, the server asks the agent for the
next two whole days (config refresh_days); the agent (0.3.13) uploads them like its baseline while it keeps
protecting; once ingested, the endpoint is retrained on the most recent N+1 days plus a "feedback" day built from
the event context of every alert marked a false alarm (so the learned layers and the rules' known programs /
trusted addresses learn it). Entity ids the agent pruned meanwhile become placeholders on the server, so ids stay
aligned. Per-endpoint opt-out: config periodic_retrain=false. tests/e2e/refresh_e2e.py (12 checks on staging:
final model, verdict, two fresh days requested and seen by the agent, retrained model on the newest days + 1
feedback window, ids aligned, endpoint protected throughout).

### 8. Incident triage workflow — status: done (server 0.6; 2026-11-04)
Incident status (new / investigating / resolved / benign), assignee, notes, history; weekly per-org summary
(e-mail/PDF).

Result: incident owner (admins and analysts of the organisation), notes and a history of status changes
(with an optional note), assignments and notes, each with author and time (incident page "Triage" card); owner
column and Mine / No owner filters on the incident list. Weekly summary: printable console report
(/#/reports/weekly, print to PDF) and a Monday-morning notification on channels with the "weekly" event (default for
new channels). tests/e2e/triage_e2e.py (13 checks on staging, including organisation isolation).

### 9. Learning progress per endpoint — status: done (server 0.6; 2026-11-04)
Console shows "day N of 8, X MB uploaded, early detection on", expected upload volume and local disk use.

Result: the endpoint page shows a "Learning: day N of 8" card while an endpoint learns: progress bar, data uploaded so
far (compressed bytes the client's network carried, recorded per upload; older uploads estimated from the
endpoint's measured bytes per event), rate per day, expected total, the agent's local disk use and free space, the
early model in use (hours, rules-only or all detection types) and when the next model comes. client-vm-02: 7.3 MB so
far, about 200 MB expected (its first hours include the install's burst).

### 10. Login security — status: done (server 0.6; 2026-11-04)
MFA (TOTP), per-org SSO (Google / Microsoft OIDC), console audit log, per-org data retention setting.

Result: two-factor sign-in for password accounts (TOTP with any authenticator app, one-step clock skew, codes
accepted once, ten single-use recovery codes; the password step returns only a 5-minute second-step cookie) and an
organisation setting that requires it (users without it can only reach the setup). Per-organisation single sign-on
(Google Workspace, Microsoft Entra ID or any OIDC provider) by email domain: code flow with PKCE, ID token verified
against the provider's keys, verified email in the organisation's domains, users created only inside that
organisation; domains unique across organisations, public mail domains refused. Audit log of every console change
(method, route, ids, result, IP; no request bodies) and every sign-in, per organisation (Security page). Data
retention per organisation (30-3650 days, default 365), applied nightly. Tests: tests/unit/test_login_security.py
(22), tests/e2e/security_e2e.py (27) and retention_check.py on staging.
Open: proving domain ownership (DNS TXT) before an organisation's SSO is used; revoking existing sessions when a
password changes (sessions are signed cookies valid 12 h); the API reaches identity providers only through the egress
proxy (profile "sso"), whose allow list must list the providers' hosts.

## Later
- Response actions (opt-in kill process / network isolate). — done (server 0.6, agent 0.3.16; 2026-11-04): off per
  organisation until an admin turns it on (Security page). "Stop" on a process alert: the agent stops it only if the
  pid still is the alerted process (collector identity + executable; a reused pid is refused). "Isolate endpoint":
  nftables drops everything except the PDP server's addresses (resolved before isolating; no DNS while isolated, the
  agent connects to the pinned addresses with TLS verified against the server name), re-applied after agent
  restarts, with a self-check in the result; "Release" removes it. Verified on client-vm-02: a stale identity was
  refused, the live process stopped; isolation blocked new SSH and outside traffic while the agent kept reporting;
  release restored access. Every action is in the audit log and the command history.
- Search past activity (threat hunting over recorded provenance). — done (server 0.6, agent 0.3.17; 2026-11-04):
  "Search activity" in the console asks every reporting agent of the organisation; each keeps a local, de-duplicated
  30-day index (programs run with command line, addresses contacted, files written; first / last seen, count; capped at
  300k entries) and answers within its next status poll. The server keeps raw events only until they are windowed
  and protected endpoints upload none, so the endpoints are the store. Verified on client-vm-02: a marker file write, curl's connection to 172.66.147.243:443
  and the command lines were found within seconds; 183 index entries after 5 minutes. Staging e2e (hunt_e2e) 16/16:
  version gate, isolation between organisations, answers only from asked endpoints, viewers read-only.
- Kubernetes DaemonSet install, ARM64, kernels without BTF. (Windows parked.) — built 2026-11-04 (server 0.6, agent
  0.3.18), partly verified (details in docs/DEPLOYMENT.md 1 and 1b):
  - Kubernetes: Endpoints > Add endpoint > Kubernetes cluster gives a DaemonSet manifest with a fleet token (N nodes,
    expiry; each node its own endpoint named after the node; closable; re-download to update). Staging e2e 17/17.
    Not yet applied to a live cluster: downloading kind/kubectl was not allowed on this host.
  - Kernels without BTF: the loader takes a BTF file; the agent finds or downloads it (operator stocks deploy/btf,
    BTFHub layout works); the installer checks availability; a collector that cannot start no longer crash-loops
    the agent (heartbeat collector_error, retried every 10 min). Verified on the real kernel with BTF as a file.
  - ARM64: native image build, multi-architecture publishing, installer accepts aarch64, CI job on GitHub arm64
    runners. Verified here only: the arm64 BPF object compiles, the aarch64 torch wheel exists. Needs one run on
    arm64 hardware (CI job or an arm64 VM).
- Measured detection coverage against the harmless attack suite, tracked per release. — tooling built 2026-11-04,
  not run: `pdp_server.tools.coverage record|compare|list` runs the offline simulation suite (fixed seed) against a
  reference endpoint's model per release, stores it (coverage_history) and flags regressions; operator console card.
  Unit test (comparison rules) and a staging check with fixture rows pass. The first measurement was left to the
  user (no attack simulation of any kind without the go-ahead); docs/OPERATIONS.md has the release step.
