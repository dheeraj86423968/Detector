# Operating the hosted service

What we (the operator) run next to the product itself: a staging stack, tests, backups, monitoring, load tests.

## Staging
`deploy/staging.sh up` starts a second, independent copy of the stack on the same host (compose project
`pdp-staging`: own volumes, network, database passwords and ports - console 9445, agent 9446; CPU training; open
sign-up; a known first admin password in `deploy/staging.env`). Use it for every release before production:
`deploy/staging.sh up` (current local images), `tests/run_e2e.sh`, then roll production.
Staging listens on 127.0.0.1 only (open sign-up, known admin password): reach it with an SSH tunnel. It serves the
console build under test from `console/dist-next` (build with `npx vite build --outDir dist-next`); production serves
`console/dist`, copied over only when production's API is rolled, so production's console never runs ahead of its
API:

```
deploy/rollout.sh api                                         # after building pdp/server:dev and testing on staging
rsync -a --delete console/dist-next/ console/dist/            # the console for that API (in place: the gateway mounts it)
deploy/publish-agent.sh <agent version>                       # when the release has a new agent
``` `deploy/staging.sh destroy`
deletes its data. It never shares data or keys with production (a restore rehearsal copies production into it;
destroy it afterwards).

## Tests
- `tests/run_unit.sh [server image] [agent image]`: every unit test in the server image, the agent-side ones again
  in the slim agent image. CI (`.github/workflows/tests.yml`) builds both images and runs the same script on every
  push. `PDP_SKIP_TESTS="test_suite"` on a host whose agent is part of the field validation (test_suite runs the
  harmless attack-suite programs, which that agent then reports).
- `tests/run_e2e.sh`: against staging - `stack_e2e` (console + agent protocol), `tenancy_e2e` (organisation
  isolation), `notify_e2e` (notifications, including the internal-address guard of the deployed notifier).
- `tests/load/loadtest.py`: N simulated agents (below).

## Detection coverage per release
Before rolling a release, measure detection the same way as for every earlier release and compare:
`docker compose exec api python -m pdp_server.tools.coverage record --release <version> --endpoint <reference id>`
then `... coverage compare --release <version>` (exit 1 on a regression). The reference is one endpoint with a
trained model kept for this purpose (a dataset-replay benchmark endpoint, or a long-running internal one); the suite
is `sim/suites/client_acceptance.json` (7 synthetic families x 6 evasion levels, 210 runs) with a fixed seed. It is
the offline simulation (sim/): attack graphs injected into the reference endpoint's recorded benign windows and
scored by the real detector, as a worker job; nothing is executed on any host. Regressions: overall detection down
by more than max(5 points, the CI half-width), a family down 20 points or more, false positives per day up by more
than 50%. Results: Console > Organisations (operators) > Detection coverage by release, `coverage list`, table
`coverage_history`. Comparisons only between runs with the same suite on the same endpoint (a re-trained reference
model starts a new series in practice: note it in the release notes). Not measured yet: the first run is the
operator's call (it is an attack simulation, even if offline).

## Backups and restore
The `backup` service (always on) writes an encrypted archive every `PDP_BACKUP_INTERVAL_H` hours (24) to
`deploy/backups/` and keeps `PDP_BACKUP_KEEP` (7): the platform database, CA / key files, the bundled KMS (OpenBao
storage, unseal key, token) and the model each endpoint uses; `PDP_BACKUP_FULL=1` adds raw baseline telemetry and
training windows (only needed to retrain endpoints still learning; large). AES-256 with the key in
`deploy/backup.key` - the archive holds the signing keys, so **copy that key off the host** (password manager), and
copy the archives off the host too (`deploy/backups/` is local). `touch deploy/backups/run-now` forces a run.
Status: kv `backup`, `pdp_backup_*` metrics, and a `platform` notification when a backup fails or is older than 36 h.

Restore: `deploy/restore.sh deploy/backups/pdp-<ts>.tar.gz.enc` restores into **staging** (rehearsal);
`--production` into production (asks for confirmation). A staging restore disables all notification channels of
the copy. Forgotten admin password: `docker compose exec api python -m pdp_server.tools.reset_password admin`.

Rehearsed 2026-11-04: production backup (1.2 GB, 49 s) restored into staging; organisations, users, endpoints,
alerts and models identical; CA fingerprint identical; a new agent enrolled through the restored KMS and got a
certificate from the production CA; the model-signing key matched the one production agents hold.

## Monitoring
- `GET /metrics` on the API (Prometheus text; internal - the gateway does not route it): endpoints by phase and
  online, agent versions, job queues and the oldest waiting job, alerts and baseline uploads per hour, backup and
  notifier age, database sizes, free data disk.
- `docker compose --profile monitoring up -d prometheus grafana`: Prometheus scrapes every API replica and
  evaluates `deploy/monitoring/rules.yml`; Grafana (dashboard "PDP platform") on 127.0.0.1:3000 only
  (`ssh -L 3000:127.0.0.1:3000`, admin password `PDP_GRAFANA_PASSWORD` in deploy/.env).
- Operator alerts without Prometheus: a notification channel of the internal organisation with the `platform`
  event (Console > Notifications, operators only): failed / old backup, jobs waiting over 2 h, crashed jobs, server
  data disk under 10%.

## Load test
`tests/load/loadtest.py --agents 50 --minutes 10 --events-per-min 3000` against staging, 2026-11-04: 50 agents
uploading 9 M events/hour, 2180 requests, 0 errors; p95 latency: event upload (3000 events, gzip) 95 ms, entities
54 ms, status 15 ms, heartbeat 16 ms, enrolment 27 ms; each API replica ~190 MB, CPU under 10%. The training queue is
the limit, not the API: one GPU worker trains one final model at a time (early models below one day are rules-only
and run on the CPU worker; the queue alternates between organisations). Other e2e checks for the same stack:
tests/e2e/partitions_check.py, queue_check.py, refresh_e2e.py, triage_e2e.py.
