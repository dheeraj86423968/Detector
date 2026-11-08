# Security review, 2026-11-08 (server, agent channel, bundles, console, deployment, endpoint agent)

Scope: a code review of `server/`, `agent/`, `engine/pdp_engine/bundle.py`, `deploy/`, the console (`console/src`) and the
desktop wrapper (`desktop/`), after the 0.6 hardening (docs/DETECTION_LAYERS.md "0.6", `tests/unit/test_integrity.py`,
`test_login_security.py`, `test_oidc.py`, `tests/e2e/security_e2e.py`, `misuse_check.py`). Exploitability was judged
by reading the code and with unit tests only (`tests/unit/test_security_hardening.py`); nothing was run against a
stack. Line numbers refer to the code *before* this review's commits (`git show d28da57:<file>`), unless marked "now".

Severity = impact x likelihood for a hosted multi-tenant deployment whose compromise means compromise of every
client endpoint (the agent runs as root with eBPF). **Fixed** = changed on this branch with a unit test;
**Reported** = described here with the exact change to make.

## Summary

| # | Sev | Area | Where | Scenario | Status |
|---|---|---|---|---|---|
| F1 | **High** | Console auth | `server/pdp_server/mfa.py:86-105`, `deploy/nginx/console.conf:17` | The second-factor step had no failure counter and the gateway rate limit covered only `location = /api/login`, not `/api/login/mfa`. With a stolen password an attacker gets a 5-minute pending cookie and guesses the 6-digit TOTP at the API's own pace (the 0.5 s sleep runs in a thread pool, so it only bounds one connection); with 3 valid codes per window and ~200 attempts/s the chance per cookie is ~15-20 %, and a new cookie costs one password login. Recovery codes (32 bits) had the same exposure. Two-factor sign-in - the control that `require_mfa` makes organisations rely on - was bypassable. | **Fixed**: wrong codes count towards the same lock-out as wrong passwords (`access.note_failed_sign_in`, shared with `api.login`); a locked account gets 429 even for a right code; the gateway limit now matches `^/api/login(/mfa)?$`. |
| F2 | **High** (local to the server host) | Agent updates / registry | `deploy/docker-compose.yml:129-137`, `deploy/publish-agent.sh:25-28`, `server/pdp_server/updates.py:95`, `install.sh.tmpl:232,306-325` | The image registry has no authentication on its push port (`127.0.0.1:5000`), tags are mutable and nothing (installer, updater, agent) pins a digest or verifies a signature. Any process or unprivileged user *on the server host* (or a compromised container on `backend`/`edge`, e.g. the notifier) can `docker push 127.0.0.1:5000/pdp/agent:<published>`; every new install and every "auto" organisation then runs that image as root with `--privileged` on every endpoint. | **Fixed (round 2)**: `publish-agent.sh` records the manifest digest (`PDP_AGENT_DIGEST`, `PDP_AGENT_DIGESTS`), installer / updater / `update_for` hand out `<host>/pdp/agent:<ver>@sha256:...` only, the agent and the host updater refuse tag-only references; the registry runs read-only except during a publish and has no published port, pushes go through the gateway's loopback listener with HTTP basic auth (`bringup.sh`/`staging.sh` generate the credentials). Cosign skipped (see round-2 notes). Original fix note: (a) record the image digest at publish time (`docker inspect -f '{{index .RepoDigests 0}}'` in `publish-agent.sh` -> `PDP_AGENT_DIGEST` in `.env`) and hand `image@sha256:...` to the installer and `updates.update_for`; (b) htpasswd auth on the registry push path (the gateway's `/v2/` pull path already authenticates through `/api/registry/auth`), or run the registry only during publish; (c) cosign the image and verify in the updater. |
| F3 | **Medium-High** | Agent updates (endpoint side) | `agent/pdp_agent/agent.py:1177-1205` | The agent handed whatever `image`/`registry` the pull-token answer named to the host updater (charset check only); `docker login <registry>` + `docker pull` + run as root followed. A compromised server, or anything that can answer `/v1/endpoints/{id}/pull-token`, could point every endpoint at an arbitrary registry. | **Fixed**: `Agent.update_source_problem` refuses a registry whose host is not the enrolled server's (`agent_url`/`server_url`) and an image outside that registry. (A signature on the image remains the proper second root of trust: see F2.) |
| F4 | **Medium** | Agent updates (policy) | `server/pdp_server/updates.py:87-88,125-129` | A pinned version "may downgrade": any *org admin* (not the operator) can pin an older agent version and roll every endpoint of the organisation back to a release with known-weaker detection (0.6/0.7 closed evasion paths). A compromised admin account silently weakens detection fleet-wide; `set_policy` is audited only by the generic middleware (no `detection_weakened` event). | **Fixed (round 2)**: `updates.set_policy` refuses a pin below the fleet's running versions for organisation admins (403); the operator may, with a reason, and it is audited (`audit_change`) and raised as a `detection_weakened` security event (`weakened`); versions without a recorded digest cannot be pinned. Original note: treat a pin below the endpoints' current version as a weakening (`posture.require_reason` + `posture.weakened`), or allow downgrades only to the operator (`s["op"]`), and refuse versions below a `PDP_AGENT_MIN_VERSION` the operator sets after a security release. |
| F5 | **Medium** | Agent updates (policy) | `server/pdp_server/updates.py:58-66` with `api.py:384` (`Heartbeat.update`) | `rollout()` holds back a version for the whole organisation when *any* endpoint's heartbeat lists it under `update.failed`. The heartbeat is agent-controlled: one compromised (root) endpoint can veto every future agent update for its organisation - i.e. keep the fleet on the version it can evade. | **Fixed (round 2)**: `updates.hold()` holds a version only when >= `PDP_UPDATE_HOLD_MIN` (2) endpoints reported it failed AND they are >= `PDP_UPDATE_HOLD_PCT` (10 %) of the endpoints that tried it; which endpoints reported is returned (`failed_on`) to the console; an endpoint that failed is never picked as canary. Original note: the hold should come from the server's own observation (the canary endpoint stopped reporting / reported an older version after the offer), not from a self-reported list; and give admins an override ("roll out anyway", audited). |
| F6 | **Medium** | Tenant isolation (agents) | `server/pdp_server/api.py:140-151` | `agent_endpoint` checked the certificate CN and the endpoint row but not the organisation: a *suspended* organisation's agents kept uploading telemetry, fetching models and commands and consuming storage after the operator disabled it (only console sessions and enrolment were refused). | **Fixed**: 403 when the organisation is disabled. |
| F7 | **Medium** | Injection / worker | `server/pdp_server/api.py:1223-1231`, `sim/pdp_sim/campaign.py:145-146`, `worker.py:555-567` | `POST /api/sim/campaigns` accepted `families`, `evasion_levels` and `days` unchecked. `transplant:<name>` becomes `open(os.path.join(ATTACK_DIR, name + ".json"))` on the worker, `days` become window-store directory names: an analyst could make the worker read any `*.json` on its disk (e.g. another organisation's bundle manifest; the error text surfaces in `/api/jobs`), and unbounded `horizon_windows`/non-integers crashed the job. | **Fixed**: `api.validate_campaign_spec` (families from `sim_family_list()`, levels from a fixed list, days `validation` or `YYYY-MM-DD`, all numbers bounded). |
| F8 | **Medium** | SSRF / notifier | `server/pdp_server/notify.py:230-233`, `exporter.py:111-115` | Syslog channels: `resolve_public()` checked the name, then `SyslogSink._connect()` resolved it *again* and connected to whatever it got (the notifier is the one service on both the internet-facing `edge` and the `backend` network). A DNS-rebinding name (public at check, `172.x`/`kms`/`registry`/`platform-db` at connect) let a client admin push CEF frames with partly chosen text at internal TCP/UDP services. Webhooks were already pinned (`_PinnedHTTPS`). | **Fixed**: the sink connects/sends to the checked address (`SyslogSink.addr`/`dest()`), TLS SNI still for the name. |
| F9 | **Medium** | Secrets / deployment | `deploy/docker-compose.yml:123` (`gateway: pdp_pki:/pki:ro`), `server/pdp_server/pki.py:54,63` | In `PDP_KMS=file` mode the CA private key and the Ed25519 bundle-signing key live in the same volume the internet-facing nginx container mounts (it needs only `server.key`, `server-chain.pem`, `ca.pem`). A gateway compromise (nginx CVE) yields the keys that issue agent certificates and sign models for every endpoint. Production uses the KMS (`bringup.sh` sets `PDP_KMS=transit`), so this is the non-KMS path only. | **Fixed (round 2)**: private material (CA key, bundle-signing key, session secret) lives in `PKI_DIR/private` = the new `pdp_pki_private` volume mounted into api, workers and backup only; `pki.migrate_private()` moves legacy files on the first start under the init lock; `kms_setup.py` looks in both places. Original note: `pki.py` writes private material to `PKI_DIR/private/` and the gateway mounts a separate `pdp_gateway_tls` volume that `issue_server_cert`/`write_chain` populate (or mounts only `server*.pem`, `server.key`, `ca.pem` via a sidecar copy). Document that file mode is development-only. |
| F10 | **Medium** | Endpoint credential handling | `deploy/docker/agent-entrypoint.sh:14`, `api.py:814-815` (install / package commands), `install.sh.tmpl` | The enrolment token was passed as a command-line argument of `python -m pdp_agent enroll <token>` inside a `--pid=host` container, i.e. world-readable in `/proc/*/cmdline` on the endpoint for the whole enrolment (up to 30 retries). The one-line installer (`sudo bash -s -- --token <t>`) and the package installer likewise expose it in argv, `sudo` logs and shell history for the install duration. A local unprivileged user on a shared host can take the 24 h token and enrol a rogue endpoint into the customer's organisation (and pull the agent image). | **Fixed** for the container path: `enroll env`/`enroll -` reads `PDP_ENROLL_TOKEN` or stdin; the entrypoint uses it. **Fixed (round 2)** for the installers: `install.sh` and `pdp-agent-install` accept `--token-env` (from `PDP_ENROLL_TOKEN`), `--token-file FILE` and `--token-stdin`; the console API returns `install_command_env` next to `install_command`, and the docker command exports the token instead of passing it as `-e NAME=value`. Original note: add `--token-file`/stdin to `install.sh.tmpl` and `pdp-agent-install`, and make the console's install commands pipe the token (`echo <t> | sudo bash -s -- --token-stdin`). |
| F11 | **Medium** | Ingest limits | `server/pdp_server/api.py:214-364`, `integrity.py:58-61`, `deploy/nginx/gateway.conf` | Per-request bounds exist (0.6: 1 GB decompressed, ratio 200, 250 k rows, 8 partitions) but there is no per-endpoint quota or rate limit on the 8443 port: a compromised endpoint can upload at line rate forever and fill the telemetry volume / platform DB (`upload_batches`, `alerts`, `windows`) for everyone. | **Fixed (round 2)**: `integrity.check_quota` (per endpoint, rolling 24 h over `upload_batches`: `PDP_INGEST_DAILY_BYTES` 8 GiB / `PDP_INGEST_DAILY_ROWS` 200 M, per-endpoint override `config.ingest_daily_bytes/rows`), 429 on event and entity uploads over budget, one integrity finding and one `ingest_quota` security event per day; gateway `limit_req` per client certificate on `/v1/` (300 r/min, burst 300). Original note: per-endpoint daily byte/row budget in `upload_events`/`upload_alerts` (compare against `upload_batches` of the last 24 h; refuse with 429 and raise an integrity finding), plus `limit_req` keyed on `$ssl_client_s_dn` for `/v1/` at the gateway (generous: the baseline uploader bursts for ~20 s). |
| F12 | **Medium** | Desktop wrapper | `desktop/main.js:82-112`, `desktop/preload.js:5-8` | The same `BrowserWindow` (with the preload exposing `window.pdp.saveConfig`) loads both the local settings page and the remote console; the IPC handler does not check `event.senderFrame.url` or the URL scheme. Any JS in the console origin (a future XSS, a compromised gateway) calls `saveConfig({serverUrl, caFingerprint})`, re-points the app and re-pins the CA persistently - defeating the pin the wrapper exists for. Also `setWindowOpenHandler` passes any URL to `shell.openExternal` (`file:`, `ms-msdt:`...), there is no `will-navigate` guard, and Electron 31.7.6 is end-of-life (`desktop/package.json:24`). | **Fixed (round 2)**: the console window has no preload (sandboxed), the settings page has its own window with the preload, both IPC handlers verify the calling frame is the local settings page, `saveConfig` validates the URL (`https:` only) and the fingerprint format, `shell.openExternal` only for http(s), `will-navigate`/`will-redirect`/`setWindowOpenHandler` confine the console to the configured origin, DevTools removed from the menu. Electron upgrade deferred (needs a network install). Original note: separate window for settings (console window without preload), `senderFrame.url.startsWith("file://")` + `https:` check in the handlers, scheme allow-list in `setWindowOpenHandler`, `will-navigate` limited to `cfg.serverUrl`'s origin, Electron >= current LTS. |
| F13 | **Low** | Injection | `server/pdp_server/distrib.py:26-28`, `install.sh.tmpl:13-18` | Without `PDP_PUBLIC_HOSTNAME` the request `Host` header is rendered verbatim into the installer shell script (`SERVER="https://<host>"`). nginx passes `"`, `;`, `$`; needs a MITM position (the victim's curl sets Host), hence Low. | **Fixed**: `public_host` accepts `^[A-Za-z0-9.-]{1,253}$`, else `localhost`. |
| F14 | **Low** | Agent API robustness | `server/pdp_server/hunt.py:103-104` | Hunt answers were stored as sent (any JSON, 500 rows of any size); `GET /api/hunts/{id}` calls `x.get("none")` on each row, so one compromised endpoint answering `["junk"]` broke the hunt view (500) for every analyst; a non-UUID `hunt_id` was a 500 too. | **Fixed**: `hunt.clean_rows` (objects only, 500 rows, 16 fields, 2000 chars), UUID check. |
| F15 | **Low** | Console auth | `server/pdp_server/api.py:440-487` | Username enumeration by timing: scrypt ran only for existing users (~50 ms difference); no upper bound on the password field (scrypt over a multi-MB password). | **Fixed**: `auth.dummy_hash()` verified for unknown users; `Login.password` <= 1024, `username` <= 254. |
| F16 | **Low** | Agent API | `server/pdp_server/api.py:154-162` | `EnrollReq` (the one unauthenticated agent route) had no field bounds: a 256 MB `csr_pem` reached the X.509 parser and `hostname` the database. | **Fixed**: bounded fields. |
| F17 | **Low** | Deployment | `deploy/bringup.sh:13-27` | `deploy/.env` was created with the default umask and `chmod 600` only after the DB password was written (a window of a few lines on first run). | **Fixed**: `umask 077` for the creation. |
| F18 | **Low** | Tenant isolation (info) | `server/pdp_server/orgs.py:117-118`, `api.py:667,701` | E-mail/username uniqueness is global (`users_email` index), so `/api/signup`, `/api/invites`, `/api/users`, invite acceptance answer 409 when an address exists *in another organisation*: a cross-tenant oracle for which e-mails have accounts. | **Reported**. Fix: make the uniqueness per organisation for local accounts (index on `(org_id, lower(email))`; login by e-mail then needs the organisation or must fall back to username) or answer the same way for both cases on the public routes. |
| F19 | **Low** | Console auth | `server/pdp_server/api.py:565-575`, `auth.py` | Sessions are stateless HMAC cookies (12 h): logout only deletes the cookie, a copied cookie stays valid until expiry or `session_gen` bump ("sign out everywhere"). | **Fixed (round 2)**: every cookie carries a session id (`sid`); `POST /api/logout` records it in `revoked_sessions` until the cookie would have expired and `access.session` refuses revoked ids. Original note: per-session id in the cookie with a server-side deny list on logout, or bump `session_gen` on logout when the user has one session. |
| F20 | **Low** | Console auth | `server/pdp_server/api.py:468-473` | Account lock-out by username: anyone can lock any account for up to 15 min with 5 wrong passwords (gateway: 30/min per IP). Standard trade-off; note that F1's fix extends it to the second factor on purpose. | **Reported** (accepted). Mitigation: lock per (account, source address) or CAPTCHA after N failures. |
| F21 | **Low** | Deployment | `deploy/entrypoint.sh:7` | `--forwarded-allow-ips '*'` with nginx not setting `X-Forwarded-For`: a client-supplied `X-Forwarded-For` becomes `request.client.host`. Only used as a fallback behind `X-Real-IP` (which nginx sets on `/api/`), so no impact today. | **Reported**. Fix: `proxy_set_header X-Forwarded-For $remote_addr;` in `console.conf`, or `--forwarded-allow-ips` = the gateway's network. |
| F22 | **Low** | Deployment | `deploy/backup/backup.sh:35`, `restore.sh:26-42` | Backups are `aes-256-cbc` without a MAC and restored by extracting a tar as root into `/pki`; no key is generated by `bringup.sh` and the `backup` service is not started by it. | **Fixed (round 2)**: `deploy/backup/seal.sh` (encrypt-then-MAC: AES-256-CBC + HMAC-SHA256 sidecar under a derived key); `restore.sh` verifies the MAC before decrypting, decrypts to a file, refuses archives with absolute / `..` / link members (`safe_members`) and extracts with `--no-same-owner` (`-o` in alpine). Key generation by `bringup.sh` still to do. Original note: `age`/`gpg` or an HMAC over the ciphertext, `tar --no-same-owner` on restore, generate `backup.key` in `bringup.sh` (`umask 077`). |
| F23 | **Low** | Deployment | `deploy/docker-compose.yml:187` | Grafana admin password defaults to `change-me` (loopback only, profile `monitoring`). | **Reported**. |
| F24 | **Low** | Public route | `server/pdp_server/distrib.py:58-61` | `/api/public/btf/{release}` walks the whole BTF tree (`os.walk`) per unauthenticated request. | **Reported**. Fix: cache the listing for 60 s. |
| F25 | **Low** | Console (UI) | `console/src/pages/Login.tsx:58-60`, `main.tsx:44` | The login page shows `?error=`/`?sso_error=` text from the URL (content spoofing on the real login page, no XSS: React text node); logout follows `end_session_url` from the operator's IdP discovery without a scheme check. | **Reported**. Fix: map error codes to fixed strings; accept only `https:` for `end_session_url`. |
| F26 | **Info** | Endpoint agent | `install.sh.tmpl:325`, `deploy/systemd/pdp-agent.service:31`, `api.py:808` | The agent container runs `--privileged --pid=host --network=host` (documented, accepted). | Note: `cap_add: [BPF, PERFMON, SYS_ADMIN, SYS_PTRACE, NET_ADMIN]` plus `--pid=host` would cover eBPF, strace and nftables with far less exposure if an image is ever substituted (F2/F3). |

## What was checked and found sound (not re-reported)

- **Tenant isolation, console**: every route takes the organisation and endpoint scope from the database on each request
  (`access.session`), never from the cookie; `require_endpoint`/`scope_sql`/`visible` precede every id use in
  `api.py`, `console.py`, `allowlist.py`, `hunt.py`, `respond.py`, `k8s.py`, `notify.py`, `updates.py`, `orgs.py`;
  incidents (`incidents.find`, `grouped`) and sim campaigns check the alert's/campaign's endpoint against the scope;
  users, invites, channels, cluster tokens, allow-list entries are looked up `WHERE ... AND org_id=%s`;
  `delete_endpoint`/`retire_endpoint` only touch paths derived from a validated UUID. Role checks: mutating routes
  use `admin` or `triager`; settings that weaken detection go through `posture.require_reason`/`weakened` (0.6).
  Platform-event notifications are only *delivered* to the internal organisation even if another org subscribes.
- **Agent channel**: mTLS terminated at nginx with `ssl_verify_client optional` and `if ($ssl_client_verify != SUCCESS) return 403` on `/v1/`;
  the console port strips `X-Client-*` and returns 403 for `/v1/`; the API re-checks CN = endpoint id. Enrolment tokens
  are 24 random bytes, single-use under `FOR UPDATE`, 24 h, organisation-bound; fleet tokens count uses. Uploads:
  gzip bombs bounded (`bounded_decompress`), rows/partitions/timestamps bounded (0.6), idempotent batch ids, alert
  `aid`, sequence numbers. No `pickle`, `yaml.load`, `eval`, `shell=True` anywhere; every `np.load` is `allow_pickle=False`
  or a default-safe `.npy`; all SQL is parameterised (f-strings carry only validated schema names / column lists).
- **Bundles**: Ed25519 signature over the manifest with the key pinned at enrolment, per-file sha256, manifest digest
  announced over the mTLS status call, endpoint id and bundle id in the manifest, `requires` feature check; the agent
  rejects absolute, `..` and non-regular tar members before extracting into a per-bundle directory. The signer verifies
  its own signature before publishing. KMS mode keeps both private keys out of the platform.
- **SSO/OIDC**: PKCE, signed state/nonce cookie, issuer/audience/azp/exp/iat/nonce validated, `alg` restricted to
  RS/PS/ES, JWKS by `kid`, per-organisation sign-in only for *proven* domains (DNS TXT via DoH, or operator), public
  mail domains refused, a proven domain cannot be claimed twice, IdP identities never bound to a local account of
  another organisation, egress only through the allow-listed CONNECT proxy with public-address checks.
- **Console**: `httponly; secure; samesite=strict` cookie, JSON-only bodies (a cross-site `text/plain` form cannot be
  parsed), no CORS, CSP `default-src 'self'` + HSTS + nosniff + `frame-ancestors 'none'`, no raw-HTML sinks in the
  React code, secrets write-only in responses (`has_secret`), e-mail headers built with `EmailMessage` (rejects CR/LF).
- **Notifier**: private/loopback/link-local/multicast targets refused at creation and before every send, HTTPS only,
  no redirects followed, webhooks connect to the checked address, per-channel hourly limits.
- **Deployment**: `backend` network is `internal: true`; API/workers/notifier run as uid 10001; no docker socket
  mounts; registry pulls need a token; `.env`, keys, `kms-secrets`, backups are git-ignored; staging binds to loopback.
- **Endpoint agent**: `/var/lib/pdp` 0700, client key 0600, `update-request.env` 0600 + atomic replace, `agent.json`
  root-only and read-only in the container; `nft` via argv + stdin with numeric addresses; `kill_process` re-checks
  the pid's identity; hunt `LIKE` wildcards escaped.

## Fixes on this branch (each with a test in `tests/unit/test_security_hardening.py`, plus `tests/unit/test_agent.py` for F3)

1. F1 second-factor lock-out + gateway rate limit on `/api/login/mfa` (`access.py`, `mfa.py`, `api.py`, `deploy/nginx/console.conf`).
2. F15 constant-cost unknown user, bounded login body (`auth.dummy_hash`, `api.Login`).
3. F16 bounded `EnrollReq`; F6 suspended organisations refused in `agent_endpoint`; F14 hunt answers sanitised (`hunt.clean_rows`).
4. F7 `api.validate_campaign_spec`.
5. F8 `SyslogSink.addr`/`dest()`; `notify._syslog_send` pins the checked address.
6. F3 `Agent.update_source_problem` (image only from the enrolled server's registry).
7. F10 (container path) `pdp_agent enroll env|-`; `agent-entrypoint.sh` passes the token through the environment.
8. F13 `distrib.public_host` host-name validation; F17 `bringup.sh` umask.

## Changes needed in files this review must not edit

None of the fixes needed `behaviour.py`, `runtime.py`, `trainer.py`, `bundle.py`, `learning.py`, `posture.py`, the
`tools/heldout_*`, `upgrade_0*`, `retrain_detector1`, replay sources, the agent VERSION line or the two documents.
Suggested follow-ups that touch them:

- `posture.py` (F4): treat `PATCH /api/org/agent-updates` with a pinned version below any endpoint's current version
  as a weakening: `org_weakenings()` gets an `agent_update` case, `updates.set_policy` calls `require_reason` and
  `weakened(..., subject="agent update policy")`. Alternatively, in `updates.set_policy`, `if vkey(p) < min(vkey(current versions)) and not s["op"]: 403`.
- `docs/DETECTION_LAYERS.md` / `docs/DEPLOYMENT.md`: document F2/F9 (digest-pinned agent images; file-mode keys are
  development-only) once implemented.

## Round 2 (same day): fixes for the reported findings

Commits on the branch (see the commit list in the report): F4/F5 + F2 server side (`updates.py`, `distrib.py`), F11
(`integrity.check_quota`, `api.py`, `gateway.conf`), F19 (`auth.py`, `access.py`, `api.logout`, `schema.sql`
`revoked_sessions`), F9 (`pki.py`, `auth.py`, `kms_setup.py`, compose `pdp_pki_private`, `restore.sh`), F2 deploy side
(`publish-agent.sh`, compose registry/gateway, `gateway.conf` push listener, `bringup.sh`/`staging.sh` credentials,
`install.sh.tmpl` updater, `agent.py`), F10 installers (`install.sh.tmpl`, `pdp-agent-install`, `api.py`
`install_command_env`), F22 (`deploy/backup/seal.sh`, `backup.sh`, `restore.sh`), F12 (`desktop/main.js`). Tests:
`tests/unit/test_security_hardening.py` (sections 10-16), `test_updater.py` and `test_agent.py` updated for
digest-pinned references.

**Deferred**
- Image signing with cosign (F2): not added - it needs the cosign tooling in the publish path and on every endpoint
  (installer + updater) and a key-distribution story; pull-by-digest plus an authenticated, read-only-by-default
  registry closes the "re-pointed tag" path. Remaining window: a process on the backend network could push during the
  seconds a publish runs (the registry is writable then; the digest recorded is the one the publish computed, so a
  substituted tag would still not be what installers pull).
- Electron upgrade (F12): `desktop/package.json` still pins 31.7.6 - bumping needs `npm install` (network) and a
  rebuild of the installers; do it with the next desktop release.
- `backup.key` generation in `bringup.sh` (F22): left as before (operator-provided, documented in OPERATIONS.md);
  the new MAC uses the same key file.
- Console UI: shows `install_command`; `install_command_env` is available from the API for the Add-endpoint dialog
  (`tests/e2e/tenancy_e2e.py` asserts on the old command, so it was kept).
- Security-event delivery for the new `ingest_quota` kind: `posture.EVENT_KINDS` (out of scope for this branch)
  should gain `"ingest_quota"` so notification channels receive it; it is already in `security_events` and the
  console's `/api/security-events`, and the integrity finding reaches `agent_health` notifications.

**What must change together at deploy time (ordering)**

1. **Before rolling anything**: run `deploy/bringup.sh` (or at least its first block) once so `.env` gains
   `PDP_REGISTRY_PUSH_USER/PASSWORD` and `deploy/nginx/registry-push.htpasswd` exists; staging: `deploy/staging.sh up`
   does the same with `registry-push-staging.htpasswd`. Without the file the gateway bind mount would be created as a
   directory and pushes would fail (pulls and the console are unaffected) - create it first.
2. **Compose + gateway** (`docker compose up -d gateway registry` after the api roll, or whatever `rollout.sh`
   recreates): the registry loses its published port and `edge` network and becomes read-only; the gateway gains the
   loopback push listener and the `pdp_agent` rate-limit zone. New volume `pdp_pki_private` is created empty on the
   first `up`.
3. **API/workers (`rollout.sh api` + workers)**: the new image's `initialize()` runs `pki.migrate_private()` under the
   init lock and moves `ca.key`, `bundle_signing.key`, `session.secret` from `pdp_pki` into `pdp_pki_private`
   (existing sessions stay valid: the secret keeps its value). An OLD replica still serving during the roll would, on
   its next sign-in, recreate a fresh `/pki/session.secret` -> sessions issued by it in that window die at the end of
   the roll. Roll at a quiet time; `rollout.sh`'s one-at-a-time order keeps the window short. The schema gains
   `revoked_sessions` (applied by `init_platform`). Workers must be on the new image before the next bundle is signed
   (they read the key from `private/`); `rollout.sh` restarts them with the api.
4. **Publish the agent again** (`deploy/publish-agent.sh <current version>`): records `PDP_AGENT_DIGEST(S)` and rolls
   the api. Until then `update_for()` offers no updates, `set_policy` refuses pins, and `/install.sh` tells the host
   "published without an image digest" - deliberate: no tag-only references are handed out any more.
5. **Agent image rebuild** (`deploy/publish-agent.sh` of a new agent build): agents on the new code
   (`update_source_problem`) refuse tag-only offers; agents on the old code accept the digest-pinned ones. Hosts keep
   their old host-side updater script (written at install) until `install.sh --upgrade` is re-run: the old updater
   does not enforce the digest / registry checks itself but pulls exactly what the server names, which is now
   digest-pinned. The `agent-entrypoint.sh` change (token via env) ships with the image.
6. **Backups**: archives written after the roll carry a `.hmac` sidecar; `restore.sh` refuses archives without one
   (older archives: restore with the previous `restore.sh` from history, or compute the sidecar with
   `seal.sh`'s `_pdp_hmac` after checking the archive by other means). `restore.sh` now mounts both pki volumes.
7. **Ingest budget**: defaults are generous (8 GiB / 200 M rows per endpoint per day); a benchmark replay endpoint may
   exceed them - set `config.ingest_daily_bytes/rows` on it (DB/tools; the console's `validate_config` does not know
   these keys, `posture.py` being out of scope) or raise `PDP_INGEST_DAILY_*` in `.env`.
