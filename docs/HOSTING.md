# Hosting PDP for clients (multi-tenant)

One PDP server hosts many client organisations. Clients set themselves up; the provider (operator) only publishes
agent versions and watches usage.

## What a client does (no help from us)
1. Opens `https://<server>/#/signup`, enters organisation name, their name, work email, password (and the sign-up
   code while sign-up is code-only). They become the organisation's admin.
2. Endpoints > Add endpoint > name > copies one command and runs it as root on a Linux server:
   `curl -fsSL https://<server>/install.sh | sudo bash -s -- --token <token>`
   The installer checks the host (x86_64, kernel 5.8+ with BTF for eBPF, memory, disk, reachability of ports 443
   and the agent port), installs docker if missing (apt / dnf / yum), downloads the agent from this server
   (enrolment token = download credential), writes `/etc/pdp`, installs and starts `pdp-agent.service`, waits for
   enrolment and removes the used token from disk. Re-running is safe; `--uninstall [--purge]` removes it.
3. The endpoint learns for 8 days (7 + 1 validation day) and then protects; incidents appear in the console.
4. Team > Invite people: a single-use link (7 days) with a role and endpoint access. No e-mail server is needed.

Isolation: every query is scoped to the caller's organisation (tests/e2e/tenancy_e2e.py, 88 checks, probes every
endpoint-keyed route across organisations). The operator sees organisations and usage, never their data.

## Operator
| Setting (deploy/.env) | Meaning |
|---|---|
| `PDP_SIGNUP` | `off` (default), `code` (needs `PDP_SIGNUP_CODE`), `open` |
| `PDP_SIGNUP_CODE` | the code clients enter while sign-up is code-only |
| `PDP_ORG_MAX_ENDPOINTS` | endpoint limit of new organisations (default 25; change per organisation in the console) |
| `PDP_SIGNUPS_PER_HOUR` | sign-ups per client address per hour (default 5); nginx also limits sign-up and sign-in |
| `PDP_INTERNAL_ORG_NAME` | name of the provider's own organisation (existing data and the operator live there) |
| `PDP_PUBLIC_HOSTNAME` | host name clients use (install commands, registry) |
| `PDP_AGENT_VERSION` | agent version new installs get (set by `deploy/publish-agent.sh`) |

- Publish an agent: `deploy/publish-agent.sh 0.3.2` (pushes `pdp/agent:0.3.2` to the registry on 127.0.0.1:5000 and
  makes it the installer's version). Clients pull through the gateway (`/v2/`, read-only, enrolment token as
  password).
- Console > Platform > Organisations: usage, disable/enable, endpoint limit, delete (offboarding; disable first;
  deletes users, endpoints, telemetry, alerts, models, checks, allow list, invites).
- Single sign-on (OIDC) is for the provider's own staff; SSO users join the internal organisation.

## Not yet (before roll-out)
- Agent upgrades after install (today: re-run the installer with a new token); a per-endpoint pull credential.
- E-mail (verification, invite mails, password reset); per-organisation SSO; data retention settings per client.
- Windows agent; the agent image is 1.9 GB (CPU PyTorch) and should be slimmed.

## Notifications
Each organisation's admins add channels under Console → Notifications; the `notifier` service (the only backend
service with internet access) delivers them within ~10 seconds:
- **What:** new incidents at or above the channel's severity (and again when one escalates), agents that stop
  reporting for `PDP_NOTIFY_OFFLINE_MIN` minutes (default 10) and when they are back, collector/spool event loss;
  webhook and syslog channels can also take every single alert (SIEM feed, in order, once).
- **Where:** e-mail (needs `PDP_SMTP_URL=smtp://user:pass@relay:587` (STARTTLS) or `smtps://...:465`, and
  `PDP_SMTP_FROM`), Slack and Teams incoming webhooks, any HTTPS webhook (JSON; with a secret, `X-PDP-Signature:
  sha256=HMAC(secret, X-PDP-Timestamp + "." + body)`), syslog CEF over tls/tcp/udp.
- **No flooding:** at most `PDP_NOTIFY_MAX_PER_HOUR` (20) messages per channel and hour; the rest are listed in one
  summary per hour. Each message is sent once per channel (notify_log).
- **Safety (hosted):** destinations are resolved before every send and refused if they point to a private, loopback,
  link-local or otherwise internal address, so a customer cannot make our server call into its own network; the API
  refuses literal internal addresses up front. `PDP_NOTIFY_ALLOW_PRIVATE=1` lifts this for on-premises installs.
- Test: `tests/e2e/notify_e2e.sh` (27 checks: isolation between organisations, the internal-address guard of the
  deployed notifier, signatures, escalation, hourly limit and digest, SIEM feed, agent offline/back).

## Updating without downtime
The API runs as two replicas (`PDP_API_REPLICAS`, default 2) behind nginx, which spreads requests over them and
retries a refused connection on the other replica. Update with
`docker compose build api && deploy/rollout.sh` - new replicas start next to the old ones, take traffic once healthy,
then the old ones stop gracefully. Never `docker compose up` the api service directly (that replaces all replicas at
once). Schema DDL runs only when schema.sql changes (hash in kv), with a 15 s lock timeout: if it cannot get its locks
the new replica fails its health check and the rollout keeps the old replicas. Measured: 0 failed requests out of
13,158 during two rollouts under 4 concurrent clients. nginx config changes: `docker exec pdp-gateway-1 nginx -s reload`.
