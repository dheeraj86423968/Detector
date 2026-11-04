# Deployment and verification runbook (toward a sellable product)

Everything except Windows and the desktop GUI now runs and is verified on the L40S Linux host (2026-11-03), including
the eBPF collector. This runbook says *where* to deploy each one and *how* to verify it, plus the server-side work a
paying customer's security team will expect. Ordered by value.

## 0. Prerequisite: one staging environment

Stand up a small staging lab you control:
* 1 GPU server (the training/console/server stack). A single NVIDIA GPU with >= 12 GB is comfortable; the
  CPU-feature-offload path (`feat_device`) handles larger registries on smaller cards.
* 2-3 Linux endpoint VMs on **stock distro kernels** (not WSL2): Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky 9, or
  Amazon Linux 2023. Any standard cloud instance works (EC2 `t3.large`, GCP `e2-standard-4`, Azure `D4s`).
* 1 Windows endpoint VM: Windows 10/11 or Server 2019/2022.
This is where the agent is completed and verified before it goes near a customer.

## 1. Linux eBPF agent (highest value — most endpoints)

**Where.** Any Linux host with a stock distro kernel >= 5.8 (ring buffer) with BTF: `ls /sys/kernel/btf/vmlinux`
(CONFIG_DEBUG_INFO_BTF; on by default in Ubuntu >= 20.10, Debian 11+, RHEL/Rocky 8.2+, Amazon Linux 2023, Fedora).
No kernel headers, compiler or tracefs are needed on the endpoint. Verified on Ubuntu 26.04 / kernel 7.0 (this L40S
host). A kernel without BTF can still use the header-based bcc engine (below).

**How it is built.** The kernel program (`agent/bpf/pdp_ebpf.bpf.c`) is compiled once, at image build time, as a
libbpf CO-RE object against a `vmlinux.h` generated from BTF (by default the build machine's
`/sys/kernel/btf/vmlinux`: the header only supplies type names, libbpf relocates every field access against the
endpoint's own BTF at load). `bpftool gen skeleton` embeds it in a small statically linked loader,
`/opt/pdp/bin/pdp-ebpf` (2.2 MB, `agent/bpf/pdp_ebpf.c`), which attaches it and streams the raw ring-buffer records
to the agent over a pipe; the agent decodes them with the same code as before (`EbpfNormaliser`). Build stage:
`deploy/docker/agent.Dockerfile` (clang, libbpf-dev, bpftool from linux-tools); outside Docker, `make -C agent/bpf`.
All hooks are raw tracepoints (`sys_enter`, `sys_exit`, `sched_process_exec/fork/exit`), so nothing reads tracefs.
The loader and the agent are both excluded in-kernel. To check a host without starting the agent,
`docker run --rm --privileged --entrypoint /opt/pdp/bin/pdp-ebpf pdp/agent:<version> --check` prints `ok` once the
program has loaded and attached (~25 ms).

**Engines.** `"source": {"kind": "ebpf", "engine": "core"}` is the default (also `$PDP_EBPF_ENGINE`).
`"engine": "bcc"` is the previous header-compiled engine, kept as a fallback for kernels without BTF and for
differential checks; it is no longer in the agent image (it needs python3-bpfcc, `/lib/modules` + `/usr/src` mounted
and tracefs). Both engines load the same program and produce byte-identical records (see the check below).

**Deploy.** The agent image (`pdp/agent`, Ubuntu 24.04 + CPU torch + `pdp-ebpf`) needs the host pid namespace (pids
and /proc must agree) and BPF privileges. As a service: `deploy/systemd/pdp-agent.service` (instructions inside). By
hand:
```
docker run -d --name pdp-agent --restart=always --privileged --pid=host --network=host \
  -v /var/lib/pdp:/var/lib/pdp -v /etc/pdp/agent.json:/etc/pdp/agent.json:ro \
  -e PDP_ENROLL_TOKEN=<token> -e PDP_CA_SHA256=<fingerprint from the console> pdp/agent:dev run
```
`/etc/pdp/agent.json`: `{"server_url": "https://<server>:8443", "agent_url": "https://<server>:9443", "data_dir":
"/var/lib/pdp", "pki_dir": "/var/lib/pdp/pki", "day_tz": "UTC", "source": {"kind": "ebpf"}}` (ports as published by the
gateway). `--privileged` can be narrowed to `--cap-add BPF --cap-add PERFMON --cap-add SYS_PTRACE --cap-add
DAC_READ_SEARCH` (verified on kernel 7.0 with Docker's default seccomp profile; SYS_PTRACE / DAC_READ_SEARCH let the
agent read other processes' /proc cwd, fd and root links). Images built before the CO-RE change (bcc inside) still
need `-v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /sys/kernel/tracing:/sys/kernel/tracing`.

**Verified on this host (2026-11-03).**
1. Collector parity: `python -m pdp_agent.tools.crosscheck` runs the eight sandbox workloads under strace and eBPF —
   identical edge counts everywhere, identical (op, label, label) edge sets on seven of eight (docs/SANDBOX.md).
2. Full cycle on live eBPF telemetry: enrol -> baseline -> GPU training -> signed bundle -> local detection of the
   attack-shaped scenarios (`agent-sandbox-ebpf`, docs/SANDBOX.md).
3. Whole-host collection (`agent-ebpf-host`): ~70k events / 90 s from every process at ~6 % of one CPU, 460 MB RSS,
   the agent's own activity excluded in-kernel.

**Kernel note.** On kernel 7.0 the per-syscall `syscalls:sys_enter_*` tracepoints fire for only a fraction of the
calls when a BPF program is attached; the collector therefore uses the raw `sys_enter`/`sys_exit` tracepoints and
`sched_process_exec`, which fire for every call (measured: `sys_enter_openat` saw 8 of 80 `openat` calls of a test
workload, `sys_exit_openat` and raw `sys_enter` all 80; `sys_enter_execve` 5 of 50).

**CO-RE vs bcc (verified on this host, 2026-11-04, image `pdp/agent:core-test`).**
1. Headers-free: in a privileged container with no `/lib/modules`, empty `/usr/src`, no tracefs, no clang and no bcc,
   the scripted workload `python -m pdp_agent.tools.syscall_workload` (exec incl. a two-chunk argv, read / write /
   read-write, symlink, fork without exec, openat on a dirfd and on its dup / F_DUPFD_CLOEXEC copies, find, grep -r,
   TCP connect + accept and UDP sendto / recvfrom / sendmsg / recvmsg on 127.0.0.1, ::1, non-local IPv4 / IPv6 / UDP
   connects) produces every expected edge; the agent and the loader are absent from a host-wide capture.
2. Differential: `python -m pdp_agent.tools.crosscheck --compare bcc,core` attaches both programs at once and runs
   each workload once (the `syscalls` workload + the eight sandbox scenarios, 3 repetitions): the raw kernel records
   were identical in every run (1519 per repetition, every field but the timestamp), and the provenance edges
   (op, node types, labels) identical except for one race in the shared user-space decode (below).
3. Cost, both engines simultaneously host-wide for 45 s (x2): startup 1.17 s (bcc compile) vs 0.025 s; collector RSS
   ~190 MB (bcc + LLVM) vs ~30 MB agent + 10 MB loader; CPU per 10k records 0.28 vs 0.29-0.30 CPU-s (CO-RE includes
   the loader, ~1.2 % of a CPU); the image shrinks from 2.16 GB to 1.86 GB.

**Known limitations (both engines, user-space decode).** Paths of fd-relative opens are resolved from
`/proc/<pid>/fd/<dirfd>` first, at decode time: if the process has already closed and reused that fd, the label is
wrong (seen once in three runs: `/dev/null/a.txt`). Relative paths of a short-lived process after `chdir` (not traced)
can stay relative. The ring buffer drops records in bursts when the agent cannot keep up; CO-RE counts them (logged
as "records lost in-kernel"; ~1.5 % at the default 1024 pages under this host's load: raise `source.ring_pages`),
bcc did not count them.

## 2. Windows ETW agent

**Where.** A Windows 10/11 or Server 2019/2022 VM.

**Deploy.** Install Python 3.11 + `pywintrace`; run the agent **elevated** (kernel ETW providers require admin).
Source kind `etw`. The three providers are listed in `sources/windows_etw.py` (`Kernel-Process`, `Kernel-File`,
`Kernel-Network`). Package as a Windows **service** (NSSM or a `sc.exe` service) for persistence.

**Verify.** Same shape as Linux: generate known process/file/network activity (e.g. a scripted drop-execute-beacon),
confirm the events map to EXECUTE/OPEN/READ/WRITE/CONNECT with correct labels, baseline trains, attack alerts.
Validate `_map_raw` against the actual field names your pywintrace build emits (they vary by Windows build) and
adjust the small translation table if needed — the decode layer below it is tested.

## 3. Agent packaging (needed for real endpoints)

* Linux: `deploy/systemd/pdp-agent.service` runs the agent image with `Restart=always`; the open-window checkpoint
  makes restarts safe and enrolment is idempotent (the token is used once).
* Windows: a **service** wrapper (NSSM / `sc.exe`) around `python -m pdp_agent run` with the `etw` source.
* Ship versioned images from a **private registry**; the agent reports its version in every heartbeat (console:
  Endpoints -> Agent column).

## 4. Server productionization (to actually sell)

Done in 0.2:
* **Secrets.** `bringup.sh` generates `PDP_DB_PASSWORD` into `deploy/.env` (mode 600); no default passwords.
* **SIEM / response integration.** `exporter` service (compose profile `export`): every alert once, in order, as
  syslog CEF over UDP/TCP/TLS (`PDP_EXPORT_SYSLOG`) and/or an HTTPS JSON webhook (`PDP_EXPORT_WEBHOOK`,
  `PDP_EXPORT_WEBHOOK_TOKEN`); its cursor lives in the database, so restarts neither lose nor duplicate alerts. It
  is the only backend service on the egress network. Ad-hoc export: `/api/alerts/export?format=csv|ndjson`.
* **Observability.** `/healthz` (DB reachability, queue depth) on the gateway and as the API container healthcheck;
  per-endpoint health (agent version, queue depth, CPU, RSS, last window) from heartbeats in the console; job
  heartbeats, and jobs of a crashed worker are re-queued.
* **Access control.** Users and roles (admin / analyst) managed in the console; password change; retire endpoints.

Done in 0.3:
* **Signing keys in a KMS** (see "Signing keys in a KMS" below): the agent CA key and the bundle-signing key live
  in OpenBao / Vault; the platform can only ask for signatures; every signature carries a key id.
* **Single sign-on** (OIDC, see "Single sign-on" below), sign-in back-off, sessions re-checked on every request
  (deleting, disabling or re-roling a user takes effect at once).

Still to do per customer:
* Replace the *console* server certificate with the customer's CA or ACME for the real hostname (`PDP_HOSTNAMES`;
  the server certificate is re-issued automatically when new names are added). Keep the internal mTLS agent CA.
* Back up both Postgres instances (platform + telemetry) with PITR, or use managed Postgres.
* Per-tenant isolation if multi-tenant.
* Restrict who can reach the console port (firewall / security group / VPN); it should not face the internet.
* Scale: one GPU server serves tens of endpoints (training a sandbox-size baseline takes ~5 s on the L40S; a
  DARPA-size week minutes). Add a second `worker-train` for parallel retrains if needed.

## Signing keys in a KMS

Two private keys protect the fleet: the **agent CA** (agents and the gateway authenticate with certificates it
issues) and the **bundle-signing key** (agents run only models signed by it). With `PDP_KMS=transit` (the default
that `bringup.sh` writes for new installs and on the next bring-up of an existing one) both live in a
Vault-compatible KMS and never on the platform's disks:

| | KMS engine | what the platform can do (policy `pdp-signer`) |
|---|---|---|
| bundle-signing key `pdp-bundle-signing` | transit, ed25519, non-exportable | `transit/sign`, read the public key |
| agent CA | pki | `pki/sign/pdp-agent` (CN forced to the endpoint id), `pki/sign/pdp-server` (gateway TLS) |

The service token cannot export, import, rotate or delete keys, issue certificates without a CSR, or read
policies (`tools/kms_setup.py` verifies each of these refusals). Every request is in the KMS audit log
(bundled: `docker exec pdp-kms-1 cat /openbao/logs/audit.log`). `signature.json` records the signing key
(`kid`, e.g. `transit:pdp-bundle-signing:v1`) and the platform verifies every signature before publishing a bundle.

**Bundled OpenBao** (compose profile `kms`, `quay.io/openbao/openbao:2.1.0`, internal network only):
`bringup.sh` initialises it, imports the existing keys - enrolled agents keep their CA fingerprint and bundle
key, nothing to re-enrol - verifies signing end to end, moves the old key files from the `pdp_pki` volume to
`deploy/kms-secrets/backup/<time>/` and revokes the root token. Then:
* **Take `deploy/kms-secrets/backup/` offline** (it is the only key copy outside the KMS) and delete it from the host.
* `deploy/kms-secrets/unseal/key` is mounted only into the kms container, which unseals itself on start.
  Keep an offline copy: without it the KMS data cannot be opened after a restart. For stricter setups use
  several key shares and manual unseal, or an external KMS.
* The service token (`deploy/kms-secrets/token/token`, mounted read-only into api and worker-train) is a 30-day
  periodic token the platform renews itself. New token: `kms_setup.py --rotate-token` with an admin token.
* Admin access later: `docker exec -it pdp-kms-1 bao operator generate-root` with the unseal key.
* OpenBao 2 does not lock memory: disable swap or encrypt it on the server.

**External Vault / OpenBao** (customer-managed, HSM-backed, ...): set `PDP_KMS=transit`,
`PDP_KMS_ADDR=https://vault.corp:8200`, `PDP_KMS_CACERT` (and `PDP_KMS_NAMESPACE` on Vault Enterprise), leave
`COMPOSE_PROFILES` without `kms`, put an admin token in `deploy/kms-secrets/admin-token` and set
`PDP_KMS_ADMIN_TOKEN_FILE=1` for the bring-up that configures it (engines, keys, roles, policy, service token);
remove the admin token afterwards. Add the KMS host to `PDP_NO_PROXY`.

Rollback: restore the `pdp_pki` volume from a backup taken before the migration and set `PDP_KMS=file`.

## Single sign-on

The console signs users in with OpenID Connect (authorization code + PKCE; Okta, Entra ID, Google Workspace,
Keycloak, Auth0, ADFS, Dex, ...). Register a confidential web client at the IdP with redirect URI
`https://<console host>/api/oidc/callback` and a groups claim in the ID token, then in `deploy/.env`:

```
PDP_OIDC_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
PDP_OIDC_CLIENT_ID=...
PDP_OIDC_CLIENT_SECRET=...
PDP_OIDC_REDIRECT_URL=https://pdp.example.com/api/oidc/callback
PDP_OIDC_ADMIN_GROUPS=<IdP group for PDP admins>
PDP_OIDC_ANALYST_GROUPS=<IdP group for analysts>
PDP_PASSWORD_LOGIN=admin-only           # keep a local break-glass admin; or "disabled"
COMPOSE_PROFILES=kms,sso                # starts the egress proxy
PDP_HTTPS_PROXY=http://egress:3128      # the api reaches the IdP only through it
```

* Roles come from IdP groups at every sign-in (`PDP_OIDC_GROUPS_CLAIM`, default `groups`); a user in no mapped
  group is refused and an existing account of theirs is disabled, ending its open sessions.
  `PDP_OIDC_DEFAULT_ROLE=analyst` admits every authenticated user as analyst instead.
* An IdP identity is bound to its issuer + subject. It never takes over an existing local account of the same
  username (sign-in is refused until an admin renames or deletes that account).
* The ID token is verified against the IdP's JWKS (RS/PS/ES 256-512; `none` and HS* refused), with issuer,
  audience, expiry and nonce checks. State, nonce and the PKCE verifier live in a signed 10-minute cookie, so a
  callback URL cannot be replayed.
* Logout also ends the IdP session (RP-initiated logout) when the IdP supports it.
* The backend network has no internet route. The `egress` service (profile `sso`) is an allow-listed CONNECT proxy
  that relays only to the issuer's host (`PDP_EGRESS_ALLOW` to override); TLS stays end to end.
* Test: `tests/e2e/sso/run_sso_e2e.sh` runs a throwaway Keycloak realm and a real browser through 21 checks
  (roles, refusal, account takeover, replay, role changes, logout).

Password sign-in (local accounts): 5 failures, then 30 s, 60 s, ... up to 15 min back-off per account.

## 5. Desktop app

Build installers in **CI with per-OS runners** (electron-builder: macOS runner for notarization/signing, Windows
runner for Authenticode, Linux for AppImage/deb). Verify it connects to the gateway with the **CA fingerprint pinned**.

## 6. Acceptance validation (the evidence a buyer wants)

On the staging fleet, after a baseline week:
* Run **Atomic Red Team** / MITRE ATT&CK techniques (authorized) on the endpoints.
* Measure **detection rate**, **time-to-detect**, and **false positives per endpoint-day** over a quiet week.
* Tune the per-endpoint **FP budget** (console control) to the customer's tolerance.
* Keep the simulation campaigns as a **regression gate** on every model retrain.

## Recommended order

1. ~~Linux eBPF on a stock kernel, cross-checked against strace~~, ~~libbpf CO-RE packaging~~ (done on the L40S host).
2. Server hardening: ~~secrets~~, ~~SIEM export~~, ~~healthz~~, ~~signing keys in a KMS~~, ~~SSO~~ (done); real console cert, backups.
3. Windows ETW on a Windows VM (§2); Windows service packaging (§3).
4. Desktop installers via CI (§5).
5. Acceptance validation with Atomic Red Team on the staging fleet (§6).

## Moving to a new host (done: L40S box, 2026-11-03)

Host preparation that was needed on a fresh Ubuntu 26.04 VM (kernel 7.0.0-38) with an NVIDIA L40S:
```
apt-get install linux-modules-nvidia-580-open-generic linux-modules-nvidia-580-open-$(uname -r)   # prebuilt module, no DKMS
modprobe nvidia nvidia_uvm; printf 'nvidia\nnvidia_uvm\n' > /etc/modules-load.d/nvidia.conf
# Docker CE + compose + buildx (download.docker.com, suite "resolute") and nvidia-container-toolkit, then
nvidia-ctk runtime configure --runtime=docker && systemctl restart docker
./deploy/bringup.sh
```
The stack is portable (relative paths, named volumes). To carry over data instead of starting fresh, copy the volumes
`pdp_platform_db`, `pdp_telemetry_db`, `pdp_data`, `pdp_pki` **and** keep the old `PDP_DB_PASSWORD`; otherwise
bring-up starts clean and endpoints re-enrol. The benchmark endpoints need the research Postgres (`shared_network`,
`deploy/docker-compose.research.yml`) only to re-run CADETS/THEIA; the product itself does not.

## GPU / PyTorch note

The L40S (and L4) are Ada GPUs (compute capability 8.9). PyTorch 1.13 (the original study's version) does not
support Ada, so the server image builds from torch 2.1.2 / CUDA 12.1 (`deploy/docker/server.Dockerfile`); the agent
image uses CPU torch 2.4. Bundles are numpy/json, independent of the torch version. With 46 GB of GPU memory, node
features can stay on the GPU for GPU-detecting benchmark agents (`"feat_device": "cuda"`); production agents detect
on CPU. For bit-for-bit parity with the original study on an Ampere host, build with
`--build-arg BASE=pidsmaker-pids:latest` (that base cannot use an Ada GPU).
