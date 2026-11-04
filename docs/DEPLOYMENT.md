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

**Where.** Any Linux host with a stock distro kernel >= 5.8 (ring buffer) and its headers:
`ls /sys/kernel/btf/vmlinux` and `ls /lib/modules/$(uname -r)/build` (install `linux-headers-$(uname -r)`).
Verified on Ubuntu 26.04 / kernel 7.0 (this L40S host); the WSL2 kernel cannot load it (no headers).

**Deploy.** The agent image (`pdp/agent`, Ubuntu 24.04 + bcc + CPU torch) compiles the kernel program at start
against the host's headers, so it needs them mounted, the host pid namespace (pids and /proc must agree) and BPF
privileges. As a service: `deploy/systemd/pdp-agent.service` (instructions inside). By hand:
```
docker run -d --name pdp-agent --restart=always --privileged --pid=host --network=host \
  -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /var/lib/pdp:/var/lib/pdp -v /etc/pdp/agent.json:/etc/pdp/agent.json:ro \
  -e PDP_ENROLL_TOKEN=<token> -e PDP_CA_SHA256=<fingerprint from the console> pdp/agent:dev run
```
`/etc/pdp/agent.json`: `{"server_url": "https://<server>:8443", "agent_url": "https://<server>:9443", "data_dir":
"/var/lib/pdp", "pki_dir": "/var/lib/pdp/pki", "day_tz": "UTC", "source": {"kind": "ebpf"}}` (ports as published by the
gateway). `--privileged` can be narrowed to `--cap-add BPF --cap-add PERFMON --cap-add SYS_ADMIN --cap-add SYS_PTRACE`
plus the tracefs mount on hosts that allow it.

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

**Before GA (recommended).** Compile the kernel program once as a libbpf CO-RE object so endpoints need no kernel
headers or clang (the decode layer, `EbpfNormaliser.decode`, is independent of the loader and unit-tested).

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

**Linux packages (`pdp-agent` .deb / .rpm).** `deploy/packaging/agent/build.sh` builds both with nfpm
(`nfpm.yaml`; uses a local `nfpm` or the `goreleaser/nfpm` image) into `dist/agent/`:
`pdp-agent_<v>-1_amd64.deb`, `pdp-agent-<v>-1.x86_64.rpm`. The package is the service, not the runtime:

| path | content |
|---|---|
| `/usr/lib/systemd/system/pdp-agent.service` | `deploy/systemd/pdp-agent.service` **as it is in the commit being built** (not a copy), so changes to the unit's `docker run` arguments ship with the next build |
| `/usr/sbin/pdp-agent-install` | configure + enrol + start helper (`man pdp-agent-install`) |
| `/usr/share/pdp-agent/` | `agent.json.example`, `agent.env.example`, `defaults` (build-time default image `<REGISTRY>/pdp/agent:<v>`) |

Depends on `docker.io | docker-ce | moby-engine` (rpm: `/usr/bin/docker`), recommends `curl` + `openssl`. Installing
creates `/etc/pdp` (0750) and `/var/lib/pdp` (0700) but does **not** enable the service (it needs the token). On an
endpoint:
```
apt install ./pdp-agent_0.3.0-1_amd64.deb          # or: dnf install ./pdp-agent-0.3.0-1.x86_64.rpm
pdp-agent-install --server https://pdp.example.com --token <token> --ca-sha256 <fingerprint> \
  --pull                                            # or --image-tar pdp-agent-image-0.3.0.tar.gz (air-gapped)
```
`pdp-agent-install` fetches `<server>/dl/ca.pem` and refuses to continue if its sha256 differs from `--ca-sha256`,
writes `/etc/pdp/agent.json` (kept on re-runs unless `--force`) and `/etc/pdp/agent.env` (0600: token, fingerprint,
`PDP_AGENT_IMAGE`, which overrides the unit's `Environment=` default because `EnvironmentFile=` wins), then
`systemctl enable --now pdp-agent`. Without `--agent-url` the agent API is assumed on port 8443 of the server host;
when the gateway publishes non-default ports pass it explicitly. Upgrades `try-restart` a running agent; `apt purge`
removes `/etc/pdp/agent.{json,env}` but keeps `/var/lib/pdp` (identity, spool, bundles). The pre-flight check warns
(only) when kernel headers are missing, since the current bcc-based image compiles at start.

Built and checked on the L40S host (2026-11-04): lintian 2.117 (`--pedantic`) clean apart from two overridden tags
(`initial-upload-closes-no-bugs`, nfpm's `License` field); shellcheck clean; in a throwaway `ubuntu:24.04`
container `apt install` pulled `docker.io`, `systemd-analyze verify` passed on the unit, the installer refused a
wrong fingerprint against the live gateway and accepted the right one, file modes were as above, purge behaved as
described; the `.rpm` installed and erased in `rockylinux:9-minimal` (scriptlets ran, missing `/usr/bin/docker`
reported). Not exercised there: systemd actually starting the unit (no systemd in the container).

CI (`.github/workflows/release.yml`, job `agent-package`) builds both packages, runs `lintian --fail-on
error,warning` and the same install test; job `images` builds `pdp/agent:<v>` and `pdp/server:<v>` (smoke-imports
the runtime), pushes them to `<REGISTRY>/pdp/{agent,server}:<v>` (+ `latest` for release tags) when the `REGISTRY`,
`REGISTRY_USERNAME`, `REGISTRY_PASSWORD` secrets exist, and always attaches `pdp-agent-image-<v>.tar.gz`
(`docker save`) for `--image-tar`.

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

Still to do per customer:
* Move the bundle-signing key out of the `pdp_pki` volume into a secrets manager / KMS; key-id in the manifest.
* Replace the *console* server certificate with the customer's CA or ACME for the real hostname (`PDP_HOSTNAMES`;
  the server certificate is re-issued automatically when new names are added). Keep the internal mTLS agent CA.
* Back up both Postgres instances (platform + telemetry) with PITR, or use managed Postgres.
* SSO/OIDC, and per-tenant isolation if multi-tenant.
* Scale: one GPU server serves tens of endpoints (training a sandbox-size baseline takes ~5 s on the L40S; a
  DARPA-size week minutes). Add a second `worker-train` for parallel retrains if needed.

## 5. Desktop app

Installers are built in **CI with per-OS runners** by `.github/workflows/release.yml` (on a `vX.Y.Z` tag or manual
dispatch; the repository needs a GitHub remote first):

1. `tests` (reusable `tests.yml`, also on every push/PR): `tests/unit/test_*.py` on Python 3.12 with CPU torch, the
   desktop CA-pin self-test, shellcheck of the packaging scripts.
2. `desktop` matrix, electron-builder 24.13.3 / Electron 31.7.6: `macos-latest` -> dmg + zip (x64, arm64), signed with
   the Developer ID cert (`CSC_LINK`, `CSC_KEY_PASSWORD`), hardened runtime, notarized by the `afterSign` hook when
   `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` are set; `windows-latest` -> NSIS installer + zip,
   Authenticode with `WIN_CSC_LINK`, `WIN_CSC_KEY_PASSWORD`; `ubuntu-latest` -> AppImage + deb. Missing secrets mean an
   unsigned build with a warning, not a failure.
3. `agent-package` and `images` (§3).
4. `release`: `SHA256SUMS` over all artifacts (GPG-signed when `GPG_PRIVATE_KEY`/`GPG_PASSPHRASE` exist) and, for
   tags whose jobs all passed, a **draft** GitHub release to review and publish by hand.

Details, artifact names and secret formats: `desktop/README.md`.

**Verified on the L40S host (2026-11-04)**: the Linux job's build in `electronuserland/builder:20` (AppImage 107 MB,
deb 75 MB); the deb installed with apt in `ubuntu:24.04` and, under xvfb against the running gateway
(`https://localhost:8443`), loaded the console with the correct CA pin (hex, colon and SPKI forms; deb and AppImage)
and fell back to the settings page with a wrong pin or a hostname outside the certificate's SAN. Both workflows pass
actionlint 1.7.12 (with shellcheck). **Not verified here**: the macOS and Windows jobs, code signing, notarization and
the GitHub-hosted run itself (no runners, certificates or remote); the Windows job is in the workflow but out of scope
for validation for now. First real run: push a `v0.3.0` tag (or dispatch) and check the job warnings for any signing
step that was skipped.

## 6. Acceptance validation (the evidence a buyer wants)

On the staging fleet, after a baseline week:
* Run **Atomic Red Team** / MITRE ATT&CK techniques (authorized) on the endpoints.
* Measure **detection rate**, **time-to-detect**, and **false positives per endpoint-day** over a quiet week.
* Tune the per-endpoint **FP budget** (console control) to the customer's tolerance.
* Keep the simulation campaigns as a **regression gate** on every model retrain.

## Recommended order

1. ~~Linux eBPF on a stock kernel, cross-checked against strace~~ (done on the L40S host); next: libbpf CO-RE packaging.
2. Server hardening: ~~secrets~~, ~~SIEM export~~, ~~healthz~~ (done); real console cert, backups, signing key in KMS.
3. Windows ETW on a Windows VM (§2); Windows service packaging (§3).
4. Desktop installers via CI (§5): pipeline in place, Linux build verified; first macOS/Windows run and signing
   certificates pending. Agent .deb/.rpm (§3) done.
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
