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
host). A kernel without BTF can still use the header-based bcc engine (below), or the CO-RE engine with a BTF file
(next paragraph).

**Kernels without BTF (agent 0.3.18).** The loader takes `--btf FILE` (libbpf `btf_custom_path`). When
`/sys/kernel/btf/vmlinux` is missing the agent uses `$PDP_BTF`, else `/var/lib/pdp/btf/<uname -r>.btf`, else downloads
one from the server (`GET /v1/endpoints/{id}/btf/<release>`). The operator stocks the server's `deploy/btf/` directory
(mounted read-only into the API as `/btf`): plain `<release>.btf` files, or the parts of BTFHub
(https://github.com/aquasecurity/btfhub-archive) that clients need, in its own layout
`<distro>/<version>/<arch>/<release>.btf.tar.xz` (the agent unpacks those; files under the other architecture's
directory are never served). The installer asks `GET /api/public/btf/<release>?arch=` before installing on such a
kernel and stops with a clear message (use `--source auditd`) when the server has none. If the collector cannot
start at all, the agent no longer restart-loops: it keeps reporting (heartbeat `collector_error`, shown with the
endpoint), takes commands and updates, and retries every 10 minutes. Verified: the loader with the host's BTF given
as a file (and the kernel's own path treated as missing) loaded in 26 ms and streamed records; unit test
`tests/unit/test_nobtf.py`; the BTF route in `tests/e2e/k8s_e2e.py`.

**ARM64.** The kernel program has the arm64 syscall table and register access (`__TARGET_ARCH_arm64`); the agent
decodes arm64 records (`ebpf.py` syscall map). The agent image builds natively on an arm64 machine (vmlinux.h from its
BTF; the Dockerfile picks the aarch64 CPU wheel of torch 2.4.1). `deploy/publish-agent.sh VERSION --arm64 IMAGE`
publishes one multi-architecture tag (OCI index; checked against the local registry), so x86_64 and arm64 hosts
pull their own build; the installer accepts aarch64 and refuses with a clear message when the server only has an
amd64 image. CI job `agent-arm64` (GitHub `ubuntu-24.04-arm`) builds the image, runs the agent-side unit tests and
loads the collector on the arm64 kernel. Not yet verified on arm64 hardware: this host has no arm64 emulation, so
only the arm64 BPF object compile (cross, in the build stage) and the aarch64 torch wheel's availability were
checked here.

**How it is built.** The kernel program (`agent/bpf/pdp_ebpf.bpf.c`) is compiled once, at image build time, as a
libbpf CO-RE object against a `vmlinux.h` generated from BTF (by default the build machine's
`/sys/kernel/btf/vmlinux`: the header only supplies type names, libbpf relocates every field access against the
endpoint's own BTF at load). `bpftool gen skeleton` embeds it in a small statically linked loader,
`/opt/pdp/bin/pdp-ebpf` (2.2 MB, `agent/bpf/pdp_ebpf.c`), which attaches it and streams the raw ring-buffer records
to the agent over a pipe; the agent decodes them with the same code as before (`EbpfNormaliser`). Build stage:
`deploy/docker/agent.Dockerfile` (clang, libbpf-dev, bpftool from linux-tools); outside Docker, `make -C agent/bpf`.
All hooks are raw tracepoints (`sys_enter`, `sys_exit`, `sched_process_exec/fork/exit`, and the optional
`io_uring_submit_req`), so nothing reads tracefs.
The loader and the agent are both excluded in-kernel. To check a host without starting the agent,
`docker run --rm --privileged --entrypoint /opt/pdp/bin/pdp-ebpf pdp/agent:<version> --check` prints `ok` once the
program has loaded and attached (~25 ms).

**Data on connected sockets (next agent release; built 2026-11-07, not yet released or deployed).** Before this,
a payload downloaded over a connected TCP socket (curl / wget / python reading with read() / recv()) produced only
the CONNECT edge, and exfiltration with write() / send() produced none. The collector now reports successful
transfers on INET/INET6 sockets (TCP, UDP) at syscall exit (ret > 0), as SOCKIO records mapped to the existing edge
types: read / readv / preadv2 -> `READ` netflow -> process; write / writev / pwritev2 / sendfile -> `WRITE` process ->
netflow; splice -> READ or WRITE for whichever end is the socket; recvfrom / recvmsg / recvmmsg that return no
address -> `RECVFROM` / `RECVMSG`; sendto / sendmsg / sendmmsg without a destination -> `SENDTO` / `SENDMSG`. The
netflow node is the one connect() creates (`netflow <remote ip> <remote port>`), so a download is
`connect -> READ -> WRITE file -> EXECUTE` in one graph (layer 1-2 treat READ / WRITE on a netflow as receive / send,
`socket_io`). Unix, netlink and packet sockets, pipes, files and unconnected UDP without an address produce nothing.
The kernel decides socket-ness and the peer from the fd itself (`task->files->fdt->fd[fd]` -> S_IFSOCK inode ->
`socket->sk->__sk_common` daddr / dport / v6_daddr), so inherited, dup'ed and passed fds work without user-space fd
tracking. Volume: at most one record per (process image, edge, peer) per 2 s (in-kernel LRU map, 64k entries; loader
`--sockio-interval-ms`, agent source config `"sockio_interval_ms"`, 0 = off); the first transfer is always reported at
once, and each record carries the bytes / calls summed since the previous one of its key. A recvfrom / recvmsg whose
kernel-returned address length is 0 (TCP) now uses the socket's peer instead of whatever was in the caller's buffer.
io_uring: IORING_OP_READ(V) / WRITE(V) / *_FIXED / READ_MULTISHOT / SEND(_ZC) / RECV(_ZC) / SENDMSG(_ZC) / RECVMSG on a
socket fd give the same edges, from the `io_uring:io_uring_submit_req` tracepoint (5.19+; the loader skips it with a
note where absent), reported at submission (ret = 0, the result is not known yet); SQPOLL rings are covered (the
poller is a thread of the owning process). Not covered: registered ("fixed") files, and IORING_OP_CONNECT / ACCEPT /
OPENAT, which bypass connect / accept / open (no CONNECT / OPEN edge for those), and 32-bit compat syscalls (as for
all record kinds). The strace and auditd collectors do not trace socket data (`crosscheck` leaves SOCKIO out of
strace comparisons).
Verified on this host (kernel 7.0, 2026-11-07, benign loopback traffic and one HTTPS GET of example.com): curl, wget
and python urllib downloads give `netflow 127.0.0.1 <port> -RECVFROM/READ-> curl|wget|python` plus the SENDTO / WRITE
of the request, `curl https://example.com` gives `netflow 172.66.147.243 443 -RECVFROM-> curl` and the DNS
`SENDMSG` (sendmmsg) / `RECVFROM` to 127.0.0.53:53; a scripted workload produced every variant above (incl. a dup'ed
fd, a forked child writing on an inherited socket, IPv6, connected and unconnected UDP mmsg) and io_uring SEND /
WRITE / RECV / READ (plain and SQPOLL); `cat` / `dd` of files produced no socket records. Both engines attached at once
(`crosscheck --compare bcc,core`, 9 scenarios): the raw records were identical (2259 per run); strace vs CO-RE edge
counts unchanged with SOCKIO excluded. Cost (median of 5 runs, 2M calls each, against the previous loader):
a successful read / write on a non-socket +51 ns (199 -> 250 ns; the in-kernel rejection is 7 probe reads), a 64-byte
write on a TCP socket +215 ns (3.71 -> 3.93 us, ~6 %), 64 MB loopback downloads unchanged; `pdp_sys_exit` grows
from 3.3 to 9.7 KB of instructions. Volume: 2M socket writes + 5 downloads -> ~130 records; the worst case, 10,000
short connections (every accepted socket a new peer), 10.0k -> 25.5k records, none lost even with a 256 KB ring;
whole host for 30 s under its normal load ~290 socket records (~10/s, 1-3 % of all records). bcc engine: compiles on
7.0 only with the header settings in sources/ebpf.py (bcc 0.35's bundled uapi bpf.h predates 7.0).

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

## 1b. Kubernetes (DaemonSet)
Endpoints > Add endpoint > Kubernetes cluster: name, how many nodes may enrol, how long new nodes may join (1-365
days). The console hands out one manifest (`kubectl apply -f`): namespace `pdp-system` (pod security `privileged`),
the enrolment token in a Secret, a registry pull Secret when the server publishes the agent, and a DaemonSet that runs
one agent per node, control plane included (tolerates every taint), privileged, host pid and network namespaces,
`system-node-critical`, state in the node's `/var/lib/pdp`, node name as the endpoint name (`PDP_HOSTNAME` from
`spec.nodeName`). The token is a fleet token (`enroll_tokens.max_uses`): every node enrols with it until `max_uses`
or the expiry; it reserves no endpoint slots, the organisation's endpoint limit is checked at each enrolment.
Endpoints > Kubernetes clusters lists them (enrolments used, endpoints) with "Manifest" (a fresh copy with the
currently published agent version: apply it again to update the agents; there is no host updater in a cluster) and
"Close to new nodes" (enrolled nodes keep working). Network isolation on a cluster node also cuts the node off from
the cluster (kubelet loses the API server). Verified on staging (`tests/e2e/k8s_e2e.py`, 17 checks: node cap, node
names, single-use tokens unchanged, closing, organisation isolation, the manifest parses); not yet applied to a live
cluster (no cluster tooling on this host).

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
* **SIEM / response integration.** The `notifier` service (always on since server 0.6; it replaced the `exporter`)
  delivers each organisation's notification channels: e-mail, Slack, Teams, signed webhooks and syslog CEF, and
  per channel optionally every alert once, in order (SIEM feed; cursor in the database, so restarts neither lose nor
  duplicate alerts). The old server-wide `PDP_EXPORT_SYSLOG` / `PDP_EXPORT_WEBHOOK` settings still work: they become
  feed channels of the internal organisation. It is the only backend service on the egress network. Ad-hoc export:
  `/api/alerts/export?format=csv|ndjson`. See docs/HOSTING.md "Notifications".
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
* Console certificate (see "Console HTTPS" below): a publicly trusted one for the console's hostname, or distribute
  the PDP CA. Original note: replace the *console* server certificate with the customer's CA or ACME for the real hostname (`PDP_HOSTNAMES`;
  the server certificate is re-issued automatically when new names are added). Keep the internal mTLS agent CA.
* Back up both Postgres instances (platform + telemetry) with PITR, or use managed Postgres.
* Per-tenant isolation if multi-tenant.
* Restrict who can reach the console port (firewall / security group / VPN); it should not face the internet.
* Scale: one GPU server serves tens of endpoints (training a sandbox-size baseline takes ~5 s on the L40S; a
  DARPA-size week 1-108 min). `worker-train` runs several trainings at once (0.11, `PDP_TRAIN_SLOTS`, default `auto`:
  one per 10 GB of GPU memory, at most half the CPU cores and one per 12 GB of host memory, at most 4; 4 on the L40S
  host). A slot beyond the first only starts a job while `PDP_TRAIN_GPU_FREE_GB` (8) of GPU memory and
  `PDP_TRAIN_RAM_FREE_GB` (12) of host memory are free and no job started in the last `PDP_TRAIN_SETTLE_S` (120) s;
  one job per endpoint at a time. Beyond that, add GPUs or a second `worker-train` host.

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

## Hardening of 2026-11-08 (security review: docs/SECURITY_REVIEW_2026-11-08.md)

- **Agent images are pinned by digest.** `deploy/publish-agent.sh VERSION` pushes through the gateway's loopback
  listener (`127.0.0.1:${PDP_REGISTRY_PUSH_PORT:-5000}`, HTTP basic auth with `PDP_REGISTRY_PUSH_USER/PASSWORD` from
  `.env`, generated by `bringup.sh` together with `nginx/registry-push.htpasswd`, root:101 mode 640), records the
  manifest digest (`PDP_AGENT_DIGEST`, `PDP_AGENT_DIGESTS`) and rolls the API. Installers, the updater and the agent
  take only `<host>/pdp/agent:<version>@sha256:<digest>` from the enrolled server's registry. The registry has no
  published port and is read-only except during a publish (a push to it answers 405). Until a version is
  re-published with a digest, no update is offered and `/install.sh` asks for a re-publish.
- **Private keys out of the gateway's volume.** File-mode CA key, bundle-signing key and the console session secret
  live in `/pki/private` (volume `pdp_pki_private`: api, workers, backup only); the first start of the new API moves
  them there (`pki.migrate_private`). KMS mode keeps the CA and signing keys in the KMS as before.
- **Agent update policy:** pinning a version below the fleet's running versions is operator-only, needs a reason and
  raises `detection_weakened`; a version is held only when at least 2 endpoints and 10% of those that tried it
  report failure.
- **Ingest quota per endpoint:** `PDP_INGEST_DAILY_BYTES` (8 GiB) / `PDP_INGEST_DAILY_ROWS` (200 M) over a rolling day,
  per-endpoint override `config.ingest_daily_bytes/rows`; over budget: 429, an integrity finding and an
  `ingest_quota` security event (delivered to channels that receive incidents). The gateway also limits each agent
  certificate to 300 requests a minute.
- **Console sign-in:** wrong second-factor codes count towards the same lock-out as wrong passwords and are rate
  limited at the gateway; logout revokes the session server-side.
- **Enrolment token** no longer appears on command lines (`PDP_ENROLL_TOKEN`, `--token-env`, `--token-file`,
  `--token-stdin`). **Backups** are encrypt-then-MAC (`deploy/backup/seal.sh`); `restore.sh` verifies before it
  decrypts and refuses unsafe archive members.

Deploy order: `bringup.sh` (credentials + htpasswd) -> `docker compose up -d registry gateway` -> `rollout.sh api`
and the workers -> `publish-agent.sh <current version>` (records the digest) -> new agent image.

## Allow list

Console -> Allow list (or "Allow..." on an incident's alert / graph node): programs, network addresses (IP or CIDR) and
specific detections, for all endpoints or selected ones. Agents get the merged list with their configuration and stop
raising those detections without a new model; the server marks alerts the list covers (kept for the record, not part
of incidents). Adding an entry can resolve the matching open alerts at once. API: docs/CONSOLE_API.md.

## Collector capacity (agent 0.3.2)

The loader drains the kernel ring buffer (`source.ring_pages`, default 4096 pages = 16 MB) at full speed into a
user-space spool (`--spool-mb`, default 512 MB, allocated only while the agent catches up), so bursts such as a build
opening 100k+ files are not dropped: on the L40S host 0.3.1 lost ~5 % of events in such bursts, 0.3.2 lost none in a
200k-opens burst test. Dropped events, if any, are reported in the heartbeat and on the endpoint page.

Agent 0.3.19: losses still happened on busy hosts (a Kali desktop right after install: ~80k in minutes; this host
during builds) because the loader did not get the CPU before the ring filled. Measured with the loader confined to
two saturated CPUs and a 200k-open + 1,500-exec burst: 0.3.18 lost 4,129 records; with the loader at nice -10 none.
0.3.19 (1) runs the loader at nice -10 (`--nice`), (2) writes compact records to the ring (64-byte header + the
string's bytes, padded back by the loader; 4-8x more records per MB), each CPU nesting level with its own scratch
buffer (syscall tracepoint programs are preemptible on 7.0 kernels: 37 interrupted runs in that test), and
(3) reports the kernel's losses (`collector_lost`) and drops because the agent fell behind (`collector_behind`)
separately, also over the last hour (`*_1h`); the console warns only about the last hour. Same burst test with
0.3.19: nothing lost, at nice 0 or -10; a live capture decodes identically to 0.3.18.

## Console HTTPS

The console is served only over HTTPS (port 80 redirects; HSTS, CSP, nosniff). Two ways to a browser-trusted lock:

1. **Public certificate (recommended)**: set `PDP_PUBLIC_HOSTNAME` (a DNS name for this host; for a bare IP
   `<a-b-c-d>.sslip.io` works) in `deploy/.env`, make sure TCP 80 is reachable, then `./deploy/acme.sh issue`
   (Let's Encrypt, HTTP-01 via the gateway). Install `deploy/systemd/pdp-acme-renew.{service,timer}` for renewal.
   The public hostname gets that certificate through SNI; browsers opening the console by IP are redirected to it.
   Agents, `localhost` and the internal names keep the internal CA's certificate, which agents and the desktop app pin.
   Behind a corporate CA instead: put the certificate in `deploy/nginx/public/console-public.conf` the same way.
2. **Trust the PDP CA**: list every name/IP users type in `PDP_HOSTNAMES` (the server certificate is re-issued by the
   KMS CA on the next api start) and install `https://<host>/dl/ca.pem` as a trusted root on analyst machines
   (compare its SHA-256 with the fingerprint `bringup.sh` prints).

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
* The backend network has no internet route. The `egress` service (profile `sso`) is an allow-listed CONNECT proxy;
  TLS stays end to end. It allows the issuer's host (`PDP_EGRESS_ALLOW` to override), the Google and Microsoft
  sign-in hosts, the DNS-over-HTTPS resolver (`PDP_DOH_URL`, default Cloudflare) and - re-read from the database
  every minute - each organisation's own OIDC provider (issuer, token and key hosts), those only on public
  addresses and connected to the address that was checked.
* Per-organisation SSO (hosted service) needs the same two settings (`COMPOSE_PROFILES=...,sso`,
  `PDP_HTTPS_PROXY=http://egress:3128`). An organisation's domain signs in only after it is proven: a DNS TXT
  record the console shows (Security > Single sign-on > Check DNS), or the operator's confirmation (Organisations
  page menu) after checking ownership another way.
* Sessions end when the password changes (by the user, an admin or `tools/reset_password`) and on "Sign out
  everywhere else" (Account page).
* Test: `tests/e2e/sso/run_sso_e2e.sh` runs a throwaway Keycloak realm and a real browser through 21 checks
  (roles, refusal, account takeover, replay, role changes, logout).

Password sign-in (local accounts): 5 failures, then 30 s, 60 s, ... up to 15 min back-off per account.

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

1. ~~Linux eBPF on a stock kernel, cross-checked against strace~~, ~~libbpf CO-RE packaging~~ (done on the L40S host).
2. Server hardening: ~~secrets~~, ~~SIEM export~~, ~~healthz~~, ~~signing keys in a KMS~~, ~~SSO~~ (done); real console cert, backups.
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
