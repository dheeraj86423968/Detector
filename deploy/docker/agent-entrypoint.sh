#!/bin/bash
set -e
# Fix ownership of the state volume, then run the agent. When PDP_ENROLL_TOKEN is set the agent enrols first
# (idempotent: an already-enrolled agent skips it; the enrol call retries until the server is reachable).
# PDP_CA_SHA256 pins the server CA fingerprint shown in the console when the token was created.
# Optionally drop privileges to the unprivileged pdp user (PDP_RUN_USER=pdp) when the collector does not need them.
[ -d /var/lib/pdp ] && chown -R pdp:pdp /var/lib/pdp 2>/dev/null || true
# The eBPF collector (libbpf CO-RE, raw tracepoints) needs no tracefs, kernel headers or compiler: only BTF
# (/sys/kernel/btf/vmlinux, visible through the container's /sys), BPF privileges and the host pid namespace.
RUN="python -m pdp_agent"
AS=""
[ "$PDP_RUN_USER" = "pdp" ] && AS="gosu pdp"
if [ -n "$PDP_ENROLL_TOKEN" ]; then
  # the token stays in the environment (`enroll env`), not on a command line other local users can read in /proc
  $AS $RUN enroll env ${PDP_CA_SHA256:+--ca-sha256 "$PDP_CA_SHA256"}
fi
exec $AS $RUN "$@"
