#!/bin/bash
set -e
# Fix ownership of the state volume, then run the agent. When PDP_ENROLL_TOKEN is set the agent enrols first
# (idempotent: an already-enrolled agent skips it; the enrol call retries until the server is reachable).
# PDP_CA_SHA256 pins the server CA fingerprint shown in the console when the token was created.
# Optionally drop privileges to the unprivileged pdp user (PDP_RUN_USER=pdp) when the collector does not need them.
[ -d /var/lib/pdp ] && chown -R pdp:pdp /var/lib/pdp 2>/dev/null || true
# bcc reads tracepoint formats from tracefs: mount it when the container was started without the bind mount
if [ -d /sys/kernel/tracing ] && [ ! -e /sys/kernel/tracing/events ]; then
  mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
fi
RUN="python -m pdp_agent"
AS=""
[ "$PDP_RUN_USER" = "pdp" ] && AS="gosu pdp"
if [ -n "$PDP_ENROLL_TOKEN" ]; then
  $AS $RUN enroll "$PDP_ENROLL_TOKEN" ${PDP_CA_SHA256:+--ca-sha256 "$PDP_CA_SHA256"}
fi
exec $AS $RUN "$@"
