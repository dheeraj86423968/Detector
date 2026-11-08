#!/usr/bin/env bash
# Fresh bring-up of the PDP server stack on a Linux host.
# Prereqs: Docker Engine + compose plugin; for GPU training also the NVIDIA driver and NVIDIA Container Toolkit.
# Run from anywhere:
#   ./deploy/bringup.sh            # build images + console, start the stack with GPU training
#   ./deploy/bringup.sh cpu        # without the GPU overlay
# Idempotent: re-running rebuilds changed images and restarts changed services; data volumes are kept.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-gpu}"
ENVFILE=deploy/.env
(umask 077; touch "$ENVFILE")     # never world-readable, not even between its creation and the chmod below

# ---- secrets: generated once, kept in deploy/.env (mode 600). Postgres reads them only when its volume is created.
if ! grep -q '^PDP_DB_PASSWORD=' "$ENVFILE"; then
  echo "PDP_DB_PASSWORD=$(openssl rand -hex 24)" >> "$ENVFILE"
  echo "generated PDP_DB_PASSWORD in $ENVFILE"
fi
# ---- signing keys in a KMS (bundled OpenBao) unless configured otherwise; existing installs migrate on their next
# bring-up: the CA and bundle-signing keys are imported, so enrolled agents are unaffected.
if ! grep -q '^PDP_KMS=' "$ENVFILE"; then
  echo "PDP_KMS=transit" >> "$ENVFILE"
  grep -q '^PDP_KMS_ADDR=' "$ENVFILE" || echo "COMPOSE_PROFILES=kms" >> "$ENVFILE"
  echo "enabled the bundled KMS in $ENVFILE"
fi
# ---- registry push credentials (deploy/publish-agent.sh; the gateway checks them on its loopback push listener)
if ! grep -q '^PDP_REGISTRY_PUSH_PASSWORD=' "$ENVFILE"; then
  echo "PDP_REGISTRY_PUSH_USER=publisher" >> "$ENVFILE"
  echo "PDP_REGISTRY_PUSH_PASSWORD=$(openssl rand -hex 24)" >> "$ENVFILE"
  echo "generated registry push credentials in $ENVFILE"
fi
chmod 600 "$ENVFILE"
set -a; . "$ENVFILE"; set +a
HTPASSWD=${PDP_REGISTRY_HTPASSWD:-deploy/nginx/registry-push.htpasswd}
(umask 077; printf '%s:%s\n' "$PDP_REGISTRY_PUSH_USER" "$(openssl passwd -apr1 "$PDP_REGISTRY_PUSH_PASSWORD")" > "$HTPASSWD")
# nginx's workers (uid/gid 101 in nginx:alpine) must read it; nobody else on the host may
chgrp 101 "$HTPASSWD" && chmod 640 "$HTPASSWD"

BASE="-f deploy/docker-compose.yml"
if [ "$MODE" = gpu ]; then
  echo "== checking GPU runtime =="
  if ! nvidia-smi -L; then echo "ERROR: NVIDIA driver not loaded (nvidia-smi failed). Install it or run: $0 cpu"; exit 1; fi
  if ! docker info 2>/dev/null | grep -qi 'nvidia'; then
    echo "ERROR: Docker has no nvidia runtime. Install nvidia-container-toolkit, then: nvidia-ctk runtime configure --runtime=docker && systemctl restart docker"; exit 1
  fi
  BASE="$BASE -f deploy/docker-compose.gpu.yml"
fi
DC="docker compose $BASE --env-file $ENVFILE"

echo "== building images (server, agent) and the console in parallel =="
$DC build api &                                                          # server / workers / benchmark agents
docker build -q -f deploy/docker/agent.Dockerfile -t "pdp/agent:${PDP_VERSION:-dev}" . &   # slim endpoint agent (bcc + strace)
docker run --rm -v "$PWD/console":/app -w /app node:20-alpine sh -c "npm install --no-audit --no-fund --loglevel=error && npm run build" &
wait

if [ "${PDP_KMS:-file}" = transit ]; then
  echo "== KMS: CA and bundle-signing keys =="
  SECRETS="${PDP_KMS_SECRETS:-$PWD/deploy/kms-secrets}"
  mkdir -p "$SECRETS/unseal" "$SECRETS/token" && chmod 711 "$SECRETS" && chmod 700 "$SECRETS/unseal"
  case ",${COMPOSE_PROFILES:-}," in *,kms,*) $DC up -d kms ;; esac
  $DC run --rm --no-deps -T -v "$SECRETS:/kms-secrets" --entrypoint python api -m pdp_server.tools.kms_setup \
      --secrets /kms-secrets --remove-local-keys ${PDP_KMS_ADMIN_TOKEN_FILE:+--admin-token-file /kms-secrets/admin-token}
fi

echo "== starting the stack =="
$DC up -d platform-db telemetry-db api worker-ingest worker-train gateway

echo "== waiting for the API =="
for i in $(seq 1 60); do
  if docker exec pdp-api-1 python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=3)" 2>/dev/null; then break; fi
  sleep 2
done
docker exec pdp-api-1 python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/healthz', timeout=3).read().decode())"
CA_FP=$(docker exec pdp-api-1 python -c "import sys; sys.path.insert(0,'/opt/pdp/server'); from pdp_server import pki; print(pki.ca_sha256())")
echo
echo "Console:     https://<host>:${PDP_CONSOLE_PORT:-443}"
echo "Admin pw:    $(docker exec pdp-api-1 cat /data/initial-admin-password.txt 2>/dev/null || echo '(already initialised; change it under Account)')"
echo "Agent API:   port ${PDP_AGENT_PORT:-8443} (mutual TLS)"
echo "CA sha256:   $CA_FP   (agents: --ca-sha256 / PDP_CA_SHA256; desktop app pin)"
echo
echo "Next: Console -> Endpoints -> Add endpoint, then on the host run the agent image with the token, e.g."
echo "  docker run -d --name pdp-agent --privileged --pid=host \\"
echo "    -v pdp_agent:/var/lib/pdp -v /etc/pdp/agent.json:/etc/pdp/agent.json:ro \\"
echo "    -e PDP_ENROLL_TOKEN=<token> -e PDP_CA_SHA256=$CA_FP pdp/agent:${PDP_VERSION:-dev} run"
echo "(agent.json: server_url / agent_url of this gateway, source {\"kind\": \"ebpf\"}; see docs/DEPLOYMENT.md)"
