#!/usr/bin/env bash
# SSO end-to-end test against a running stack: starts a throwaway Keycloak, points the api at it, drives a real
# browser through the sign-in flows (sso_e2e.py), then restores the api's normal configuration and removes Keycloak.
#   ./tests/e2e/sso/run_sso_e2e.sh [gpu]
set -uo pipefail
cd "$(dirname "$0")/../../.."
DC="docker compose -f deploy/docker-compose.yml"
[ "${1:-}" = gpu ] && DC="$DC -f deploy/docker-compose.gpu.yml"
DC="$DC --env-file deploy/.env"
T="$DC -f tests/e2e/sso/docker-compose.sso-test.yml"
cleanup() {
  echo "== restoring the api configuration and removing Keycloak =="
  $DC up -d --no-deps api >/dev/null
  docker rm -f pdp-keycloak-1 >/dev/null 2>&1 || true
  docker exec pdp-platform-db-1 psql -U pdp -d platform -qAt -c \
    "DELETE FROM users WHERE auth='oidc' AND oidc_issuer='http://keycloak:8080/realms/pdp'" >/dev/null
}
trap cleanup EXIT
$T up -d --no-deps keycloak api
echo "== waiting for Keycloak and the api =="
for i in $(seq 1 90); do
  docker run --rm --network pdp_edge --entrypoint python pdp/server:dev -c "import urllib.request; urllib.request.urlopen('http://keycloak:8080/realms/pdp/.well-known/openid-configuration', timeout=3)" >/dev/null 2>&1 \
    && docker exec pdp-api-1 python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=3)" 2>/dev/null && break
  sleep 2
done
docker run --rm --network pdp_edge -v "$PWD/tests/e2e/sso:/t:ro" -e PDP_CONSOLE=https://gateway \
  mcr.microsoft.com/playwright/python:v1.48.0-noble sh -c "pip -q install playwright==1.48.0 >/dev/null 2>&1; python -u /t/sso_e2e.py"
