#!/bin/bash
# Restore a backup archive (deploy/backup/backup.sh) into a stack.
#
#   deploy/restore.sh backups/pdp-<ts>.tar.gz.enc                 into the STAGING stack (default; DR rehearsal)
#   deploy/restore.sh backups/pdp-<ts>.tar.gz.enc --production    into the production stack (replaces its data!)
#   options: --key FILE (default deploy/backup.key)
#
# Restores the platform database, CA / key files, the bundled KMS (storage, unseal key, token) when the archive has
# it, and the current models; with a full archive also telemetry and training windows. The target's api, workers,
# notifier and gateway are stopped meanwhile; the databases keep their own passwords.
set -euo pipefail
cd "$(dirname "$0")"
ARCH=${1:?usage: restore.sh ARCHIVE [--production] [--key FILE]}; shift
TARGET=staging; KEY=backup.key
while [ $# -gt 0 ]; do case "$1" in --production) TARGET=production ;; --key) KEY=$2; shift ;; *) echo "unknown option $1" >&2; exit 2 ;; esac; shift; done
if [ "$TARGET" = production ]; then
  PROJ=pdp; ENVF=.env; SECRETS=./kms-secrets; FILES="-f docker-compose.yml"; [ -f docker-compose.gpu.yml ] && FILES="$FILES -f docker-compose.gpu.yml"
  read -r -p "Replace ALL production data with $ARCH? Type 'restore production': " ans; [ "$ans" = "restore production" ] || exit 1
else
  [ -f staging.env ] || ./staging.sh up >/dev/null
  PROJ=pdp-staging; ENVF=staging.env; SECRETS=./kms-secrets-staging; FILES="-f docker-compose.yml"
fi
DC="docker compose -p $PROJ --env-file $ENVF $FILES"
. ./backup/seal.sh
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
echo "== verifying and decrypting $ARCH"
# authenticity first (HMAC over the ciphertext, sidecar .hmac), then decrypt to a file, then check every member's path
# before anything is extracted: a tampered or crafted archive must not reach tar as root
verify "$KEY" "$ARCH" || { echo "the archive's HMAC does not verify (wrong key, or the archive was altered): not restoring" >&2; exit 1; }
unseal "$KEY" "$ARCH" | gunzip > "$W/archive.tar"
safe_members "$W/archive.tar" || { echo "the archive holds unsafe paths: not restoring" >&2; exit 1; }
tar -C "$W" --no-same-owner -xf "$W/archive.tar" && rm -f "$W/archive.tar"
for t in pki models stores kms; do [ -f "$W/$t.tar" ] && { safe_members "$W/$t.tar" || { echo "$t.tar holds unsafe paths: not restoring" >&2; exit 1; }; }; done
cat "$W/manifest.json"; echo
echo "== stopping $PROJ services"
$DC stop api worker-ingest worker-train notifier gateway backup >/dev/null 2>&1 || true
$DC up -d platform-db telemetry-db >/dev/null
for i in $(seq 1 30); do $DC exec -T platform-db pg_isready -U pdp -d platform >/dev/null 2>&1 && break; sleep 2; done
echo "== platform database"
$DC exec -T platform-db psql -q -U pdp -d postgres -c "DROP DATABASE IF EXISTS platform WITH (FORCE)" -c "CREATE DATABASE platform OWNER pdp"
$DC exec -T platform-db pg_restore -U pdp -d platform --no-owner < "$W/platform.dump"
if [ -f "$W/telemetry.dump" ]; then
  echo "== telemetry database"
  $DC exec -T telemetry-db psql -q -U pdp -d postgres -c "DROP DATABASE IF EXISTS telemetry WITH (FORCE)" -c "CREATE DATABASE telemetry OWNER pdp"
  $DC exec -T telemetry-db pg_restore -U pdp -d telemetry --no-owner < "$W/telemetry.dump"
fi
vol() { echo "${PROJ}_$1"; }
echo "== keys and models"
# pki.tar holds PKI_DIR with its private/ subdirectory (two volumes since the 2026-11-08 review: the gateway mounts
# only pdp_pki); the private directory is a mount point, so its contents are cleared, not the directory itself
docker run --rm -v "$(vol pdp_pki)":/pki -v "$(vol pdp_pki_private)":/pki/private -v "$W":/w alpine:3.20 \
  sh -c 'find /pki -mindepth 1 -not -path /pki/private -not -path "/pki/private/*" -delete && rm -rf /pki/private/* && tar -C /pki -o -xf /w/pki.tar'
[ -f "$W/models.tar" ] && docker run --rm -v "$(vol pdp_data)":/data -v "$W":/w alpine:3.20 sh -c 'tar -C /data -o -xf /w/models.tar'
[ -f "$W/stores.tar" ] && docker run --rm -v "$(vol pdp_data)":/data -v "$W":/w alpine:3.20 sh -c 'tar -C /data -o -xf /w/stores.tar'
if [ -f "$W/kms.tar" ]; then
  echo "== KMS (OpenBao storage, unseal key, token)"
  $DC stop kms >/dev/null 2>&1 || true
  mkdir -p "$W/k" && tar -C "$W/k" --no-same-owner -xf "$W/kms.tar"
  docker run --rm -v "$(vol pdp_kms_data)":/kd -v "$W/k":/k alpine:3.20 sh -c 'rm -rf /kd/* && cp -a /k/kms-data/. /kd/'
  mkdir -p "$SECRETS" && cp -a "$W/k/kms-secrets/." "$SECRETS/"
  if [ "$TARGET" = staging ]; then      # staging switches to the restored KMS
    sed -i '/^PDP_KMS=/d; /^COMPOSE_PROFILES=/d; /^PDP_KMS_SECRETS=/d' "$ENVF"
    printf 'PDP_KMS=transit\nCOMPOSE_PROFILES=kms\nPDP_KMS_SECRETS=%s\n' "$SECRETS" >> "$ENVF"
  fi
  $DC up -d kms
fi
if [ "$TARGET" = staging ]; then   # a copy must never notify the real channels (nor report the real agents offline)
  $DC exec -T platform-db psql -q -U pdp -d platform -c "UPDATE notify_channels SET enabled=false"
fi
echo "== starting $PROJ"
$DC up -d api worker-ingest worker-train notifier gateway
for i in $(seq 1 60); do $DC exec -T api python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=3)" >/dev/null 2>&1 && break; sleep 2; done
$DC exec -T api python -c "
from pdp_server import db, pki
with db.conn() as c:
    n = {t: db.q(c, f'SELECT count(*) AS n FROM {t}', one=True)['n'] for t in ('orgs', 'users', 'endpoints', 'alerts', 'bundles', 'notify_channels')}
print('restored:', n); print('CA sha256:', pki.ca_sha256())"
