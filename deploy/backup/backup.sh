#!/bin/sh
# PDP backup job (compose service "backup", postgres image: pg_dump, tar, openssl). Every PDP_BACKUP_INTERVAL_H hours:
#   platform.dump   platform database (users, organisations, endpoints, alerts, incidents' data, model metadata)
#   pki.tar         CA / signing key files (PDP_KMS=file) and the CA certificate
#   kms.tar         bundled OpenBao storage + its unseal key and token (PDP_KMS=transit with profile kms)
#   models.tar      the model each endpoint currently uses (agents can re-download after a restore)
#   [telemetry.dump, stores.tar]  with PDP_BACKUP_FULL=1: raw baseline telemetry and training windows, needed only to
#                   retrain endpoints still learning (large)
# The set is packed into one archive encrypted with AES-256 (openssl, key file /run/backup.key): the archive holds
# the signing keys, so the key must be kept somewhere else (deploy/backup.key; copy it off this host).
# Retention: PDP_BACKUP_KEEP archives (default 7). Status in the platform database (kv 'backup') for the console and
# the operator notifications. Restore: deploy/restore.sh <archive>.
set -u
umask 077
INTERVAL_H=${PDP_BACKUP_INTERVAL_H:-24}; KEEP=${PDP_BACKUP_KEEP:-7}; OUT=/backups
export PGPASSWORD="$PDP_DB_PASSWORD"
PG="-h platform-db -U pdp -d platform"
log() { echo "$(date -u +%FT%TZ) backup: $*"; }
status() {   # ok size file error
  psql $PG -qAtc "INSERT INTO kv (k, v, updated_at) VALUES ('backup', jsonb_build_object('at', extract(epoch from now()), 'ok', $1,
    'bytes', $2, 'file', '$3', 'error', '$4'), now()) ON CONFLICT (k) DO UPDATE SET v=excluded.v, updated_at=now()" >/dev/null 2>&1
}
one() {
  ts=$(date -u +%Y%m%dT%H%M%SZ); w=$(mktemp -d /backups/.work-XXXXXX)
  pg_dump $PG -Fc -f "$w/platform.dump" || { echo "platform database dump failed"; return 1; }
  tar -C /pki -cf "$w/pki.tar" . 2>/dev/null || true
  if [ -d /kms-data ] && [ "$(ls -A /kms-data 2>/dev/null)" ]; then tar -cf "$w/kms.tar" -C / kms-data kms-secrets 2>/dev/null; fi
  psql $PG -qAtc "SELECT b.path FROM endpoints e JOIN bundles b ON b.id=e.current_bundle WHERE e.phase <> 'retired'" > "$w/models.list"
  sed 's#^/data/##' "$w/models.list" | tar -C /data -cf "$w/models.tar" -T - 2>/dev/null || true
  if [ "${PDP_BACKUP_FULL:-0}" = 1 ]; then
    PGPASSWORD="$PDP_DB_PASSWORD" pg_dump -h telemetry-db -U pdp -d telemetry -Fc -f "$w/telemetry.dump" || true
    tar -C /data -cf "$w/stores.tar" endpoints 2>/dev/null || true
  fi
  echo "{\"created\": \"$ts\", \"full\": ${PDP_BACKUP_FULL:-0}}" > "$w/manifest.json"
  tar -C "$w" -cf - . | gzip -1 | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass file:/run/backup.key -out "$OUT/pdp-$ts.tar.gz.enc" \
    || { rm -rf "$w"; echo "encryption failed"; return 1; }
  rm -rf "$w"
  sz=$(stat -c %s "$OUT/pdp-$ts.tar.gz.enc")
  ls -1t "$OUT"/pdp-*.tar.gz.enc 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
  log "wrote pdp-$ts.tar.gz.enc ($sz bytes); keeping the newest $KEEP"
  status true "$sz" "pdp-$ts.tar.gz.enc" ""
}
[ -s /run/backup.key ] || { log "no backup key (/run/backup.key); generate deploy/backup.key"; sleep 3600; exit 1; }
while true; do
  last=$(ls -1t "$OUT"/pdp-*.tar.gz.enc 2>/dev/null | head -n1)
  age=999999; [ -n "$last" ] && age=$(( $(date +%s) - $(stat -c %Y "$last") ))
  if [ "$age" -ge $((INTERVAL_H * 3600)) ] || [ -f "$OUT/run-now" ]; then
    rm -f "$OUT/run-now"
    if one > /tmp/backup.log 2>&1; then cat /tmp/backup.log
    else err=$(tail -n1 /tmp/backup.log | tr -d "'"); log "FAILED: $err"; status false 0 "" "$err"; fi
  fi
  sleep 300
done
