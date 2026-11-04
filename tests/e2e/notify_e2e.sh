#!/bin/bash
# Notifications end to end against a running stack (signs up two throw-away organisations).
#   tests/e2e/notify_e2e.sh                 the production stack (compose project pdp, deploy/.env)
#   PDP_E2E_STACK=staging tests/e2e/notify_e2e.sh    the staging stack (deploy/staging.sh)
# 1. a receiver container answers HTTPS as hooks.pdp-e2e.example (a docker network alias, so: an internal address)
# 2. the deployed notifier must refuse it (internal-address guard on, as in production)
# 3. the test runs notifier rounds itself with internal targets allowed and checks what arrives
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=$(mktemp -d); chmod 777 "$OUT"
docker run --rm -i -v "$OUT":/out -v "$PWD":/src:ro -w /src --entrypoint python pdp/server:dev - <<'PY'
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
now = datetime.datetime.now(datetime.timezone.utc)
ck = ec.generate_private_key(ec.SECP256R1()); cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "notify-e2e CA")])
ca = (x509.CertificateBuilder().subject_name(cn).issuer_name(cn).public_key(ck.public_key()).serial_number(1)
      .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
      .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ck, hashes.SHA256()))
k = ec.generate_private_key(ec.SECP256R1())
leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hooks.pdp-e2e.example")]))
        .issuer_name(cn).public_key(k.public_key()).serial_number(2).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("hooks.pdp-e2e.example")]), critical=False).sign(ck, hashes.SHA256()))
open("/out/ca.pem", "wb").write(ca.public_bytes(serialization.Encoding.PEM))
open("/out/hook.pem", "wb").write(leaf.public_bytes(serialization.Encoding.PEM))
open("/out/hook.key", "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
PY
chmod 644 "$OUT"/*
if [ "${PDP_E2E_STACK:-prod}" = staging ]; then PROJ=pdp-staging; ENVF=staging.env; else PROJ=pdp; ENVF=.env; fi
RID=$(docker run -d --rm --network ${PROJ}_edge --network-alias hooks.pdp-e2e.example -v "$OUT":/out -v "$PWD":/src:ro --entrypoint python pdp/server:dev /src/tests/e2e/hook_receiver.py)
trap 'docker stop "$RID" >/dev/null 2>&1 || true; rm -rf "$OUT"' EXIT
CODE=$(grep -E '^PDP_SIGNUP_CODE=' "deploy/$ENVF" | cut -d= -f2- || true)
cd deploy
docker compose -p "$PROJ" --env-file "$ENVF" -f docker-compose.yml run --rm --no-deps -T -v "$PWD/..":/src:ro -v "$OUT":/out -w /src -e PDP_SIGNUP_CODE="$CODE" \
  -e PYTHONPATH=/src/server:/src/engine --entrypoint python notifier tests/e2e/notify_e2e.py
