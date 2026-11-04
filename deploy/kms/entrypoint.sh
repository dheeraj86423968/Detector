#!/bin/sh
# Start OpenBao and unseal it with the key in /run/kms-unseal/key (mounted only into this container).
# First start: the server comes up uninitialised; tools/kms_setup.py initialises it and writes the key.
set -e
/usr/local/bin/docker-entrypoint.sh server -config=/kms/config.hcl &
SRV=$!
export BAO_ADDR=http://127.0.0.1:8200
(
  for i in $(seq 1 600); do
    st=$(bao status -format=json 2>/dev/null || true)
    case "$st" in
      *'"initialized": true'*'"sealed": true'*)
        if [ -s /run/kms-unseal/key ]; then bao operator unseal "$(cat /run/kms-unseal/key)" >/dev/null && echo "kms: unsealed"; fi ;;
      *'"sealed": false'*) exit 0 ;;
    esac
    sleep 2
  done
) &
wait $SRV
