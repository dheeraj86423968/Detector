#!/bin/bash
# 0.6 held-out benchmark (docs/BENCHMARK_HELDOUT.md): DARPA E3 ClearScope (Android) and FiveDirections (Windows),
# PIDSMaker databases, through the normal product path with the product DEFAULTS (no per-host train overrides: what
# a new client gets). Chronological split: the first N days train, the next validates, the rest are test days.
#   deploy/bench/run_heldout.sh start [clearscope-e3 fivedirections-e3]
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
DC="docker compose -f docker-compose.yml -f docker-compose.gpu.yml -f docker-compose.research.yml --env-file .env"
declare -A DB=([clearscope-e3]=clearscope_e3 [fivedirections-e3]=fivedirections_e3)
declare -A NTRAIN=([clearscope-e3]=6 [fivedirections-e3]=4)
api() { docker ps --format '{{.Names}}' | grep -E '^pdp-api-[0-9]+$' | head -1; }
case "${1:-}" in
  start)
    shift; hosts=${*:-clearscope-e3 fivedirections-e3}
    for h in $hosts; do
      cfg="{\"baseline_days\": ${NTRAIN[$h]}, \"tz\": \"US/Eastern\"}"
      tok=$(docker exec "$(api)" python -m pdp_server.tools.token --name "darpa-$h" --kind benchmark --dataset "${DB[$h]}" --config "$cfg")
      t=$(echo "$tok" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
      fp=$(echo "$tok" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ca_sha256"])')
      $DC run --rm --no-deps "agent-bench-$h" agent enroll "$t" --ca-sha256 "$fp"
      $DC up -d --no-deps "agent-bench-$h"
      echo "darpa-$h started"
    done ;;
  *) sed -n 2,6p "$0" >&2; exit 2 ;;
esac
