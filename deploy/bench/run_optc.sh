#!/bin/bash
# DARPA OpTC benchmark (docs/BENCHMARK_OPTC.md): load PIDSMaker's pre-built databases, create one benchmark endpoint
# per host and start its replay agent through the normal product path (enrol, upload the baseline, training on the
# GPU worker, signed bundle, local detection on the test days).
#
#   deploy/bench/run_optc.sh load DIR       pg_restore DIR/optc_{201,501,051}.dump into the research Postgres
#   deploy/bench/run_optc.sh start [HOSTS]  endpoints + agents (default: 201 501 051)
#   deploy/bench/run_optc.sh status         replay / training progress per host
#
# Settings per host: PIDSMaker's tuned hyper-parameters for Velox (detector-1) and Orthrus non-snooped (detector-2)
# (docs tuned_systems.md); baseline = the 3 training days, then the validation day.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
DC="docker compose -f docker-compose.yml -f docker-compose.gpu.yml -f docker-compose.research.yml --env-file .env"
PG=${PDP_RESEARCH_PG:-postgres}
declare -A TRAIN=(
  [201]='{"velox_lr": 0.001, "velox_out_dim": 128, "orthrus_hid_dim": 128, "orthrus_out_dim": 128}'
  [501]='{"velox_lr": 0.001, "velox_out_dim": 320, "orthrus_hid_dim": 256, "orthrus_out_dim": 256}'
  [051]='{"velox_lr": 0.001, "velox_out_dim": 320, "orthrus_hid_dim": 128, "orthrus_out_dim": 128}'
)
api() { docker ps --format '{{.Names}}' | grep -E '^pdp-api-[0-9]+$' | head -1; }

case "${1:-}" in
  load)
    dir=${2:?usage: run_optc.sh load DIR}
    for h in 201 501 051; do
      f="$dir/optc_$h.dump"
      [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
      file "$f" | grep -q "PostgreSQL custom database dump" || { echo "$f is not a PostgreSQL dump: $(file -b "$f" | cut -c1-80)" >&2; exit 1; }
      if docker exec "$PG" psql -U postgres -Atc "SELECT 1 FROM pg_database WHERE datname='optc_$h'" | grep -q 1; then
        echo "optc_$h already loaded"; continue
      fi
      echo "loading optc_$h ($(du -h "$f" | cut -f1))"
      docker exec "$PG" psql -U postgres -c "CREATE DATABASE optc_$h" >/dev/null
      docker cp "$f" "$PG:/tmp/optc_$h.dump"
      docker exec "$PG" pg_restore -U postgres --no-owner --no-privileges -j 4 -d "optc_$h" "/tmp/optc_$h.dump" || echo "pg_restore reported warnings for optc_$h"
      docker exec "$PG" rm -f "/tmp/optc_$h.dump"
      docker exec "$PG" psql -U postgres -d "optc_$h" -Atc "SELECT 'optc_$h: ' || (SELECT count(*) FROM event_table) || ' events, ' ||
        (SELECT count(*) FROM subject_node_table) || ' processes, ' || (SELECT count(*) FROM file_node_table) || ' files, ' ||
        (SELECT count(*) FROM netflow_node_table) || ' flows'"
    done ;;
  start)
    shift; hosts=${*:-201 501 051}
    for h in $hosts; do
      cfg="{\"baseline_days\": 3, \"tz\": \"US/Eastern\", \"train\": ${TRAIN[$h]}}"
      tok=$(docker exec "$(api)" python -m pdp_server.tools.token --name "darpa-optc-h$h" --kind benchmark --dataset "optc_$h" --config "$cfg")
      t=$(echo "$tok" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
      fp=$(echo "$tok" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ca_sha256"])')
      $DC run --rm --no-deps "agent-bench-optc-h$h" agent enroll "$t" --ca-sha256 "$fp"
      $DC up -d --no-deps "agent-bench-optc-h$h"
      echo "darpa-optc-h$h started"
    done ;;
  status)
    docker exec pdp-platform-db-1 psql -U pdp -d platform -c "SELECT e.name, e.phase, e.last_seen::timestamp(0),
      (SELECT string_agg(b.date || ':' || b.events, ' ' ORDER BY b.date) FROM baseline_days b WHERE b.endpoint_id=e.id) AS days,
      (SELECT string_agg(j.kind || '/' || j.state, ' ') FROM jobs j WHERE j.endpoint_id=e.id AND j.created_at > now() - interval '2 days') AS jobs
      FROM endpoints e WHERE e.name LIKE 'darpa-optc-%' ORDER BY e.name" ;;
  *) sed -n 2,12p "$0" >&2; exit 2 ;;
esac
