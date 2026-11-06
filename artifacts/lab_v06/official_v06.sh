#!/bin/bash
# 0.6 held-out run (lab_v06 PROTOCOL.md), once: DARPA E3 ClearScope and FiveDirections, product-trained bundle
# (0.5 code, 0.4 layer configuration) vs the same bundle with its layers re-fitted under the frozen 0.6 defaults.
L=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab6
cd /root/Desktop/platform/deploy
DC="docker compose -f docker-compose.yml -f docker-compose.gpu.yml -f docker-compose.research.yml --env-file .env --profile eval"
RUN="$DC run --rm --no-deps -T -v /root/Desktop/platform/engine:/opt/pdp/engine:ro -v /root/Desktop/platform/server:/opt/pdp/server:ro -e PYTHONDONTWRITEBYTECODE=1 bench-eval"
# learning integrity reads alerts.status_by (0.6 schema; additive, ignored by the running 0.5 API)
docker exec pdp-platform-db-1 sh -c 'psql -U $POSTGRES_USER -d $POSTGRES_DB -c "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status_by INT REFERENCES users(id) ON DELETE SET NULL; ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status_at TIMESTAMPTZ;"'
for x in "5ef60025-b74e-417a-8e48-7ab1c7dbcd67 CLEARSCOPE_E3 clearscope" "01ca45e0-721f-4181-a4cb-33682335812a FIVEDIRECTIONS_E3 fivedirections"; do
  set -- $x; e=$1; ds=$2; n=$3
  b5=$(docker exec pdp-platform-db-1 sh -c "psql -U \$POSTGRES_USER -d \$POSTGRES_DB -Atc \"select current_bundle from endpoints where id='$e'\"")
  echo "== $ds 0.5 bundle $b5 $(date +%T)"
  $RUN python -m pdp_server.tools.darpa_eval --endpoint $e --dataset $ds --bundles $b5 --device cuda --json /out/benchmark_heldout/eval-$n-v05.json < /dev/null > ../artifacts/benchmark_heldout/eval-$n-v05.log 2>&1
  echo "$ds v05 rc=$? $(date +%T)"
  $RUN python -m pdp_server.tools.add_layers --endpoint $e --bundle $b5 < /dev/null > $L/addl-$n.log 2>&1
  b6=$(tail -1 $L/addl-$n.log | python3 -c 'import json,sys; print(json.load(sys.stdin)["bundles"][0])')
  echo "== $ds 0.6 bundle $b6 $(date +%T)"; echo "$e $ds $b5 $b6" >> $L/jobs_v06.txt
  $RUN python -m pdp_server.tools.darpa_eval --endpoint $e --dataset $ds --bundles $b6 --device cuda --json /out/benchmark_heldout/eval-$n-v06.json < /dev/null > ../artifacts/benchmark_heldout/eval-$n-v06.log 2>&1
  echo "$ds v06 rc=$? $(date +%T)"
done
echo ALL-DONE
