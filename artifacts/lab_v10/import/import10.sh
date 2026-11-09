#!/bin/bash
# Console import of lab 0.10 (artifacts/lab_v10): retire the old benchmark endpoints, then for each lab set create a
# benchmark endpoint (enrolled by a 0.10.0 agent), register the lab's model as its current model and send the lab's
# 0.10 alert rows. Usage: import10.sh SETS_JSON STATE_DIR
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd); P=$(cd "$D/../../.." && pwd)
SETS=$1; ST=$2; mkdir -p "$ST"
api() { docker ps --format '{{.Names}}' | grep -E '^pdp-api-[0-9]+$' | head -1; }
declare -A LABEL=([CARBANAKV2]=carbanakv2 [OPTC]=optc [ATLASV2]=atlasv2 [E3]=darpa-e3)
if [ "${RETIRE:-1}" = 1 ]; then docker exec -i "$(api)" python - retire-benchmarks < "$D/register10.py"; fi
for s in $(python3 -c "import json; print(' '.join(json.load(open('$SETS'))))"); do
  name="lab10-$(echo "$s" | tr 'A-Z_' 'a-z-')"
  fleet=$(python3 -c "import json; print(json.load(open('$SETS'))['$s']['fleet'])")
  bundle=$(python3 -c "import json; print(json.load(open('$SETS'))['$s']['bundle'])")
  lab=${LABEL[$fleet]:-}
  cfg='{"tz": "US/Eastern"}'      # the fleet label is set at registration (the token tool predates it)
  tok=$(docker exec "$(api)" python -m pdp_server.tools.token --name "$name" --kind benchmark --dataset "$s" --config "$cfg")
  t=$(echo "$tok" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
  fp=$(echo "$tok" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ca_sha256"])')
  mkdir -p "$ST/$name"
  # 1) enrol (no alerts yet) to learn the endpoint id; 2) register the model; 3) send the alerts (same agent identity)
  res=$(docker run --rm --network pdp_edge -v "$P/artifacts/lab_v10:/lab10:ro" -v "$ST/$name:/state" --entrypoint python pdp/server:dev \
        /lab10/import/post10.py "$name" "$t" "$fp" - /state | tail -1)
  docker exec -i "$(api)" python - register "$res" "$bundle" "$lab" < "$D/register10.py"
  docker run --rm --network pdp_edge -v "$P/artifacts/lab_v10:/lab10:ro" -v "$ST/$name:/state" --entrypoint python pdp/server:dev \
        /lab10/import/post10.py "$name" "$t" "$fp" "/lab10/results/rows13-$s.json.gz" /state | tail -1
done
echo IMPORT-DONE
