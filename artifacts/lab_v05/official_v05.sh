#!/bin/bash
# 0.5 official numbers: dev bundles (detector-1 retrained) -> max fusion; held-out 0.4 bundles -> detector-1 retrained
# + max fusion (run once); then darpa_eval on all 25 (one at a time)
L=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab5
cd /root/Desktop/platform/deploy
DC="docker compose -f docker-compose.yml -f docker-compose.gpu.yml -f docker-compose.research.yml --env-file .env --profile eval"
RUN="$DC run --rm --no-deps -T -v /root/Desktop/platform/engine:/opt/pdp/engine:ro -v /root/Desktop/platform/server:/opt/pdp/server:ro -e PYTHONDONTWRITEBYTECODE=1 bench-eval"
tool() {  # eid bids extra-args -> prints new bundle ids
  $RUN python -m pdp_server.tools.retrain_detector1 --endpoint $1 --bundles $2 $3 < /dev/null > $L/off-$1.log 2>&1
  tail -1 $L/off-$1.log | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)["bundles"]))'
}
declare -A OUT
echo "== phase A (dev fusion) $(date +%T)"
while read e d b; do ( echo "$e $d $(tool $e $b --reuse-detector1)" > $L/off-new-$e.txt ) & done < $L/jobs5.txt
wait
echo "== phase B (held-out retrain) $(date +%T)"
( echo "18978a51-ac8f-4afd-8f7a-c3003fa744c2 2019-09-23,2019-09-24,2019-09-25 $(tool 18978a51-ac8f-4afd-8f7a-c3003fa744c2 e938ca01-a93a-4cc2-a44a-6e3c9ce4ebc1,994db890-bf1b-44a9-a0b3-da2b77e61795,985c0640-9242-4b58-baa8-5d31e8c12ec1,2d2e995d-74d3-45c5-ad33-8307d076252b,a5b982fc-9f67-4aaf-bcf8-b104974da589)" > $L/off-new-18978a51-ac8f-4afd-8f7a-c3003fa744c2.txt ) &
( echo "6ca8a927-9474-45be-870a-52bd56133b0e 2019-09-23,2019-09-24,2019-09-25 $(tool 6ca8a927-9474-45be-870a-52bd56133b0e 568f3afc-eae2-45d6-ba8d-420e3060409d,8a603f0a-056b-4e8b-ab44-e66ce3e6dbc2,954378d9-f30e-459e-8763-35c48d2db14a,375374cd-a0a6-47e9-816c-1387857adaee,93fd4212-ee43-45b9-a996-47b92314fc53)" > $L/off-new-6ca8a927-9474-45be-870a-52bd56133b0e.txt ) &
wait
cat $L/off-new-*.txt > $L/jobs_v05.txt
declare -A NAME=([5eafc637-14c7-4074-b4d3-4e611dea925e]="CADETS_E3 benchmark_e3/eval-cadets-v05" [b4021490-6dd4-4dfb-8628-b3e55af27b90]="THEIA_E3 benchmark_e3/eval-theia-v05"
  [f85bab6a-0fce-4b21-81d8-dd967b8d4395]="OPTC_H201 benchmark_optc/eval-optc-h201-v05" [18978a51-ac8f-4afd-8f7a-c3003fa744c2]="OPTC_H501 benchmark_optc/eval-optc-h501-v05"
  [6ca8a927-9474-45be-870a-52bd56133b0e]="OPTC_H051 benchmark_optc/eval-optc-h051-v05")
for e in 5eafc637-14c7-4074-b4d3-4e611dea925e b4021490-6dd4-4dfb-8628-b3e55af27b90 f85bab6a-0fce-4b21-81d8-dd967b8d4395 18978a51-ac8f-4afd-8f7a-c3003fa744c2 6ca8a927-9474-45be-870a-52bd56133b0e; do
  set -- ${NAME[$e]}; ds=$1; out=$2
  b=$(grep "^$e" $L/jobs_v05.txt | awk '{print $3}')
  echo "== $ds darpa_eval $b $(date +%T)"
  $RUN python -m pdp_server.tools.darpa_eval --endpoint $e --dataset $ds --bundles $b --device cuda --json /out/$out.json < /dev/null > ../artifacts/$out.log 2>&1
  echo "$ds done rc=$? $(date +%T)"
done
echo ALL-DONE
