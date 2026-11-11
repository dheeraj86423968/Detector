#!/bin/bash
# anchor_run.sh SET [score files ...] : one anchor13.py pass (pdp/server:dev image, lab data read-only)
SET=$1; shift; P=/root/Desktop/platform/artifacts/baselines_paper
L=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab9
F=""; for f in "$@"; do F="$F /scores/$(basename $f)"; done
EX=""; [ "$SET" = "CLEARSCOPE_E5-clearscope-3att" ] && { SET=CLEARSCOPE_E5-clearscope; EX="--gt-extra E5-CLEARSCOPE/node_clearscope_e5_lockwatch_0517.csv"; TAG=-3att; }
docker run --rm --name bl-anch-$SET$TAG --gpus all --shm-size 8g -m 20g --oom-score-adj 800 --entrypoint python \
  -v pdp_pdp_data:/data:ro -v /root/Desktop/platform/engine:/opt/pdp/engine:ro -v /root/Desktop/platform/server:/opt/pdp/server:ro \
  -v /root/PIDSMaker/Ground_Truth/orthrus:/gt:ro -v $L:/lab:ro -v $P/scripts:/bl:ro -v $P/scores:/scores:ro -v $P/results/anchoring:/out -v /root/bl/anch:/nodes \
  -w /bl -e PYTHONPATH=/opt/pdp/engine:/opt/pdp/server -e PYTHONDONTWRITEBYTECODE=1 pdp/server:dev -u anchor13.py $SET $EX \
  --out /out/anch-$SET$TAG.json --nodes /nodes/nodes-$SET$TAG.npz ${F:+--scores $F} > $P/results/anchoring/anch-$SET$TAG.log 2>&1
echo "$(date -u +%T) $SET$TAG rc=$?"
