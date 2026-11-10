#!/bin/bash
# runprof.sh <tag> <eid> <bundle_dir>  - profiled training + 5 s GPU/CPU samples
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/cap
n=cap-$1
docker run -d --name $n --gpus all --shm-size 8g -m ${MEM:-24g} --oom-score-adj 800 --entrypoint python -v pdp_pdp_data:/data:ro \
  -v /root/Desktop/platform/engine:/opt/pdp/engine:ro -v $S:/cap -e PYTHONPATH=/opt/pdp/engine -e PYTHONDONTWRITEBYTECODE=1 \
  ${EXTRA} pdp/server:dev -u /cap/${PROF:-prof.py} $2 $3 /cap/out-$1 >/dev/null
while docker inspect -f '{{.State.Running}}' $n 2>/dev/null | grep -q true; do
  echo "$(date +%T) $(nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv,noheader) $(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' $n 2>/dev/null)"
  sleep 5
done > $S/util-$1.log
docker logs $n > $S/train-$1.log 2>&1
docker rm $n >/dev/null
