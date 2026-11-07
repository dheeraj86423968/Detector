#!/bin/bash
# run a lab script in the server image with the working-tree code mounted
L=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab7
G=${GPU:+--gpus all}
exec docker run --rm -i $G --shm-size 8g -m ${MEM:-24g} --oom-score-adj 800 --entrypoint python \
  -v pdp_pdp_data:/data -v /root/Desktop/platform/engine:/opt/pdp/engine:ro -v /root/Desktop/platform/server:/opt/pdp/server:ro \
  -v /root/PIDSMaker/Ground_Truth/orthrus:/gt:ro -v $L:/lab -w /lab -e PYTHONPATH=/opt/pdp/engine:/opt/pdp/server -e PYTHONDONTWRITEBYTECODE=1 ${JOBS:+-e JOBS=$JOBS} \
  pdp/server:dev -u "$@"
