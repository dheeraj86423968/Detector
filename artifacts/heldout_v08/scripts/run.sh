#!/bin/bash
# run python in the pdp/server image: platform code mounted read-only, scratchpad at /work, pdp_data at /data
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v08
exec docker run --rm -i --log-driver none ${NAME:+--name $NAME} --network shared_network --memory ${MEM:-20g} --memory-swap ${MEM:-20g} --oom-score-adj 800 \
  -v /root/Desktop/platform:/src:ro -v $S:/work -v pdp_pdp_data:/data -v /root/PIDSMaker/Ground_Truth/orthrus:/gt:ro \
  ${EXTRA} -e PYTHONPATH=/src/engine:/src/server:/work -e PYTHONDONTWRITEBYTECODE=1 -w /work --entrypoint python pdp/server:dev "$@"
