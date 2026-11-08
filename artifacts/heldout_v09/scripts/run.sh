#!/bin/bash
# run python in the pdp/server image: platform code mounted read-only (scripts at /src/artifacts/heldout_v09/scripts),
# v09 work dir at /work, pdp_data at /data, orthrus GT at /gt   (v08 run.sh with the work dir changed)
W=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v09
exec docker run --rm -i --log-driver none ${NAME:+--name $NAME} --network shared_network --memory ${MEM:-20g} --memory-swap ${MEM:-20g} --oom-score-adj 800 \
  -v /root/Desktop/platform:/src:ro -v $W:/work -v pdp_pdp_data:/data -v /root/PIDSMaker/Ground_Truth/orthrus:/gt:ro \
  ${EXTRA} -e PYTHONPATH=/src/engine:/src/server:/src/artifacts/heldout_v09/scripts -e PYTHONDONTWRITEBYTECODE=1 -w /work --entrypoint python pdp/server:dev "$@"
