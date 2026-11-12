#!/bin/bash
# run a lotl_paper script in the server image (product code mounted read-only, lab data read-only)
# usage: [GPU=1] [MEM=18g] [NAME=x] run.sh script.py args...   (outputs under the scratch work dir, mounted as /lab)
W=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lotl
C=/root/Desktop/platform/artifacts/lotl_paper/scripts
G=${GPU:+--gpus all}
exec docker run --rm -i $G ${NAME:+--name $NAME} --shm-size 8g -m ${MEM:-18g} --oom-score-adj 800 --entrypoint python \
  -v pdp_pdp_data:/data:ro -v /root/Desktop/platform/engine:/opt/pdp/engine:ro -v /root/Desktop/platform/server:/opt/pdp/server:ro \
  -v /root/PIDSMaker/Ground_Truth/orthrus:/gt:ro -v $W:/lab -v $C:/code:ro -w /lab \
  -e PYTHONPATH=/code:/opt/pdp/engine:/opt/pdp/server -e PYTHONDONTWRITEBYTECODE=1 \
  pdp/server:dev -u "$@"
