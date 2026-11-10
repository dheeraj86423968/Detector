#!/bin/bash
# run15.sh SET... : eval15 per set in the server image with the working-tree code (GPU), 3 at a time
L=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab12
one() {
  s=$1; shift
  docker run --rm --gpus all --shm-size 8g -m ${MEM:-20g} --oom-score-adj 800 --entrypoint python \
    -v pdp_pdp_data:/data -v /root/Desktop/platform/engine:/opt/pdp/engine:ro -v /root/Desktop/platform/server:/opt/pdp/server:ro \
    -v /root/PIDSMaker/Ground_Truth/orthrus:/gt:ro -v $L:/lab -w /lab -e PYTHONPATH=/opt/pdp/engine:/opt/pdp/server -e PYTHONDONTWRITEBYTECODE=1 \
    pdp/server:dev -u eval15.py $s --out out/res15${TAG}-$s.json --rows out/rows15${TAG}-$s.json.gz "$@" > $L/out/log15${TAG}-$s.log 2>&1
  echo "$(date +%T) $s rc=$?"
}
export -f one; export L
printf '%s\n' "$@" | xargs -P ${PAR:-3} -I{} bash -c "one {} $EXTRA"
echo ALLDONE
