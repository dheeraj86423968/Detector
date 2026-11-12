#!/bin/bash
# run16.sh SCRIPT SET... : SCRIPT (prep16.py | eval16.py) per set in the server image with the working-tree engine, PAR at a time
L=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$1; shift
one() {
  s=$1
  extra=""; [ "$SCRIPT" = eval16.py ] && extra="--out out/res16-$s.json"
  docker run --rm --gpus all --shm-size 8g -m ${MEM:-20g} --oom-score-adj 800 --entrypoint python \
    -v pdp_pdp_data:/data:ro -v /root/Desktop/platform/engine:/opt/pdp/engine:ro -v /root/Desktop/platform/server:/opt/pdp/server:ro \
    -v /root/PIDSMaker/Ground_Truth/orthrus:/gt:ro -v $L:/lab -w /lab -e PYTHONPATH=/opt/pdp/engine:/opt/pdp/server -e PYTHONDONTWRITEBYTECODE=1 \
    pdp/server:dev -u $SCRIPT $s $extra > $L/out/log-${SCRIPT%.py}-$s.log 2>&1
  echo "$(date +%T) $SCRIPT $s rc=$?"
}
export -f one; export L SCRIPT
printf '%s\n' "$@" | xargs -P ${PAR:-3} -I{} bash -c "one {}"
echo ALLDONE
