#!/bin/bash
# runall.sh TRANSFORM SET... : one lotl13.py pass per set, one at a time on the GPU (skips sets already done)
T=$1; shift
W=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lotl
R=/root/Desktop/platform/artifacts/lotl_paper/scripts/run.sh
mkdir -p $W/out
for s in "$@"; do
  [ -s $W/out/res-$T-$s.json ] && continue
  EX=""; [ "$s" = "CLEARSCOPE_E5-clearscope" ] && EX=""   # PIDSMaker list (appstarter, tester), as heldout_v10
  M=18g; [ "$s" = "TRACE_E3-trace" ] && M=36g
  GPU=1 MEM=$M NAME=lotl-$T-$s $R /code/lotl13.py $s --transform $T --out /lab/out/res-$T-$s.json --rows /lab/out/rows-$T-$s.json.gz \
    --map /lab/out/map-$T-$s.json $EX < /dev/null > $W/out/log-$T-$s.log 2>&1
  echo "$(date -u +%T) $T $s rc=$? $(grep -E '^.{9}(P2|F3|L12):' $W/out/log-$T-$s.log | tr '\n' ' ')"
done; echo LANE-DONE
