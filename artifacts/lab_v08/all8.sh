#!/bin/bash
# all8.sh NAME [key=value ...]: prod08 on every dev/seen set, sequentially (one GPU run at a time, memory-capped)
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab8
N=$1; shift
for s in ${SETS:-CADETS_E3 THEIA_E3 OPTC_H201 OPTC_H501 OPTC_H051 CLEARSCOPE_E3 FIVEDIRECTIONS_E3 ATLASV2_EDR-h1 ATLASV2_EDR-h2 TRACE_E3-trace}; do
  [ -f res-$N-$s.json ] && { echo "$s have"; continue; }
  GPU=1 MEM=${MEM:-26g} ./run.sh prod08.py $s --name $N ${@:+--cfg "$@"} < /dev/null > log-$N-$s.log 2>&1; echo "$s rc=$?"
done; echo ALL8-$N-DONE
