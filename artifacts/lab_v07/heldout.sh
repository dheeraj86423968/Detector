#!/bin/bash
# 0.7 held-out run (once). Configuration frozen in commit 54386cf (PROTOCOL.md decision record).
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab7
for h in ATLASV2_EDR/h1 ATLASV2_EDR/h2 TRACE_E3/trace; do
  n=$(echo $h | tr / -)
  GPU=1 MEM=${MEM:-32g} ./run.sh heldout_eval.py /data/heldout/$h --out /lab/heldout-$n.json < /dev/null > heldout-$n.log 2>&1; echo "$h rc=$?"
done; echo HELDOUT-DONE
