#!/bin/bash
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab7
for d in CADETS_E3 THEIA_E3 OPTC_H201 OPTC_H501 OPTC_H051 CLEARSCOPE_E3 FIVEDIRECTIONS_E3; do
  GPU=1 MEM=24g ./run.sh prod07.py $d --name v07c --grouped < /dev/null > v07c-$d.log 2>&1; echo "$d rc=$?"
done
for h in ATLASV2_EDR/h1 ATLASV2_EDR/h2 TRACE_E3/trace; do n=$(echo $h | tr / -)
  GPU=1 MEM=32g ./run.sh heldout_eval.py /data/heldout/$h --name b07c --only 0.7 --grouped --out /lab/seen07c-$n.json < /dev/null > seen07c-$n.log 2>&1; echo "$h rc=$?"
done; echo V07C-DONE
