#!/bin/bash
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab7
while read e d b; do
  GPU=1 MEM=24g ./run.sh cache_scores.py $e $d $b < /dev/null; echo "test $e rc=$?"
  v=$(python3 -c "import json;print(json.load(open('/var/lib/docker/volumes/pdp_pdp_data/_data/bundles/$e/$b/manifest.json'))['val_day'])")
  GPU=1 MEM=24g ./run.sh cache_val.py $e $v $b < /dev/null; echo "val $e rc=$?"
done < jobs_seen.txt
for d in OPTC_H501 OPTC_H051 CLEARSCOPE_E3 FIVEDIRECTIONS_E3; do
  MEM=20g ./run.sh l2nodes.py $d < /dev/null > l2-$d.log 2>&1; echo "l2 $d rc=$?"
  MEM=24g ./run.sh run_v4.py $d --learned --budget 10 --variants max:0:0,max:0.95:0.4 --save s6-$d.npz --out s6-$d.json < /dev/null > s6-$d.log 2>&1; echo "s6 $d rc=$?"
done
echo SEEN-DONE
