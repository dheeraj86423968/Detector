#!/bin/bash
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab7
while pgrep -f cache05.sh >/dev/null; do sleep 20; done
while read e d b; do
  v=$(python3 -c "import json;print(json.load(open('/var/lib/docker/volumes/pdp_pdp_data/_data/bundles/$e/$b/manifest.json'))['val_day'])")
  GPU=1 MEM=24g ./run.sh cache_val.py $e $v $b < /dev/null; echo "$e rc=$?"
done < jobs05.txt
echo CACHEVAL-DONE
