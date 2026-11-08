#!/bin/bash
# lane runner: all9.sh SET:BUNDLE ...
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab9
for j in "$@"; do s=${j%%:*}; b=${j##*:}
  [ -s res9-$s.json ] && continue
  GPU=1 MEM=${MEM:-20g} ./run.sh eval9.py $s $b --out /lab/res9-$s.json < /dev/null > log9-$s.log 2>&1; echo "$s rc=$?"
done; echo LANE-DONE
