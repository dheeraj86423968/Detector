#!/bin/bash
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab9
for s in "$@"; do
  [ -s res13-$s.json ] && continue
  GPU=1 MEM=${MEM:-18g} ./run.sh eval13.py $s --out /lab/res13-$s.json --rows /lab/rows13-$s.json.gz < /dev/null > log13-$s.log 2>&1; echo "$s rc=$?"
done; echo LANE-DONE
