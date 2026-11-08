#!/bin/bash
# 0.8 held-out run (once). Configuration frozen in commit 55c5eb8 (PROTOCOL.md decision record).
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab8
for h in "$@"; do n=$(echo $h | tr / -)
  [ -f ho-$n.json ] && { echo "$h have"; continue; }
  GPU=1 MEM=${MEM:-24g} ./run.sh heldout08.py /data/heldout/$h --out /lab/ho-$n.json < /dev/null > ho-$n.log 2>&1; echo "$h rc=$?"
done; echo HO-DONE
