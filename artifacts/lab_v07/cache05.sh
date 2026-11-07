#!/bin/bash
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab7
while read e d b; do GPU=1 MEM=24g ./run.sh cache_scores.py $e $d $b < /dev/null; echo "$e rc=$?"; done < jobs05.txt
echo CACHE05-DONE
