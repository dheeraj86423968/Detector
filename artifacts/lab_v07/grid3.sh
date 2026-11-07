#!/bin/bash
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab7
for d in CADETS_E3 THEIA_E3 OPTC_H201; do
  for b in 0 10; do
    MEM=20g ./run.sh run_v3.py $d --learned --budget $b --variants max:0,max:0.7,max:0.85,max:0.9 --out g3-$d-b$b.json < /dev/null > g3-$d-b$b.log 2>&1
    echo "$d b$b rc=$?"
  done
done
echo GRID3-DONE
