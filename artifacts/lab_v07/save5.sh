#!/bin/bash
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab7
for d in CADETS_E3 THEIA_E3 OPTC_H201; do
  MEM=20g ./run.sh run_v4.py $d --learned --online --budget 10 --variants max:0:0,max:0.95:0.4 --save s5-$d.npz --out s5-$d.json < /dev/null > s5-$d.log 2>&1; echo "$d rc=$?"
done; echo S5-DONE
