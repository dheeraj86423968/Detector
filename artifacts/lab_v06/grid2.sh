#!/bin/bash
cd /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab6
for d in CADETS_E3 THEIA_E3 OPTC_H201 OPTC_H501 OPTC_H051; do
  MEM=24g ./run.sh lab.py $d v2.json --out r2-$d.json > g2-$d.log 2> g2-$d.err
  echo "$d rc=$?"
done
echo GRID2-DONE
