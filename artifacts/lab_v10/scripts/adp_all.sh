#!/bin/bash
# ADP of 0.10 (adp13.py), comparable hosts first; one at a time on the GPU
L=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/lab9
R=/root/Desktop/platform/artifacts/lab_v10/scripts/run.sh
run() { # set [extra-gt] [tag]
  GPU=1 MEM=20g $R adp13.py "$1" --out adp/adp-$1$3.json --rows adp/rows-$1$3.json.gz ${2:+--gt-extra $2} > $L/adp/adp-$1$3.log 2>&1
  echo "$(date +%H:%M:%S) $1$3 rc=$? $(grep -E '^.{9}P2:|P0:' $L/adp/adp-$1$3.log | tail -2 | tr '\n' ' ')"
}
run CADETS_E3; run THEIA_E3; run OPTC_H201; run OPTC_H501; run OPTC_H051; run THEIA_E5-theia
run CLEARSCOPE_E5-clearscope E5-CLEARSCOPE/node_clearscope_e5_lockwatch_0517.csv -3att
run CLEARSCOPE_E3
for s in TRACE_E3-trace FIVEDIRECTIONS_E3 ATLASV2_EDR-h1 ATLASV2_EDR-h2 CARBANAKV2_EDR-h1 CARBANAKV2_EDR-h2 CARBANAKV2_EDR-h3 CARBANAKV2_EDR-h4 CARBANAKV2_EDR-h5 CLEARSCOPE_E5-clearscope; do run $s; done
echo ADP-ALL-DONE
