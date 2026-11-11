#!/bin/bash
G="E3-FIVEDIRECTIONS/node_fivedirections_e3_excel_0409.csv E3-FIVEDIRECTIONS/node_fivedirections_e3_firefox_0411.csv"
run() { sys=$1; s=$2
  /root/bl/pm_run.sh $sys FIVEDIRECTIONS_E3 $s
  rm -rf /root/bl/pm/FIVEDIRECTIONS_E3/evaluation
  /root/bl/pm_score.sh $sys FIVEDIRECTIONS_E3 $s 3 /root/PIDSMaker/Ground_Truth/orthrus $G > /root/bl/pm/score_${sys}_5d_s$s.txt 2>&1
  echo "$(date +%T) done $sys $s exit=$(cat /root/bl/pm/exit_bl-pm-$sys-FIVEDIRECTIONS_E3-s$s.txt)" >> /root/bl/pm/queue_5d.log; }
run velox 3; run velox 4
# ORTHRUS needs > 28 GB RAM here: run alone with 40 GB once no other bl- container runs
for s in 0 1 2 3 4; do
  [ -f /root/bl/stop_queue2 ] && break
  while docker ps --format '{{.Names}}' | grep -q '^bl-'; do sleep 30; done
  MEM=40g run orthrus_non_snooped $s
done
