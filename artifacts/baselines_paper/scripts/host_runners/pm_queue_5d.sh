#!/bin/bash
G="E3-FIVEDIRECTIONS/node_fivedirections_e3_excel_0409.csv E3-FIVEDIRECTIONS/node_fivedirections_e3_firefox_0411.csv"
for job in "velox 2" "orthrus_non_snooped 0" "orthrus_non_snooped 1" "orthrus_non_snooped 2" "velox 3" "velox 4" "orthrus_non_snooped 3" "orthrus_non_snooped 4"; do
  set -- $job; sys=$1; s=$2
  [ -f /root/bl/stop_queue ] && break
  /root/bl/pm_run.sh $sys FIVEDIRECTIONS_E3 $s
  rm -rf /root/bl/pm/FIVEDIRECTIONS_E3/evaluation
  /root/bl/pm_score.sh $sys FIVEDIRECTIONS_E3 $s 3 /root/PIDSMaker/Ground_Truth/orthrus $G > /root/bl/pm/score_${sys}_5d_s$s.txt 2>&1
  echo "$(date +%T) done $sys $s exit=$(cat /root/bl/pm/exit_bl-pm-$sys-FIVEDIRECTIONS_E3-s$s.txt)" >> /root/bl/pm/queue_5d.log
done
