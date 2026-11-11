#!/bin/bash
# pm_queue_host.sh DS TESTDAYS GTROOT "gt files" "sys:seed[:mem] ..."
DS=$1; TD=$2; GR=$3; G=$4; JOBS=$5
for job in $JOBS; do
  IFS=: read sys s mem <<< "$job"
  [ -f /root/bl/stop_$DS ] && break
  while [ "$(df --output=avail -B1 / | tail -1)" -lt ${MINFREE:-30000000000} ]; do sleep 60; done
  PMNAME=${PMNAME:-$DS} MEM=${mem:-28g} /root/bl/pm_run.sh $sys $DS $s
  rm -rf /root/bl/pm/$DS/evaluation
  /root/bl/pm_score.sh $sys $DS $s $TD $GR $G > /root/bl/pm/score_${sys}_${DS}_s$s.txt 2>&1
  echo "$(date +%T) done $sys $DS $s exit=$(cat /root/bl/pm/exit_bl-pm-$sys-$DS-s$s.txt)" >> /root/bl/pm/queue_hosts.log
done
