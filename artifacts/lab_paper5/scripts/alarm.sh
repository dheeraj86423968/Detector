#!/bin/bash
# exits (one notification) on: a new failure, disk free < 25 GB, the scorer finishing, or after $1 seconds
P=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/p5
n0=$(cat $P/logs/score.out $P/logs/lane*.out | grep -c "FAIL\|rc=[1-9]"); t0=$(date +%s)
while true; do
  n=$(cat $P/logs/score.out $P/logs/lane*.out | grep -c "FAIL\|rc=[1-9]")
  [ $n -gt $n0 ] && { echo "NEW FAILURE:"; cat $P/logs/score.out $P/logs/lane*.out | grep "FAIL\|rc=[1-9]" | tail -n $((n-n0)); exit; }
  f=$(df -m / | awk 'NR==2{print $4}'); [ $f -lt 25600 ] && { echo "DISK LOW $f MB; mine $(du -sm /var/lib/docker/volumes/pdp_pdp_data/_data/paper5 | cut -f1) MB"; exit; }
  grep -q "all done\|STOP" $P/logs/score.out && { echo "SCORER FINISHED"; exit; }
  [ $(( $(date +%s) - t0 )) -ge ${1:-3600} ] && { echo "TIMER $(date +%T)"; grep scored $P/logs/score.out | grep -v " r1:" | cut -c1-80 | tail -n 6; exit; }
  sleep 30
done
