#!/bin/bash
# paper5 training lane (v3 = v2 + need 1.2x the bundle; at most 2 p5-train containers, TRACE needs 32 GB free RAM): takes jobs "SET RUN" from queue.txt; starts one only when resources allow (PROTOCOL.md)
P=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/p5
V=/var/lib/docker/volumes/pdp_pdp_data/_data
cd $P; lane=$1
run1size() { # MB of run 1's bundle
  case $1 in
    CARBANAKV2_EDR-h*) d=$V/lab08/heldout/CARBANAKV2_EDR/${1#CARBANAKV2_EDR-}/b07rel;;
    THEIA_E5-theia) d=$V/lab08/heldout/THEIA_E5/theia/b07rel;;
    CLEARSCOPE_E5-clearscope) d=$V/lab08/heldout/CLEARSCOPE_E5/clearscope/b07rel;;
    TRACE_E3-trace) d=$V/lab08/heldout/TRACE_E3/trace/v07rel;;
    ATLASV2_EDR-h*) d=$V/lab08/heldout/ATLASV2_EDR/${1#ATLASV2_EDR-}/v07rel;;
    *) d=$(grep -l "\"endpoint\": \"$(python3 -c "import sys;print({'CADETS_E3':'5eafc637','THEIA_E3':'b4021490','CLEARSCOPE_E3':'5ef60025','FIVEDIRECTIONS_E3':'01ca45e0','OPTC_H201':'f85bab6a','OPTC_H501':'18978a51','OPTC_H051':'6ca8a927'}['$1'])")" $V/lab08/*/v07rel/manifest.json | head -1 | xargs dirname);;
  esac
  du -sm $d | cut -f1
}
while true; do
  [ -f STOP ] && { echo "$(date +%T) lane $lane STOP"; break; }
  job=$(flock queue.lock sh -c 'head -1 queue.txt; sed -i 1d queue.txt')
  [ -z "$job" ] && { echo "$(date +%T) lane $lane queue empty"; break; }
  set -- $job; s=$1; r=$2
  if [ -f $V/paper5/$s/r$r/train5.json ]; then echo "$(date +%T) lane $lane $s r$r already trained"; continue; fi
  need=$(( $(run1size $s) * 12 / 10 ))   # v3: b07 hard-links b06's files
  while true; do
    [ -f STOP ] && break
    exec 9> start.lock; flock 9      # v3: check-and-claim is atomic across lanes (two lanes started at once in v2)
    gfree=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1)
    mfree=$(free -m | awk '/Mem:/{print $7}')
    dfree=$(df -m / | awk 'NR==2{print $4}')
    mine=$(( $(du -sm $V/paper5 | cut -f1) + $(du -sm $P | cut -f1) ))
    last=$(cat last_start 2>/dev/null || echo 0); now=$(date +%s)
    ntrain=$(docker ps -q --filter name=p5-train | wc -l)
    ramneed=12288; [ $s = TRACE_E3-trace ] && ramneed=32768
    if [ $ntrain -lt 2 ] && [ $gfree -ge 10240 ] && [ $mfree -ge $ramneed ] && [ $(( dfree - need )) -ge 26000 ] && [ $(( mine + need )) -le 10000 ] && [ $(( now - last )) -ge 600 ]; then date +%s > last_start; flock -u 9; break; fi
    flock -u 9
    echo "$(date +%T) lane $lane waiting $s r$r: running $ntrain gpu $gfree MB ram $mfree MB disk $dfree MB mine $mine MB need $need MB" >> logs/wait.log
    sleep 120
  done
  [ -f STOP ] && { flock queue.lock sh -c "sed -i '1i $s $r' queue.txt"; break; }
  echo "$(date +%T) lane $lane start $s r$r (need $need MB)"
  NAME=p5-train-$lane-$s-r$r GPU=1 MEM=${MEM:-24g} ./run5.sh train5.py $s $r < /dev/null > logs/train-$s-r$r.log 2>&1
  rc=$?; echo "$(date +%T) lane $lane done $s r$r rc=$rc"
  [ $rc -ne 0 ] && echo "$s $r rc=$rc" >> failed.txt
done
