#!/bin/bash
# paper5 scorer: one scoring at a time; new runs first (they hold disk), then run 1's bundles (per-detector numbers)
P=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/p5
V=/var/lib/docker/volumes/pdp_pdp_data/_data
R=/root/Desktop/platform/artifacts/lab_paper5/results
cd $P
SETS="CADETS_E3 THEIA_E3 CLEARSCOPE_E3 THEIA_E5-theia OPTC_H051 OPTC_H201 OPTC_H501 CLEARSCOPE_E5-clearscope TRACE_E3-trace FIVEDIRECTIONS_E3 ATLASV2_EDR-h1 ATLASV2_EDR-h2 CARBANAKV2_EDR-h1 CARBANAKV2_EDR-h2 CARBANAKV2_EDR-h3 CARBANAKV2_EDR-h4 CARBANAKV2_EDR-h5"
run1() {
  case $1 in
    CARBANAKV2_EDR-h*) echo /data/lab08/heldout/CARBANAKV2_EDR/${1#CARBANAKV2_EDR-}/b07rel;;
    THEIA_E5-theia) echo /data/lab08/heldout/THEIA_E5/theia/b07rel;;
    CLEARSCOPE_E5-clearscope) echo /data/lab08/heldout/CLEARSCOPE_E5/clearscope/b07rel;;
    TRACE_E3-trace) echo /data/lab08/heldout/TRACE_E3/trace/v07rel;;
    ATLASV2_EDR-h*) echo /data/lab08/heldout/ATLASV2_EDR/${1#ATLASV2_EDR-}/v07rel;;
    CADETS_E3) echo /data/lab08/5eafc637-14c7-4074-b4d3-4e611dea925e/v07rel;;
    THEIA_E3) echo /data/lab08/b4021490-6dd4-4dfb-8628-b3e55af27b90/v07rel;;
    CLEARSCOPE_E3) echo /data/lab08/5ef60025-b74e-417a-8e48-7ab1c7dbcd67/v07rel;;
    FIVEDIRECTIONS_E3) echo /data/lab08/01ca45e0-721f-4181-a4cb-33682335812a/v07rel;;
    OPTC_H201) echo /data/lab08/f85bab6a-0fce-4b21-81d8-dd967b8d4395/v07rel;;
    OPTC_H501) echo /data/lab08/18978a51-ac8f-4afd-8f7a-c3003fa744c2/v07rel;;
    OPTC_H051) echo /data/lab08/6ca8a927-9474-45be-870a-52bd56133b0e/v07rel;;
  esac
}
score() { # set run bundle(container path)
  local s=$1 r=$2 b=$3 extra=""
  [ $s = CLEARSCOPE_E5-clearscope ] && extra="--gt-extra E5-CLEARSCOPE/node_clearscope_e5_lockwatch_0517.csv"
  while true; do   # light job, but still wait for room
    g=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1); m=$(free -m | awk '/Mem:/{print $7}')
    [ $g -ge 6144 ] && [ $m -ge 10240 ] && break
    echo "$(date +%T) scorer waiting $s r$r gpu $g ram $m" >> logs/wait.log; sleep 120
  done
  echo "$(date +%T) score $s r$r"
  NAME=p5-eval GPU=1 MEM=20g ./run5.sh eval5.py $s --run $r --bundle $b --out /p5/out/res5-$s-r$r.json --rows /p5/out/rows5-$s-r$r.json.gz $extra < /dev/null > logs/eval-$s-r$r.log 2>&1
  rc=$?
  if [ $rc -ne 0 ] || [ ! -s out/res5-$s-r$r.json ]; then echo "$(date +%T) score $s r$r FAILED rc=$rc"; touch out/fail-$s-r$r; return; fi
  MEM=4g ./run5.sh /lab/inc13.py --variants P2 --grouping G2 /p5/out/rows5-$s-r$r.json.gz < /dev/null > out/inc5-$s-r$r.json 2>> logs/eval-$s-r$r.log
  cp out/res5-$s-r$r.json out/inc5-$s-r$r.json $R/ && cp out/rows5-$s-r$r.json.gz $R/rows/ && cp logs/eval-$s-r$r.log $R/rows/
  if [ $r -ge 2 ]; then
    d=$V/paper5/$s/r$r
    cp $d/train5.json $R/train/train5-$s-r$r.json; cp $d/b07/calibration.json $R/train/calibration-$s-r$r.json
    cp logs/train-$s-r$r.log $R/train/ 2>/dev/null
    find $d/b07 -type f ! -name manifest.json ! -name calibration.json ! -name layers.json -delete
  fi
  echo "$(date +%T) scored $s r$r: $(grep -E 'P2:|alone' logs/eval-$s-r$r.log | cut -c10- | tr '\n' ' ')"
  python3 summ5.py > /dev/null 2>> logs/summ.err
}
while true; do
  [ -f STOP ] && { echo "$(date +%T) scorer STOP"; break; }
  did=0
  for s in $SETS; do for r in 2 3 4 5; do
    if [ -f $V/paper5/$s/r$r/train5.json ] && [ ! -f out/res5-$s-r$r.json ] && [ ! -f out/fail-$s-r$r ]; then score $s $r /data/paper5/$s/r$r/b07; did=1; break 2; fi
  done; done
  if [ $did = 0 ]; then for s in $SETS; do
    if [ ! -f out/res5-$s-r1.json ] && [ ! -f out/fail-$s-r1 ]; then score $s 1 $(run1 $s); did=1; break; fi
  done; fi
  if [ $did = 0 ]; then
    if [ ! -s queue.txt ] && [ -z "$(docker ps -q --filter name=p5-train)" ] && ! pgrep -f "lane.sh" > /dev/null; then echo "$(date +%T) scorer all done"; break; fi
    sleep 300
  fi
done
