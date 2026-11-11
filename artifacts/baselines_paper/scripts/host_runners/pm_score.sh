#!/bin/bash
# pm_score.sh SYSTEM DS SEED TESTDAYS GTROOT gt1 [gt2 ...]
sys=$1; ds=$2; s=$3; td=$4; gr=$5; shift 5
docker run --rm -v /root/bl/pm/dumps:/dumps:ro -v $gr:/gt:ro -v /root/Desktop/platform/artifacts/baselines_paper/scripts:/scripts:ro -v /root/Desktop/platform/artifacts/baselines_paper:/o baselines-pids:1 \
  python -u /scripts/pm_score.py /dumps/${sys}_${ds}_s$s --gt "$@" --out /o/results/${sys}_${ds}_s$s.json --scores /o/scores/${sys}_${ds}_s$s.csv.gz --test_days $td --label "$sys $ds seed $s"
