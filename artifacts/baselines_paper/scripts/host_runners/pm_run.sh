#!/bin/bash
# pm_run.sh SYSTEM DS SEED : one PIDSMaker run with disk hygiene (keep only the newest epoch's edge losses)
sys=$1; ds=$2; s=$3; A=/root/bl/pm/$ds; name=bl-pm-$sys-$ds-s$s; PMNAME=${PMNAME:-$ds}
while [ "$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1)" -lt 12288 ] || [ "$(free -g | awk "/Mem:/{print \$7}")" -lt 12 ] || [ "$(docker ps --format "{{.Names}}" | grep -c "^bl-pm-\|^bl-pf-[a-z]")" -ge 2 ]; do sleep 30; done
docker run -d --name $name --gpus all --network shared_network -m ${MEM:-28g} --memory-swap ${MEM:-28g} --oom-score-adj 800 --shm-size 8g -w /tmp -e WANDB_MODE=disabled \
  -v /root/PIDSMaker:/pids:ro -v $A:/home/artifacts -v /root/bl/pm/dumps:/dumps -v /root/bl/conv:/conv:ro \
  -v /root/Desktop/platform/artifacts/baselines_paper/scripts:/scripts:ro -v /root/Desktop/platform/artifacts/baselines_paper/specs:/specs:ro \
  baselines-pids:1 python -u /scripts/pm_run.py --dump /dumps/${sys}_${ds}_s$s --spec /specs/pm_$ds.json -- $sys $PMNAME --training.seed=$s >/dev/null
docker wait $name > /root/bl/pm/exit_$name.txt 2>&1 &
WP=$!
while kill -0 $WP 2>/dev/null; do
  for d in $A/training/training/*/*/edge_losses/val $A/training/training/*/*/edge_losses/test; do
    [ -d "$d" ] || continue
    ls $d | sort -t_ -k3 -n | head -n -1 | while read e; do rm -rf "$d/$e"; done
  done
  sleep 20
done
docker logs $name > /root/bl/pm/logs_$name.txt 2>&1; docker rm $name >/dev/null
