#!/bin/bash
S=/root/Desktop/platform/artifacts/baselines_paper/scripts; SP=/root/Desktop/platform/artifacts/baselines_paper/specs
HP="--num_hidden 64 --num_heads 2 --mask_rate 0.5 --lr 0.0015 --max_epoch 500 --max_epoch_f 10 --weight_decay 1e-4 --weight_decay_f 2e-6 --lr_f 0.001"
for h in 1 2 3 4 5; do
  DS=CARBANAKV2_H$h; R=/root/bl/pf/$DS; ds=$(echo $DS | tr A-Z a-z); mkdir -p $R && chown 1000:1000 $R
  [ -f $R/${ds}_merged.pt ] || docker run --rm --name bl-pfprep-carb$h --gpus all --network shared_network -m 28g --oom-score-adj 800 --shm-size 4g -v /root/ProvFusion:/pf:ro -v $R:/out -v $S:/scripts:ro -v $SP:/specs:ro baselines-pids:1 python -u /scripts/pf_prepare.py $DS --out /out --spec /specs/pf_$DS.json > $R/prep.log 2>&1
  docker run --rm --gpus all --network shared_network -v /root/bl/conv/gt_carbanakv2_h$h:/gt:ro -v $R:/out -v $S:/scripts:ro baselines-pids:1 python -u /scripts/pf_gt.py $DS bl_carbanakv2_h$h --out /out/gt carbanakv2_edr.csv > $R/gt.log 2>&1
  W=$(docker run --rm --gpus all -v $R:/d:ro -v $S:/scripts:ro baselines-pids:1 python /scripts/pf_weights.py /d/${ds}_merged.pt 2>/dev/null | tail -1); echo "$W" > $R/weights.txt
  echo "$(date +%T) $DS prepared" >> /root/bl/pf_carb.log
done
for s in 1 2 3; do for h in 1 2 3 4 5; do
  [ -f /root/bl/stop_carb ] && exit
  DS=CARBANAKV2_H$h; R=/root/bl/pf/$DS; td=$(python3 -c "import json;print(len(json.load(open('$SP/pm_$DS.json'))['test_dates']))")
  /root/bl/pf_seed.sh $DS $s $td "$(cat $R/weights.txt)" "$HP"; echo "$(date +%T) $DS s$s done" >> /root/bl/pf_carb.log
done; done
