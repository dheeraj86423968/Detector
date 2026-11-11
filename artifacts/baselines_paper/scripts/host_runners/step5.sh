#!/bin/bash
S=/root/Desktop/platform/artifacts/baselines_paper/scripts; P=/root/Desktop/platform/artifacts/baselines_paper
until grep -q "FiveDirections PIDSMaker block finished" /root/bl/pm/queue_hosts.log; do sleep 60; done
for D in THEIA_E3 OPTC_h051; do
  R=/root/bl/pf/$D; ds=$(echo $D | tr A-Z a-z); DB=""; [ $D = OPTC_h051 ] && DB="--db optc_051"
  while [ "$(df --output=avail -B1 / | tail -1)" -lt 30000000000 ]; do sleep 60; done
  docker run --rm --name bl-pfprep-$ds --gpus all --network shared_network -m 28g --oom-score-adj 800 --shm-size 4g -v /root/ProvFusion:/pf:ro -v $R:/out -v $S:/scripts:ro baselines-pids:1 python -u /scripts/pf_prepare.py $D --out /out $DB > $R/prep.log 2>&1
  echo "$(date +%T) $D prepared" >> /root/bl/pf_step5.log
done
HT="--num_hidden 64 --num_heads 8 --mask_rate 0.3 --lr 0.0015 --max_epoch 20 --max_epoch_f 50 --weight_decay 0.001 --weight_decay_f 1e-5 --lr_f 0.001"
HO="--num_hidden 64 --num_heads 8 --mask_rate 0.5 --lr 0.0015 --max_epoch 500 --max_epoch_f 10 --weight_decay 1e-4 --weight_decay_f 5e-5 --lr_f 0.0005"
for s in 1 2 3; do
  for D in THEIA_E3 OPTC_h051; do
    [ -f /root/bl/stop_step5 ] && exit
    R=/root/bl/pf/$D; ds=$(echo $D | tr A-Z a-z); HP=$HT; td=3; [ $D = OPTC_h051 ] && HP=$HO
    /root/bl/pf_seed.sh $D $s $td "" "$HP"
    f=$(ls $R/runs/s$s/save_middle_results/*.pt | head -1)
    docker run --rm --gpus all -v /root/ProvFusion:/pf:ro -v $R:/d:ro -v $S:/scripts:ro -v $P:/o baselines-pids:1 python -u /scripts/pf_score.py \
      /d/runs/s$s/save_middle_results/$(basename $f) /d/${ds}_merged.pt /d/gt_orthrus/${D}_gt_nids.pt /d/gt_orthrus/${D}_attack_to_nids.pt \
      --out /o/results/provfusion_${D}-ORTHRUSGT_s$s.json --label "ProvFusion $D seed$s, ORTHRUS labels" --test_days $td > $R/runs/s$s/score_orthrus.log 2>&1
    echo "$(date +%T) $D s$s done" >> /root/bl/pf_step5.log
  done
done
