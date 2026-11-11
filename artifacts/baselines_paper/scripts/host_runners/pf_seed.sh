#!/bin/bash
# pf_seed.sh DS seed testdays weights "<hyperparameter args>"
while [ "$(docker ps --format "{{.Names}}" | grep -c "^bl-pm-\|^bl-pf-[a-z]")" -ge 2 ] || [ "$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1)" -lt 12288 ] || [ "$(free -g | awk "/Mem:/{print \$7}")" -lt 12 ]; do sleep 30; done
DS=$1; s=$2; td=$3; W=$4; HP=$5; R=/root/bl/pf/$DS; ds=$(echo $DS | tr A-Z a-z)
P=/root/Desktop/platform/artifacts/baselines_paper
mkdir -p $R/runs/s$s && cp $R/gt/${DS}_attack_to_nids.pt $R/runs/s$s/ && chown -R 1000:1000 $R/runs/s$s
WA=""; [ -n "$W" ] && WA="--weights $W"
docker run --rm --name bl-pf-$ds-s$s --gpus all -m 28g --oom-score-adj 800 --shm-size 8g -v /root/ProvFusion:/pf:ro -v $R:/d -v $P/scripts:/scripts:ro baselines-pids:1 \
  python -u /scripts/pf_train.py --rundir /d/runs/s$s $WA -- --device 0 --dataset $DS --data_path /d/${ds}_merged.pt --ground_truth_path /d/gt/${DS}_gt_nids.pt \
  --encoder gatedge --decoder gat --loss_fn sce --optimizer adam --num_layers 2 --in_drop 0.2 --attn_drop 0.1 --replace_rate 0.0 --activation prelu \
  --linear_prob --scheduler --use_cfg --seeds $s --normalization_method percentile --alpha_l 3 --drop_edge_rate 0.0 $HP > $R/runs/s$s/train.log 2>&1
echo "exit $?" >> $R/runs/s$s/train.log
grep -a "Final Voted (\|The adp score" $R/runs/s$s/train.log > $P/results/provfusion_${DS}_s${s}_printed.txt
f=$(ls $R/runs/s$s/save_middle_results/*.pt 2>/dev/null | head -1)
[ -z "$f" ] && { echo "no results for $DS s$s"; exit 1; }
docker run --rm --gpus all -v /root/ProvFusion:/pf:ro -v $R:/d:ro -v $P/scripts:/scripts:ro -v $P:/o baselines-pids:1 python -u /scripts/pf_score.py \
  /d/runs/s$s/save_middle_results/$(basename $f) /d/${ds}_merged.pt /d/gt/${DS}_gt_nids.pt /d/gt/${DS}_attack_to_nids.pt --out /o/results/provfusion_${DS}_s$s.json \
  --label "ProvFusion $DS seed$s" --scores /o/scores/provfusion_${DS}_s$s.csv.gz --test_days $td > $R/runs/s$s/score.log 2>&1
