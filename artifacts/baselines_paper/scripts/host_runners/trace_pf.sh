#!/bin/bash
R=/root/bl/pf/TRACE_E3; S=/root/Desktop/platform/artifacts/baselines_paper/scripts
until [ -f $R/trace_e3_merged.pt ] && [ -f $R/prepare_stats.json ]; do sleep 30; done
docker rm bl-pfprep-trace >/dev/null 2>&1
docker run --rm --gpus all --network shared_network -v /root/bl/conv/gt_trace_e3:/gt:ro -v $R:/out -v $S:/scripts:ro baselines-pids:1 python -u /scripts/pf_gt.py TRACE_E3 bl_trace_e3 --out /out/gt node_trace_e3_firefox_0410.csv node_trace_e3_phishing_executable_0413.csv node_trace_e3_pine_0413.csv > $R/gt.log 2>&1
W=$(docker run --rm --gpus all -v $R:/d:ro -v $S:/scripts:ro baselines-pids:1 python /scripts/pf_weights.py /d/trace_e3_merged.pt 2>/dev/null | tail -1)
echo "$W" > $R/weights.txt
HP="--num_hidden 64 --num_heads 8 --mask_rate 0.3 --lr 0.0015 --max_epoch 20 --max_epoch_f 50 --weight_decay 0.001 --weight_decay_f 1e-5 --lr_f 0.001"
for s in 1 2 3 4 5; do
  [ -f /root/bl/stop_trace ] && break
  /root/bl/pf_seed.sh TRACE_E3 $s 4 "$W" "$HP"; echo "$(date +%T) trace s$s done" >> /root/bl/pf_trace.log
done
