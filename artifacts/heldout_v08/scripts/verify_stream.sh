#!/bin/bash
# verify_stream.sh name first last train val test gt : database path vs stream path on <name>_sample
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v08
n=$1; O=$S/${n}_sample; V=/data/heldout_verify_v08/$n
rm -rf /var/lib/docker/volumes/pdp_pdp_data/_data/heldout_verify_v08/$n
NAME=pdp-v08-$n-load MEM=8g $S/run.sh -I /work/load_sample.py ${n}_sample /work/${n}_sample || exit 1
cut -s -f2,3,5,6,7 $O/events.copy > $O/events.cut
NAME=pdp-v08-$n-vdb MEM=16g $S/run.sh -m pdp_server.tools.heldout_prep build --database ${n}_sample --out $V/db \
  --dataset VERIFY --host h --platform linux --train $4 --val $5 --test $6 --gt "$7" || exit 1
NAME=pdp-v08-$n-vsurvey MEM=8g $S/run.sh -m pdp_server.tools.heldout_stream survey --events /work/${n}_sample/events.cut \
  --first-day $2 --last-day $3 --base $4,$5 --test $6 --out-prefix /work/${n}_sample/s || exit 1
NAME=pdp-v08-$n-vstream MEM=16g $S/run.sh -m pdp_server.tools.heldout_stream --nodes /work/${n}_sample/nodes.stream \
  --events /work/${n}_sample/events.cut --referenced /work/${n}_sample/s_ref.npz --out $V/stream/h \
  --train $4 --val $5 --test $6 --day-sizes /work/${n}_sample/s_sizes.json --stats /work/${n}_sample/s_stats.json || exit 1
NAME=pdp-v08-$n-vcmp MEM=8g $S/run.sh /work/compare_stores.py $V/db/h $V/stream/h
