#!/bin/bash
# verify_stream.sh name first last train val test gt : database path (heldout_prep build = PostgresReplay + ingest_day)
# vs stream path (heldout_stream) on database <name>_sample.  (v08 verify_stream.sh; v09 paths; the verify stores go to the tmpfs
# work dir (disk headroom) and are deleted after the comparison)
W=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v09; SC=$(dirname $(readlink -f $0)); P=/src/artifacts/heldout_v09/scripts
n=$1; O=$W/${n}_sample; V=/work/${n}_sample/verify
rm -rf $O/verify
NAME=pdp-v09-$n-load MEM=8g $SC/run.sh -I $P/load_sample.py ${n}_sample /work/${n}_sample || exit 1
cut -s -f2,3,5,6,7 $O/events.copy > $O/events.cut
NAME=pdp-v09-$n-vdb MEM=16g $SC/run.sh -m pdp_server.tools.heldout_prep build --database ${n}_sample --out $V/db \
  --dataset VERIFY --host h --platform android --train $4 --val $5 --test $6 --gt "$7" || exit 1
NAME=pdp-v09-$n-vsurvey MEM=8g $SC/run.sh -m pdp_server.tools.heldout_stream survey --events /work/${n}_sample/events.cut \
  --first-day $2 --last-day $3 --base $4,$5 --test $6 --out-prefix /work/${n}_sample/s || exit 1
NAME=pdp-v09-$n-vstream MEM=16g $SC/run.sh -m pdp_server.tools.heldout_stream --nodes /work/${n}_sample/nodes.stream \
  --events /work/${n}_sample/events.cut --referenced /work/${n}_sample/s_ref.npz --out $V/stream/h \
  --train $4 --val $5 --test $6 --day-sizes /work/${n}_sample/s_sizes.json --stats /work/${n}_sample/s_stats.json || exit 1
NAME=pdp-v09-$n-vcmp MEM=8g $SC/run.sh -I $P/compare_stores.py $V/db/h $V/stream/h
