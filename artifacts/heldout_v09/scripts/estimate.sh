#!/bin/bash
# estimate.sh name dump days : fused-edge / disk estimate pass (estimate_size.py) before converting
W=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v09; SC=$(dirname $(readlink -f $0))
n=$1; dump=$2
F=$W/${n}_est.fifo; rm -f $F; mkfifo $F
(docker run --rm --log-driver none --name pdp-v09-$n-estfeed -v $dump:/dump:ro --entrypoint pg_restore postgres:17 -a -t event_table -f - /dump 2>>$W/${n}_est_feed.err | cut -s -f2,3,5,6,7 > $F) &
NAME=pdp-v09-$n-est MEM=16g $SC/run.sh /src/artifacts/heldout_v09/scripts/estimate_size.py /work/${n}_est.fifo /work/${n}_sizes.json $3 /work/${n}_estimate.json
echo "ESTIMATE EXIT $? $(date +%T)"; rm -f $F
