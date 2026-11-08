#!/bin/bash
# survey_stream.sh name dump first last base test   (v08 survey_stream.sh, v09 paths)
W=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v09; SC=$(dirname $(readlink -f $0))
n=$1; dump=$2
F=$W/${n}_ev.fifo; rm -f $F; mkfifo $F
(docker run --rm --log-driver none --name pdp-v09-$n-feed -v $dump:/dump:ro --entrypoint pg_restore postgres:17 -a -t event_table -f - /dump 2>>$W/${n}_feed.err | cut -s -f2,3,5,6,7 > $F; echo "feed done $(date +%T)" >> $W/${n}_feed.err) &
NAME=pdp-v09-$n-survey MEM=16g $SC/run.sh -m pdp_server.tools.heldout_stream survey --events /work/${n}_ev.fifo \
  --first-day $3 --last-day $4 --base $5 --test $6 --out-prefix /work/$n
echo "SURVEY EXIT $? $(date +%T)"; rm -f $F
