#!/bin/bash
# convert_stream.sh name dump DATASET host train val test passes
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v08
n=$1; dump=$2; DS=$3; H=$4; P=$8
NF=$S/${n}_nodes.fifo; EF=$S/${n}_events.fifo; rm -f $NF $EF; mkfifo $NF $EF
D() { local c=$1; shift; docker run --rm --log-driver none --name $c -v $dump:/dump:ro --entrypoint pg_restore postgres:17 "$@"; }
(D pdp-v08-$n-nodes -a -t subject_node_table -t file_node_table -t netflow_node_table -f - /dump 2>>$S/${n}_conv_feed.err > $NF) &
(for i in $(seq 1 $P); do D pdp-v08-$n-ev$i -a -t event_table -f - /dump 2>>$S/${n}_conv_feed.err | cut -s -f2,3,5,6,7 > $EF; echo "feed pass $i done $(date +%T)" >> $S/${n}_conv_feed.err; done) &
NAME=pdp-v08-$n-conv MEM=20g $S/run.sh -m pdp_server.tools.heldout_stream --nodes /work/${n}_nodes.fifo --events /work/${n}_events.fifo \
  --referenced /work/${n}_ref.npz --out /data/heldout/$DS/$H --train $5 --val $6 --test $7 \
  --day-sizes /work/${n}_sizes.json --stats /work/${n}_stats.json --pass-budget 120000000 --min-free-gb 26
echo "CONVERTER EXIT $? $(date +%T)"; rm -f $NF $EF
