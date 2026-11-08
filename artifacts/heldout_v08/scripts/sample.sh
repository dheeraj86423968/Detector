#!/bin/bash
# sample.sh name dump stride : stride sample (every Nth event row, dump order) of event_table + the node rows they reference
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v08
n=$1; dump=$2; K=$3; O=$S/${n}_sample; mkdir -p $O
D() { docker run --rm --log-driver none -v $dump:/dump:ro --entrypoint pg_restore postgres:17 "$@"; }
D -a -t event_table -f - /dump 2>>$O/err | awk -F'\t' -v K=$K 'NF==8 && (++n % K)==0' > $O/events.copy
echo "events sampled $(wc -l < $O/events.copy) $(date +%T)"
F=$O/nodes.fifo; rm -f $F; mkfifo $F
(D -a -t subject_node_table -t file_node_table -t netflow_node_table -f - /dump 2>>$O/err > $F) &
NAME=pdp-v08-$n-sample MEM=12g $S/run.sh -I /work/sample_nodes.py /work/${n}_sample /work/${n}_sample/nodes.fifo
rm -f $F; echo "SAMPLE DONE $(date +%T)"
