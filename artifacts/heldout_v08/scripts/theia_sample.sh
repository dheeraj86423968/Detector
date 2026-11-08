#!/bin/bash
# stride sample (every 40th event row, dump order) of theia_e5 event_table + the node rows they reference
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v08
O=$S/theia_sample
D() { docker run --rm --log-driver none -v /root/darpa/theia_e5/theia_e5.dump:/dump:ro --entrypoint pg_restore postgres:17 "$@"; }
D -a -t event_table -f - /dump 2>>$O/err | awk -F'\t' 'NF==8 && (++n % 40)==0' > $O/events.copy
echo "events sampled $(wc -l < $O/events.copy) $(date +%T)"
F=$O/nodes.fifo; rm -f $F; mkfifo $F
(D -a -t subject_node_table -t file_node_table -t netflow_node_table -f - /dump 2>>$O/err > $F) &
NAME=pdp-v08-theia-sample MEM=12g $S/run.sh -I /work/sample_nodes.py /work/theia_sample /work/theia_sample/nodes.fifo
rm -f $F; echo "SAMPLE DONE $(date +%T)"
