#!/bin/bash
# concur.sh: ATLASv2 h1 replay baseline trained alone, then 3 copies at once (same seeds) - wall times + bundle equality
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/cap
E=4bca479b-89e8-4104-9737-041f8a594a46; B=/data/bundles/$E/18adb787-5e60-4af4-b956-ce1ce48eed10
t0=$(date +%s); $S/runprof.sh solo $E $B; t1=$(date +%s); echo "solo $((t1-t0)) s"
for i in 1 2 3; do $S/runprof.sh par$i $E $B & sleep 2; done; wait; t2=$(date +%s); echo "3 at once $((t2-t1)) s"
