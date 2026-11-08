#!/bin/bash
# finish.sh : convert + manifest for CLEARSCOPE_E5, only if / has room for the estimated output above the 25 GiB floor.
# Estimate (estimate_size.py): 6.0 GiB of windows + ~0.1 GiB registries; requires >= 32 GiB free on / to start.
# The survey/ref/sizes files are re-staged from artifacts/heldout_v09/surveys into the (tmpfs) work dir if missing.
W=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v09; SC=$(dirname $(readlink -f $0)); A=$(dirname $SC)
mkdir -p $W; for f in clearscope_e5_survey.json clearscope_e5_sizes.json clearscope_e5_ref.npz; do [ -f $W/$f ] || cp $A/surveys/$f $W/; done
free=$(df -B1 --output=avail / | tail -1); need=$((32 * 1024**3))
if [ "$free" -lt "$need" ]; then echo "NOT STARTED: $((free / 1024**3)) GiB free on /, need >= 32 GiB (6.1 GiB output + 25 GiB floor + margin)"; exit 2; fi
[ -e /var/lib/docker/volumes/pdp_pdp_data/_data/heldout/CLEARSCOPE_E5/clearscope ] && { echo "output dir exists; remove it first"; exit 3; }
$SC/convert_stream.sh clearscope_e5 /root/darpa/clearscope_e5/clearscope_e5.dump CLEARSCOPE_E5 clearscope \
  2019-05-08,2019-05-09,2019-05-10,2019-05-11,2019-05-12 2019-05-13 2019-05-14,2019-05-15,2019-05-17 2 | tee $W/cs_conv.log
grep -q "CONVERTER EXIT 0" $W/cs_conv.log || exit 1
$SC/manifest_clearscope.sh | tee $W/cs_manifest.log
cp $W/clearscope_e5_stats.json $W/cs_conv.log $W/cs_manifest.log $A/surveys/
df -h /
