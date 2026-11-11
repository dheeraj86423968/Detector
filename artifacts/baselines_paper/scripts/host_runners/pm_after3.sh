#!/bin/bash
waitfree() { while [ "$(df --output=avail -B1 / | tail -1)" -lt $1 ]; do sleep 60; done; }
G5="E3-FIVEDIRECTIONS/node_fivedirections_e3_excel_0409.csv E3-FIVEDIRECTIONS/node_fivedirections_e3_firefox_0411.csv"
rm -rf /root/bl/pm/dumps/velox_FIVEDIRECTIONS_E3_s3 /root/bl/pm/dumps/velox_FIVEDIRECTIONS_E3_s4
MINFREE=27000000000 /root/bl/pm_queue_host.sh FIVEDIRECTIONS_E3 3 /root/PIDSMaker/Ground_Truth/orthrus "$G5" "velox:3 velox:4"
rm -rf /root/bl/pm/FIVEDIRECTIONS_E3
echo "$(date +%T) FiveDirections PIDSMaker block finished" >> /root/bl/pm/queue_hosts.log
for h in 1 2 3 4 5; do
  DS=CARBANAKV2_H$h; mkdir -p /root/bl/pm/$DS && chown 1000:1000 /root/bl/pm/$DS
  td=$(python3 -c "import json;print(len(json.load(open('/root/Desktop/platform/artifacts/baselines_paper/specs/pm_$DS.json'))['test_dates']))")
  PMNAME=TCFMT_$DS /root/bl/pm_queue_host.sh $DS $td /root/bl/conv/gt_carbanakv2_h$h "carbanakv2_edr.csv" "velox:0 orthrus_non_snooped:0 velox:1 orthrus_non_snooped:1 velox:2 orthrus_non_snooped:2"
  rm -rf /root/bl/pm/$DS
done
echo "$(date +%T) pm_after finished" >> /root/bl/pm/queue_hosts.log
