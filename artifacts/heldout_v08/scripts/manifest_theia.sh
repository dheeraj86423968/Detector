#!/bin/bash
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v08
NAME=pdp-v08-theia-man MEM=12g $S/run.sh -m pdp_server.tools.heldout_stream manifest --out /data/heldout/THEIA_E5/theia \
  --dataset THEIA_E5 --host theia --platform linux --dump /root/darpa/theia_e5/theia_e5.dump \
  --train 2019-05-08,2019-05-09,2019-05-10 --val 2019-05-11 --test 2019-05-14,2019-05-15 \
  --stats /work/theia_e5_stats.json --survey /work/theia_e5_survey.json --referenced /work/theia_e5_ref.npz \
  --gt E5-THEIA/node_THEIA_1_Firefox_Drakon_APT_BinFmt_Elevate_Inject.csv \
  --split-note "PIDSMaker lists are chronological (train 05-08,05-09,05-10 < val 05-11 < test 05-14,05-15) -> used as is (rule fixed before the survey; TRACE_E3 precedent). PIDSMaker 'unused' days 05-12, 05-13, 05-16, 05-17 and the day before its start_date (05-07) are in neither store." \
  --flags "only 3 training days (PIDSMaker list);val day 05-11 is not directly before the first test day (05-12 and 05-13, 3.2M / 4.2M kept events, PIDSMaker-unused, are skipped);2019-05-07 has 57.7M kept events but is before PIDSMaker's start_date 05-08 and is not used" \
  --verified "verified identical to PostgresReplay + ingest_day (heldout_prep build) on a 3,524,866-row stride sample of this dump (every 40th event_table row, all days, + the 695,313 node rows it references; database theia_e5_sample; registries and every window array identical, same train/val/test days)" \
  --notes "DARPA TC E5 THEIA (Linux, THEIA recorder): 140,994,662 event rows, no NULL/out-of-range timestamps, all event uuids canonical;strict TC map drops EVENT_EXIT, EVENT_CHANGE_PRINCIPAL, EVENT_UNLINK, EVENT_MODIFY_FILE_ATTRIBUTES, EVENT_BOOT, EVENT_MPROTECT (1.26M rows);EXECUTE and CLONE present; RECVFROM/SENDTO as well as RECVMSG/SENDMSG;database not restored (stream); only the 1.55M nodes referenced by kept events of the prepared days are in the registries"
echo "MANIFEST EXIT $?"
