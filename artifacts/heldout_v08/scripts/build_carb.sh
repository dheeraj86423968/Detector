#!/bin/bash
S=/tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v08
GT=carbanakv2_edr/carbanakv2_edr.csv
RULE="PIDSMaker lists (train 04-20,04-21,04-23..04-25,04-27..04-29; val 04-22,04-26; test 04-30..05-02,05-07..05-10) are not chronological -> fallback rule (fixed before the survey): test = every US/Eastern day with events of this host from the first to the last ground-truth attack day (PIDSMaker attack window 2024-04-30 17:30 .. 2024-05-10 20:30 US/Central = 04-30 .. 05-10 US/Eastern; contiguous, as a live product sees it); val = the latest day with events of this host before the first test day; train = up to 7 days with events of this host directly before val. Applied per host (hosts have different day coverage)."
NOTES="Carbon Black EDR record: process exe = lower-cased image path (c:\\...), cmdline as recorded (some empty);file nodes include registry keys/values (HKLM\\..., HKU\\...);flows carry local and remote address/port;process creation = PROCESS_EXECUTED parent->child (mapped to CLONE), no EXECUTE edges (no executable file node);MODULE_LOADED (DLL loads) mapped to READ;FILE_CLOSED, NETFLOW_DISCONNECTED, PROCESS_KILLED, REGISTRY_KEY_CLOSED/UNLOADED dropped;host attribution by graph component (no host column in the database): 5 attributed components, 18,834 small unattributed components (37,823 nodes) left out"
b() { # host key platform train val test flags
  rm -rf /var/lib/docker/volumes/pdp_pdp_data/_data/heldout/CARBANAKV2_EDR/$1
  NAME=pdp-v08-carb-$1 MEM=20g $S/run.sh -m pdp_server.tools.heldout_prep build --edr --database carbanakv2_edr --out /data/heldout/CARBANAKV2_EDR \
    --dataset CARBANAKV2_EDR --host $1 --host-key $2 --platform windows --train $3 --val $4 --test $5 \
    --gt "$GT" --split-note "$RULE" --flags "$6" --notes "$NOTES;host $1 = graph component with local address $2"
  echo "BUILD $1 exit $? $(date +%T)"; df -h / | tail -1
}
b h1 10.195.75.103 2024-04-21,2024-04-22,2024-04-23,2024-04-24,2024-04-25,2024-04-26,2024-04-28 2024-04-29 2024-04-30,2024-05-01,2024-05-02,2024-05-03,2024-05-06,2024-05-07,2024-05-08,2024-05-09 "train day 2024-04-21 has only 286 mapped events (data starts late);no events on 04-27, 05-04, 05-05, 05-10 for this host"
b h2 10.195.78.253 2024-04-20,2024-04-23 2024-04-29 2024-04-30,2024-05-01,2024-05-02,2024-05-03,2024-05-06,2024-05-07,2024-05-08,2024-05-09,2024-05-10 "short baseline: only one substantial training day (04-23, 1.14M mapped events); 04-20 has 51 events;no events 04-21,04-22,04-24..04-28,05-04,05-05 for this host"
b h3 10.192.90.48 2024-04-19,2024-04-20,2024-04-22,2024-04-23,2024-04-24,2024-04-25,2024-04-26 2024-04-27 2024-04-30,2024-05-01,2024-05-02,2024-05-06,2024-05-07,2024-05-08,2024-05-09 "no events 04-21,04-28,04-29,05-03..05-05,05-10 for this host (val 04-27 is 3 days before the first test day)"
b h4 10.192.101.45 2024-04-18,2024-04-22,2024-04-24,2024-04-25,2024-04-26 2024-04-29 2024-04-30,2024-05-01,2024-05-02,2024-05-07,2024-05-08,2024-05-09,2024-05-10 "only 5 training days with events (all earlier days of this host);no events 04-19..04-21,04-23,04-27,04-28,05-03..05-06 for this host"
b h5 130.126.136.46 2024-04-22,2024-04-23,2024-04-24,2024-04-25,2024-04-26,2024-04-27,2024-04-28 2024-04-29 2024-04-30,2024-05-01,2024-05-02,2024-05-03,2024-05-04,2024-05-05,2024-05-06,2024-05-07,2024-05-08,2024-05-09,2024-05-10 "small host (5-20k mapped events/day)"
echo CARB-DONE
