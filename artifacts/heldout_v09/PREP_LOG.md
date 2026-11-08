# Held-out data prep v09: CLEARSCOPE_E5 (data preparation only; no detector/model/Runtime/Trainer/scoring run, no alerts looked at)

Started 2026-11-08 17:08 UTC. Output: /data/heldout/CLEARSCOPE_E5/clearscope (host: /var/lib/docker/volumes/pdp_pdp_data/_data/heldout/CLEARSCOPE_E5/clearscope).
Scripts: /root/Desktop/platform/artifacts/heldout_v09/scripts/ (copies of the v08 THEIA_E5 pipeline, paths changed only).
Work files (FIFOs, survey/stats json, sample): /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v09/ (tmpfs).
Input: /root/darpa/clearscope_e5/clearscope_e5.dump (6,630,620,258 B, pg_dump custom format, verified ranged download 17:03).

## Split (fixed before any survey; given by the caller = PIDSMaker CLEARSCOPE_E5 lists, chronological, used as is)
train 2019-05-08,05-09,05-10,05-11,05-12 / val 2019-05-13 / test 2019-05-14,05-15,05-17 (05-16 PIDSMaker 'unused').
Day boundaries US/Eastern (PIDSMaker timezone US/Eastern; PostgresReplay). Host `clearscope`, platform `android`
(manifest platform field is a lower-case OS name: linux for TRACE_E3/THEIA_E5, windows for the EDR sets).
GT (PIDSMaker list): E5-CLEARSCOPE/node_clearscope_e5_appstarter_0515.csv, node_clearscope_e5_tester_0517.csv.
firefox_0517 (empty) and lockwatch_0517 (commented out in PIDSMaker's GT list, but it has an attack window 05-17 15:48-16:01)
recorded separately.

## Log
- 17:08 Schema check (pg_restore -l / -s, COPY headers): same 4 tables (event_table, subject/file/netflow_node_table),
  same columns in the same order as THEIA_E5 / TRACE_E3. Only difference vs THEIA_E5: event_table._id is bigint (THEIA: integer);
  _id is not used by heldout_stream (cut -f2,3,5,6,7) nor by PostgresReplay. heldout_stream applies unchanged.
  Observed: subject_node_table.path is NULL in the first rows (Android: exe in cmd only, e.g. /system/bin/app_process64);
  netflow dst_addr/dst_port NULL in the first rows. Both are carried exactly as PostgresReplay does (str(None) = 'None').
- 17:10-17:17 Survey (`scripts/survey_stream.sh clearscope_e5 <dump> 2019-05-07 2019-05-18 <train+val> <test>`):
  198,794,211 event rows; 5,271,926 outside 05-07..05-18 US/Eastern or NULL timestamp; 0 exactly-midnight, 0 bad uuid,
  0 non-canonical index ids. Strict op map drops nothing (only READ/OPEN/WRITE/CONNECT/RECVFROM/SENDMSG/RECVMSG/SENDTO/
  CLONE/EXECUTE present). Very few process events: EVENT_CLONE 644, EVENT_EXECUTE 28 in the whole dump (Android/ClearScope).
  Kept (= raw, nothing dropped) events per US/Eastern day:
  | day | kept | role |
  |---|---|---|
  | 05-07 | 36,006,543 | before PIDSMaker start_date, unused |
  | 05-08 | 25,872,679 | train |
  | 05-09 | 35,376,236 | train |
  | 05-10 | 4,330,822 | train |
  | 05-11 | 512,119 | train (Sat; ~1.5-2% of 05-08/05-09) |
  | 05-12 | 502,322 | train (Sun; ~1.5-2% of 05-08/05-09) |
  | 05-13 | 10,692,100 | val |
  | 05-14 | 11,110,686 | test |
  | 05-15 | 20,117,731 | test |
  | 05-16 | 27,794,111 | PIDSMaker unused |
  | 05-17 | 17,325,168 | test |
  | 05-18 | 3,881,768 | after end, unused |
  Referenced index ids: base 226,438, test 150,964 (109,017 test-only), any 335,455.
  No split day is empty. 05-11 and 05-12 are small (~0.5M each) but not empty; split NOT changed (fixed rule); flagged.
- Disk risk: THEIA_E5 stores took ~78 B per kept event (176 B per fused edge: src/dst/t/etype int64 + uuid <U36, npz
  uncompressed). 125.3M kept events here could need up to ~22 GB unfused (31 GB free, 25 GB floor). Added a counting-only
  estimate pass (`scripts/estimate.sh` / `estimate_size.py`: converter's collect_days + WindowBuilder chunk rule + fuse
  run-counting; no content stored) to size the output before converting. Run in parallel with the stride sample (stride 40).
- 17:18-17:26 Estimate pass (`scripts/estimate.sh`, counting only): per day kept events / windows / estimated fused edges / bytes:
  05-08 25,872,679 / 96 / 7,686,531 / 1.26 GiB; 05-09 35,376,236 / 96 / 9,789,259 / 1.60 GiB; 05-10 4,330,822 / 92 / 1,399,201 / 0.23 GiB;
  05-11 512,119 / 84 / 92,460 / 15 MiB; 05-12 502,322 / 82 / 87,970 / 15 MiB; 05-13 10,692,100 / 91 / 3,026,319 / 0.50 GiB;
  05-14 11,110,686 / 95 / 3,338,545 / 0.55 GiB; 05-15 20,117,731 / 96 / 5,787,700 / 0.95 GiB; 05-17 17,325,168 / 96 / 5,359,204 / 0.88 GiB.
  Total windows 5.99 GiB + registries ~0.1 GiB (registry ~335K entities) = ~6.1 GiB on / (pdp_pdp_data volume).
- 17:18-17:26 Stride sample (`scripts/sample.sh clearscope_e5 <dump> 40`): 4,969,855 event rows (every 40th, all days) + 163,888
  referenced node rows (subject 61,153, file 95,335, netflow 7,400), in the tmpfs work dir.
- 17:27-17:28 Verification (`scripts/verify_stream.sh`, verify stores in the tmpfs work dir instead of pdp_data to save disk):
  sample loaded as research-postgres database clearscope_e5_sample; heldout_prep build (PostgresReplay + ingest_day) vs
  heldout_stream on the same split -> compare_stores **EQUIVALENT** (baseline registry 70,306 identical, eval-test 110,710 identical,
  every window array identical on all 9 days: 05-08 83 windows/161,546 edges ... 05-17 75/117,155; dropped_unknown_entity 0).
  17:29 database clearscope_e5_sample dropped, sample dir deleted (no other database touched).
- 17:29 GT lookup against the survey's referenced ids (`scripts/gt_projection.py`; the eval-test registry = referenced ids of the
  base+test days that have a node row; 0 missing node rows in the sample): appstarter_0515 26/26 referenced on test days;
  tester_0517 8/8; (not in PIDSMaker list) lockwatch_0517 17/17, firefox_0517 1/1. firefox_0517.csv is NOT empty: 1 row
  (193720, profiles.ini) without a trailing newline (wc -l = 0). The lockwatch nodes are attack activity on 05-17 that the
  PIDSMaker GT does not label (they would count as false positives under the PIDSMaker GT) -> flagged in the manifest script.

### CLEARSCOPE_E5 — NOT CONVERTED (disk floor) 17:30
- Free on / at 17:30: 32,217,956,352 B = 30.0 GiB (df -h "31G"; it dipped to 28.9 GiB at 17:26, pdp-backup wrote a 1.97 GB
  backup at 17:22, then recovered; not this prep). Conversion needs ~6.1 GiB -> ~23.9 GiB left, below the 25 GB floor (also the
  converter's own --min-free-gb 26 check would abort before 05-15/05-17). Per the hard rule: stopped before converting.
- Ready to run once >= 32 GiB is free: `scripts/finish.sh` (checks >= 32 GiB free and no existing output dir, then
  convert_stream.sh with 2 passes [baseline 77.3M kept events, test 48.6M; budget 120M] -> manifest_clearscope.sh
  [heldout_stream manifest, platform android, flags/notes/verified text above] -> manifest_extra_gt.py adds
  ground_truth_not_in_pidsmaker_list [firefox_0517, lockwatch_0517]). Survey/sizes/ref files are kept in
  artifacts/heldout_v09/surveys/ (the work dir is tmpfs) and re-staged by finish.sh.
- Nothing written to /data/heldout/CLEARSCOPE_E5 (directory not created). Dump untouched.
