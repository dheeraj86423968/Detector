# Held-out data prep v08 (data preparation only; no detector run, no detector output looked at)

Started 2026-11-08 08:20 UTC. Output root /data/heldout/<DATASET>/ (host: /var/lib/docker/volumes/pdp_pdp_data/_data/heldout/).
Scripts: /tmp/claude-0/-root-Desktop/23340b6f-b435-453c-8f8c-05b5fcb54d98/scratchpad/v08/

## Split rules (fixed 08:25, before any survey; only PIDSMaker config + ground-truth attack windows read)

Source: /root/PIDSMaker/pidsmaker/config/config.py. Day boundaries: US/Eastern calendar days (PostgresReplay and
PIDSMaker build_default_graphs, which uses US/Eastern for every dataset whose timezone is not UTC).

Generic rule: if PIDSMaker's train/val/test lists are chronological (max train < val < min test) use them as is
(TRACE_E3 precedent). Otherwise fallback: test = every calendar day with events from the first to the last
ground-truth attack day (attack_to_time_window, converted to US/Eastern days; contiguous, as a live product sees it);
val = latest day with events directly before the first test day; train = up to 7 days with events directly before val.

- CARBANAKV2_EDR: PIDSMaker lists NOT chronological (val 04-22, 04-26 interleaved with train 04-20..04-29) -> fallback.
  Attack window 2024-04-30 17:30 .. 2024-05-10 20:30 US/Central = 18:30 / 21:30 US/Eastern -> attack days 04-30 .. 05-10.
  test = days with events in 2024-04-30 .. 2024-05-10; val = 2024-04-29 (if it has events, else the latest earlier day
  with events); train = the 7 days with events before val (expected 04-22 .. 04-28). Hosts = connected components
  (heldout_prep partition), one host dir per attributed component, as ATLASV2_EDR. Ground truth: carbanakv2_edr.csv.
- THEIA_E5: PIDSMaker lists chronological (train 05-08,05-09,05-10 < val 05-11 < test 05-14,05-15) -> used as is.
  (05-12, 05-13, 05-16, 05-17 are PIDSMaker 'unused'.) GT: E5-THEIA/node_THEIA_1_Firefox_Drakon_APT_BinFmt_Elevate_Inject.csv
- CADETS_E5: chronological (train 05-08,05-09,05-11 < val 05-12 < test 05-16,05-17) -> used as is.
  GT: E5-CADETS/node_Nginx_Drakon_APT.csv, node_Nginx_Drakon_APT_17.csv
- CLEARSCOPE_E5: chronological (train 05-08..05-12 < val 05-13 < test 05-14,05-15,05-17) -> used as is.
  GT: PIDSMaker list = node_clearscope_e5_appstarter_0515.csv, node_clearscope_e5_tester_0517.csv
  (firefox_0517 is empty, lockwatch_0517 commented out in PIDSMaker; recorded separately in the manifest if present).

## Log
- 08:20 Drive folder listed (embeddedfolderview). File ids: carbanakv2_edr 1rJN9F8JkmqMAV9zUjralcFB5wykAgLnd (1,178,382,514 B),
  theia_e5 1Q0rCCj2KnJeOqJN2NcmHnDBF1sl33g9x (6,187,437,078 B), cadets_e5 1Xiq7w0Ofz4jZG2PVFuNqi_i0fm28kRcT (38,031,603,978 B),
  clearscope_e5 1zfQBbpIRIqo5EugAT5Ou0354Ii_naINC (6,630,620,258 B).
- 08:21 Downloads via drive.usercontent.google.com/download?id=..&export=download&confirm=t in verified 512 MB ranges
  (each range must be HTTP 206 application/octet-stream of the exact length before it is appended; v08/dl.sh). No quota
  block this time. carbanakv2_edr complete 08:21:32 -> /root/darpa/carbanakv2_edr/carbanakv2_edr.dump.
- 08:23 theia_e5 complete -> /root/darpa/theia_e5/theia_e5.dump.
- 08:24 CARBANAKV2_EDR restored into research postgres as database `carbanakv2_edr` (6.5 GB; 17,143,304 events; schema identical
  to atlasv2_edr). `heldout_prep partition` -> 5 attributed hosts (10.195.75.103, 10.195.78.253, 10.192.90.48, 10.192.101.45,
  130.126.136.46) + 18,834 tiny unattributed components (37,823 nodes). `heldout_prep survey --edr` -> day_survey.json.
  Hosts have different day coverage, so the fallback rule is applied per host (see manifests). Builds started 08:25.
- 08:27 cadets_e5 download hit "Google Drive - Quota exceeded" at 14.5/38.0 GB; dl.sh keeps retrying with backoff
  (60 s doubling to 30 min, max 40 attempts). clearscope_e5 started in parallel 08:30: also quota-blocked, backing off.
- 08:28 THEIA_E5 dump schema checked (pg_restore -s / COPY headers): same 4 tables, same columns in the same order as
  TRACE_E3/PostgresReplay expect (event_table src_node, src_index_id, operation, dst_node, dst_index_id, event_uuid,
  timestamp_rec, _id; subject node_uuid, hash_id, path, cmd, index_id; file ..., path, index_id; netflow ..., src_addr,
  src_port, dst_addr, dst_port, index_id). No schema extension needed. Decision: stream (restore ~36 GB would not leave
  25 GB free alongside the E5 downloads).
- heldout_stream.py extended (generic): `survey` subcommand (the counting pass that was a scratch script for TRACE),
  manifest `--flags` and `--verified` (the database-field verification text was hard-coded to the TRACE sample).

### CARBANAKV2_EDR — READY 08:37 (/data/heldout/CARBANAKV2_EDR/h1..h5)
Commands: `v08/build_carb.sh` = per host `heldout_prep build --edr --database carbanakv2_edr --out /data/heldout/CARBANAKV2_EDR
--dataset CARBANAKV2_EDR --host hN --host-key <addr> --platform windows --train .. --val .. --test .. --gt carbanakv2_edr/carbanakv2_edr.csv`.
| host | partition key | train | val | test |
|---|---|---|---|---|
| h1 | 10.195.75.103 | 04-21,04-22,04-23,04-24,04-25,04-26,04-28 | 04-29 | 04-30,05-01,05-02,05-03,05-06,05-07,05-08,05-09 |
| h2 | 10.195.78.253 | 04-20,04-23 (flag: short baseline) | 04-29 | 04-30,05-01,05-02,05-03,05-06,05-07,05-08,05-09,05-10 |
| h3 | 10.192.90.48 | 04-19,04-20,04-22,04-23,04-24,04-25,04-26 | 04-27 | 04-30,05-01,05-02,05-06,05-07,05-08,05-09 |
| h4 | 10.192.101.45 | 04-18,04-22,04-24,04-25,04-26 | 04-29 | 04-30,05-01,05-02,05-07,05-08,05-09,05-10 |
| h5 | 130.126.136.46 | 04-22..04-28 | 04-29 | 04-30..05-10 (11 days) |
Ground truth carbanakv2_edr.csv: 229 unique node ids (load_gt), all in the database; found in eval-test registry: h1 63, h2 81,
h3 26, h4 21, h5 21 (all subject) = 212; 2 more are h5-component nodes with no kept event on h5's prepared days; 15 are in
unattributed small components. h2 manifest flags list re-written by hand (a ';' inside one flag had split it in two).

### THEIA_E5 — READY 08:51 (/data/heldout/THEIA_E5/theia)
Stream path (no restore). Commands (v08/): `survey_stream.sh theia_e5 <dump> 2019-05-07 2019-05-18 <base days> <test days>`
(= `heldout_stream survey` on the `pg_restore -a -t event_table -f - | cut -s -f2,3,5,6,7` FIFO, pg_restore in a
`--log-driver none` postgres:17 container); `convert_stream.sh` (= heldout_stream conversion, node FIFO + event FIFO, 2 passes);
`manifest_theia.sh` (= heldout_stream manifest). Survey: 140,994,662 rows, all within 05-07..05-17, 0 NULL/midnight/bad uuid/
non-canonical ids. Verification: `verify_stream.sh` on a 3,524,866-row stride sample (every 40th event row, all days) loaded
as database theia_e5_sample: heldout_prep build (PostgresReplay) vs heldout_stream -> compare_stores EQUIVALENT (registries
and every window array identical). Sample db + files deleted afterwards.
train 05-08,05-09,05-10 / val 05-11 / test 05-14,05-15. Kept events per day: 05-08 9,755,176; 05-09 7,006,586; 05-10 6,564,340;
05-11 6,586,717; 05-14 13,771,858; 05-15 12,464,260. Registries: baseline 920,492, eval-test 1,550,195.
Ground truth node_THEIA_1_Firefox_Drakon_APT_BinFmt_Elevate_Inject.csv: 70 nodes, 68 found (subject 64, netflow 4), 2 not found
(no kept event on the prepared days or not in the database).
- 08:52 clearscope_e5: the folder's theia_clearscope_e5.tar (12,818,063,360 B, id 1DfolzEa3PVz_6fGZUNEUm0sBP42LB7_1) starts with
  the member clearscope_e5.dump of exactly 6,630,620,258 B (tar header read from a 1 KB probe); switched the clearscope download
  to that member's byte range (v08/dl_range.sh, offset 512). It too became quota-blocked within a minute (the quota now looks
  per client, not per file); both downloads keep retrying with backoff. The drive.google.com/uc route ends in the same
  usercontent endpoint (virus-scan confirm page), so it is not a separate quota.

### CADETS_E5 / CLEARSCOPE_E5 — NOT READY (Google Drive quota)
- cadets_e5: 14,495,514,624 / 38,031,603,978 B downloaded before "Quota exceeded" at 08:27; 13 retries with backoff until 12:28
  all quota-blocked. Partial kept as /root/darpa/cadets_e5/cadets_e5.dump.partial (rename to cadets_e5.dump and rerun
  `scripts/dl.sh cadets_e5 1Xiq7w0Ofz4jZG2PVFuNqi_i0fm28kRcT 38031603978` to resume at the same offset). Schema checked from the
  partial dump's TOC: identical tables/columns to THEIA_E5/TRACE_E3, so heldout_stream applies unchanged.
- clearscope_e5: blocked from the first byte (direct file 08:30-08:51, tar member 08:52-12:23, 12 retries). Resume:
  `scripts/dl_range.sh clearscope_e5 1DfolzEa3PVz_6fGZUNEUm0sBP42LB7_1 6630620258 512` (or dl.sh with the direct id).
- Downloaders stopped 12:35. Pipeline for both once downloaded: survey_stream.sh -> sample.sh + verify_stream.sh ->
  convert_stream.sh -> heldout_stream manifest (as THEIA_E5); split rules above (PIDSMaker lists, chronological).

### Wrap-up 12:35
- Research postgres: carbanakv2_edr (6.5 GB, restorable from the dump in 30 s) and theia_e5_sample dropped; no existing db touched.
- Dumps kept: /root/darpa/carbanakv2_edr/carbanakv2_edr.dump (1.18 GB), /root/darpa/theia_e5/theia_e5.dump (6.19 GB),
  /root/darpa/cadets_e5/cadets_e5.dump.partial (14.5 GB).
- Data-prep code path (pdp_engine data/windows/schema/sources, darpa_eval.load_gt, heldout_prep) is unchanged vs git HEAD; the
  working tree's other uncommitted engine changes (behaviour/bundle/runtime/trainer, not mine) are not imported by the prep tools.
- Disk at wrap-up: 40 GB free on / (was 78 GB at 08:51; the drop is other activity in pdp_data/lab08, not this prep).
