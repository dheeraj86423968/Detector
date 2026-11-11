# Converting lab hosts to PIDSMaker's database format (E3 TRACE, ATLASv2 h1, CARBANAKv2 h1-h5)

Tool: `scripts/conv_store.py` (read-only on the lab store, writes a NEW PostgreSQL database `bl_<host>` in the
PIDSMaker container). Specs for the systems: `scripts/gen_specs.py`. Reports: `/root/bl/conv/gt_<host>/conv_bl_<host>.json`
(copied to `results/conversion/`).

## Source
The lab's host store (`/data/heldout/<SET>/<host>/` in the `pdp_pdp_data` volume): `baseline/` (training and validation
days) and `eval-test/` (test days), each with `registry.json` (entities) and `windows/<day>/*.npz` (fused edges). These
are exactly the nodes, edges and days the lab scored. For E3 TRACE the store was streamed from the PIDSMaker TRACE dump
(PostgresReplay-equivalent, verified on a 5 M-row sample); for ATLASv2 / CARBANAKv2 from PIDSMaker's multi-host EDR
databases, split into hosts by connected components labelled with their dominant local address, with the 33 Carbon
Black event types mapped to our 10 edge types by (source type, operation, destination type) (method.tex).

## Mapping
- Node ids: `index_id` = the registry entity `uuid` = the framework index_id (= ORTHRUS ground-truth CSV column 3).
  `node_uuid` = the original UUID (`display.raw_uuid`), `hash_id` = str(index_id); events reference `hash_id`.
- Node attributes: subject `path` = the registry label without the `subject ` prefix (our label is
  `<exe or None> <cmdline or None>`), `cmd` = ''. Both PIDSMaker (ORTHRUS features `type, path, cmd_line`) and
  ProvFusion (`path + ' ' + cmd`) concatenate path and command line before tokenising, so the split point does not
  matter; the only difference to a native database is a literal `None` token where the original field was empty.
  File `path` = label without `file `. Netflow: label `netflow <ip> <port>` -> `dst_addr`, `dst_port` (the columns
  both systems read as the remote end); local address/port are not in our registry and are left empty (both systems'
  default features use the remote end only).
- Events: one row per fused edge of the days in the lab manifest's train + val + test lists; `operation` =
  `EVENT_<type>` with our 10 types (CONNECT, EXECUTE, OPEN, READ, RECVFROM, RECVMSG, SENDMSG, SENDTO, WRITE, CLONE =
  the relation vocabulary of both systems); `timestamp_rec` = the fused edge's time; `event_uuid` = its first event.
  A fused edge is the ORTHRUS collapse of consecutive same-type events between the same (src, dst) within a 15-min
  window. ORTHRUS/Velox (`fuse_edge: True`, 15-min windows) and ProvFusion (per-day fusion) apply the same collapse;
  it is idempotent across a partition of time into contiguous segments, so they rebuild the graphs they would have
  built from the raw events, except where their own windows cut differently (they can only merge further).
- Days: US/Eastern calendar days as in the lab (`timezone: US/Eastern` in the PIDSMaker specs; ProvFusion always
  uses US/Eastern). Splits = the lab manifests (method.tex rule).
- Ground truth: the ORTHRUS CSV rows whose index_id is in the host's registry (CARBANAKv2: the attack spans hosts,
  each host is scored on its own GT nodes), written to `gt_<host>/`; both systems read them unchanged.

## Checks
- Fused-edge counts per day equal the lab manifest (ATLASv2 h1: 241,470 / 270,484 / 237,731 / 266,844 / 310,327).
- Node counts equal the lab registry; GT ids found in the host database (ATLASv2 h1: 48/48; node UUIDs match).
- Join of every score file back to the lab registry: results/join_rates.json.
