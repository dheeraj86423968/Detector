"""Prepare held-out evaluation data as WindowStores, one per host (data preparation only: no model, no scoring).

  python -m pdp_server.tools.heldout_prep partition --database atlasv2_edr --out /data/heldout/ATLASV2_EDR
  python -m pdp_server.tools.heldout_prep survey    --database atlasv2_edr --out /data/heldout/ATLASV2_EDR
  python -m pdp_server.tools.heldout_prep build     --database atlasv2_edr --out /data/heldout/ATLASV2_EDR \
        --dataset ATLASV2_EDR --host h1 --train 2022-07-15,... --val 2022-07-18 --test 2022-07-19,2022-07-20 \
        --gt atlasv2_edr/atlasv2_edr_s1.csv,...

Layout per host (<out>/<host>/):
  baseline/    WindowStore: training days then the validation day, one registry grown in that order
  eval-test/   WindowStore: the test days; its registry starts as a copy of the baseline registry and grows (as
               darpa_eval.rescore builds eval-test), so dense ids agree with the baseline. Entity uuids are the
               framework index ids (what PostgresReplay uses and the orthrus ground truth's 3rd column holds).
  manifest.json

Windows are built exactly as the product path does for replayed days: ingest_day(reg, replay.events(day), lookup,
window_ns=15 min) (darpa_eval.rescore, worker.job_sim). Events come from PostgresReplay (DARPA TC databases),
EdrPostgresReplay (Carbon Black EDR databases, with a per-host node filter) or, for a dump too large to restore, a
streamed equivalent (heldout_stream.py).

Hosts (`partition`): the EDR databases have no host column. Each host is a connected component of the provenance
graph (all events, all days): processes, files, registry keys and flows are host-local nodes in these databases, so
the hosts separate cleanly. A component is labelled by its dominant local address (netflow src_addr, loopback and
link-local excluded); tiny components without flows cannot be attributed and are left out (counted in the manifest).
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import time
from datetime import datetime, timedelta

import numpy as np

WINDOW_NS = 15 * 60 * 1_000_000_000
REG_PREFIX = ("HKLM\\", "HKU\\", "HKCU\\", "HKCR\\", "HKCC\\", "HKEY_", "\\REGISTRY\\")   # registry keys stored as file nodes


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def connect(database: str, host: str = "postgres"):
    import psycopg2
    return psycopg2.connect(dbname=database, host=host, user="postgres", password="postgres")


def node_kinds(con) -> dict[str, str]:
    cur = con.cursor()
    out = {}
    for t, k in (("subject_node_table", "subject"), ("file_node_table", "file"), ("netflow_node_table", "netflow")):
        cur.execute(f"SELECT index_id FROM {t}")
        for (i,) in cur:
            out[str(i)] = k
    return out


def _local(a: str | None) -> bool:
    a = (a or "").lower()
    return a in ("", "none", "0", "0.0.0.0", "::", "::1") or a.startswith("127.") or a.startswith("fe80:") or a.startswith("ff0")


# ---------------------------------------------------------------- partition
def host_partition(con, min_share: float = 0.01) -> tuple[dict[str, list[str]], dict]:
    """Connected components of the provenance graph -> {label: [index ids]}, plus a summary."""
    kinds = node_kinds(con)
    par: dict[str, str] = {}

    def find(x):
        r = x
        while par.get(r, r) != r:
            r = par[r]
        while par.get(x, x) != r:
            par[x], x = r, par[x]
        return r
    cur = con.cursor(name="partition")
    cur.itersize = 500_000
    cur.execute("SELECT src_index_id, dst_index_id FROM event_table")
    for s, d in cur:
        a, b = find(str(s)), find(str(d))
        if a != b:
            par[a] = b
    cur.close()
    c2 = con.cursor()
    c2.execute("SELECT index_id, src_addr FROM netflow_node_table")
    laddr = {str(i): a for i, a in c2}
    c2.execute("SELECT index_id, path FROM subject_node_table")
    spath = {str(i): (p or "") for i, p in c2}
    members = collections.defaultdict(list)
    for i in kinds:
        members[find(i)].append(i)
    total = len(kinds)
    hosts, summary, left = {}, {"components": len(members), "hosts": {}, "unassigned": {"components": 0, "nodes": 0}}, collections.Counter()
    for r, ids in sorted(members.items(), key=lambda kv: -len(kv[1])):
        addrs = collections.Counter(laddr[i] for i in ids if i in laddr and not _local(laddr[i]))
        if len(ids) < min_share * total or not addrs:
            summary["unassigned"]["components"] += 1
            summary["unassigned"]["nodes"] += len(ids)
            left.update(kinds[i] for i in ids)
            continue
        label = addrs.most_common(1)[0][0]
        if label in hosts:
            label = f"{label}#{len(hosts)}"
        kc = collections.Counter(kinds[i] for i in ids)
        subj = [spath[i] for i in ids if i in spath]
        win = sum(1 for p in subj if ":\\" in p or p.lower().startswith("\\device")) / max(1, len(subj))
        hosts[label] = ids
        summary["hosts"][label] = {"nodes": len(ids), "by_type": dict(kc), "local_addresses": addrs.most_common(5),
                                   "windows_path_share_of_processes": round(win, 3),
                                   "platform_guess": "windows" if win > 0.5 else "linux/posix"}
    summary["unassigned"]["by_type"] = dict(left)
    return hosts, summary


def save_partition(out: str, hosts: dict[str, list[str]], summary: dict):
    os.makedirs(out, exist_ok=True)
    np.savez_compressed(os.path.join(out, "host_partition.npz"),
                        **{k.replace(":", "_"): np.array(sorted(int(i) for i in v), dtype=np.int64) for k, v in hosts.items()})
    json.dump({"method": "connected components of the provenance graph (all events, all days), labelled by the "
                         "dominant non-loopback local address of the component's flows; npz keys = label with ':' -> '_'",
               **summary}, open(os.path.join(out, "host_partition.json"), "w"), indent=1, default=str)


def load_partition(out: str, label: str) -> set[str]:
    z = np.load(os.path.join(out, "host_partition.npz"))
    return {str(i) for i in z[label.replace(":", "_")].tolist()}


# ---------------------------------------------------------------- survey
def day_of(ts: int, tz: str = "US/Eastern") -> str:
    import pytz
    return datetime.fromtimestamp(ts / 1e9, pytz.timezone(tz)).strftime("%Y-%m-%d")


def survey(con, out: str, edr: bool) -> dict:
    """Per host and per calendar day (US/Eastern, the replay's day boundaries): raw rows and mapped events.
    Event counts only (used to pick the split)."""
    from pdp_engine.schema import normalise_op
    from pdp_engine.sources.edr_replay import cb_op
    kinds = node_kinds(con)
    host_of = {}
    if os.path.exists(os.path.join(out, "host_partition.npz")):
        z = np.load(os.path.join(out, "host_partition.npz"))
        for k in z.files:
            for i in z[k].tolist():
                host_of[str(i)] = k
    cur = con.cursor(name="survey")
    cur.itersize = 500_000
    cur.execute("SELECT src_index_id, operation, dst_index_id, timestamp_rec FROM event_table")
    raw = collections.defaultdict(collections.Counter)
    mapped = collections.defaultdict(collections.Counter)
    bounds: dict[int, str] = {}
    for s, op, d, t in cur:
        h = host_of.get(str(s), "unassigned" if host_of else "all")
        hr = int(t) // 3_600_000_000_000          # hour bucket -> day (cached)
        day = bounds.get(hr)
        if day is None:
            day = bounds[hr] = day_of(hr * 3_600_000_000_000 + 1)
        raw[h][day] += 1
        m = cb_op(op, kinds.get(str(s)), kinds.get(str(d))) if edr else normalise_op(op, strict=True)
        if m is not None:
            mapped[h][day] += 1
    cur.close()
    res = {h: {d: {"rows": raw[h][d], "mapped_events": mapped[h][d]} for d in sorted(raw[h])} for h in raw}
    json.dump(res, open(os.path.join(out, "day_survey.json"), "w"), indent=1)
    return res


# ---------------------------------------------------------------- build
def format_notes(reg, op_counts: collections.Counter) -> dict:
    """Record-format facts (no labels, no scores): which fields are present in the entity labels / event types."""
    subj = [e for e in reg.entities if e.ntype == "subject"]
    files = [e for e in reg.entities if e.ntype == "file"]
    nets = [e for e in reg.entities if e.ntype == "netflow"]

    def exe(lbl):
        return lbl.split(" ", 2)[1] if lbl.count(" ") >= 1 else ""

    def cmd(lbl):
        p = lbl.split(" ", 2)
        return p[2] if len(p) > 2 else ""
    sx = [exe(e.label) for e in subj]
    n = max(1, len(subj))
    absent = ("None", "", "null")
    remote = [e.label.split(" ") for e in nets]
    ra = [r[1] if len(r) > 1 else "" for r in remote]
    return {
        "entities": {"subject": len(subj), "file": len(files), "netflow": len(nets)},
        "process_exe_present": round(sum(1 for x in sx if x not in absent) / n, 4),
        "process_exe_absolute_path": round(sum(1 for x in sx if x.startswith("/") or ":\\" in x[:3] or x.lower().startswith("\\device")) / n, 4),
        "process_cmdline_present": round(sum(1 for e in subj if cmd(e.label).strip() not in absent) / n, 4),
        "file_path_present": round(sum(1 for e in files if e.label[5:].strip() not in absent) / max(1, len(files)), 4),
        "file_registry_key_share": round(sum(1 for e in files if e.label[5:].upper().startswith(REG_PREFIX)) / max(1, len(files)), 4),
        "netflow_remote_addr_present": round(sum(1 for a in ra if a not in absent and a not in ("0", "0.0.0.0", "::")) / max(1, len(nets)), 4),
        "edge_types_after_mapping": dict(op_counts),
        "exec_events_present": op_counts.get("EXECUTE", 0) > 0,
        "process_creation_events_present": op_counts.get("CLONE", 0) > 0,
    }


def counting(events, raw_ops: collections.Counter, mapped_ops: collections.Counter):
    for ev in events:
        mapped_ops[ev.op] += 1
        yield ev


def build_store(root: str, days: list[str], src, lookup, reg, stats: dict, op_counts: collections.Counter):
    from pdp_engine.data import WindowStore, ingest_day
    store = WindowStore(root)
    for d in days:
        if d in store.days():
            raise SystemExit(f"{root}: day {d} already present (remove the store to rebuild)")
        before = len(reg)
        st, ops = {}, collections.Counter()
        n = store.add_day(d, ingest_day(reg, counting(src.events(d), None, ops), lookup, window_ns=WINDOW_NS, stats=st))
        edges = sum(len(w.src) for w in store.windows(d))
        store.save_registry(reg)
        stats[d] = {"events": int(sum(ops.values())), "events_by_type": dict(ops), "dropped_unknown_entity": st.get("dropped", 0),
                    "windows": n, "fused_edges": edges, "new_entities": len(reg) - before, "registry_size": len(reg)}
        op_counts.update(ops)
        log(f"{root}: {d} {stats[d]['events']} events, {n} windows, {edges} fused edges, registry {len(reg)}")
    return store


def raw_rows_per_day(con, days: list[str], nodes: set[str] | None) -> dict:
    """Raw rows (before the op mapping) per day for this host, by operation (format information)."""
    from pdp_engine.sources.pg_replay import ns
    out = {}
    for d in days:
        t0 = ns(f"{d} 00:00:00")
        t1 = ns(f"{(datetime.strptime(d, '%Y-%m-%d') + timedelta(days=1)).strftime('%Y-%m-%d')} 00:00:00")
        cur = con.cursor(name=f"raw_{d.replace('-', '')}")
        cur.itersize = 500_000
        cur.execute("SELECT src_index_id, operation FROM event_table WHERE timestamp_rec > %s AND timestamp_rec < %s", (t0, t1))
        c = collections.Counter(op for s, op in cur if nodes is None or str(s) in nodes)
        cur.close()
        out[d] = {"rows": sum(c.values()), "rows_by_operation": dict(c)}
    return out


def gt_counts(gt_dir: str, files: list[str], reg_ids: dict, kinds: dict, nodes: set[str] | None,
              other_hosts: dict[str, set[str]]) -> dict:
    from pdp_server.tools.darpa_eval import load_gt
    out = {}
    for f in files:
        ids = next(iter(load_gt(gt_dir, [f]).values()))
        found = {i for i in ids if i in reg_ids}
        miss = ids - found
        r = {"csv": f, "gt_nodes": len(ids), "found_in_eval_test_registry": len(found), "not_found": len(miss),
             "found_by_type": dict(collections.Counter(kinds.get(i, "?") for i in found))}
        if miss:
            r["not_found_breakdown"] = {
                "not_in_database": sum(1 for i in miss if i not in kinds),
                "on_other_hosts": {h: n for h, s in other_hosts.items() if (n := sum(1 for i in miss if i in s))},
                "this_host_but_no_test_day_event": sum(1 for i in miss if i in kinds and (nodes is None or i in nodes)),
                "unattributed_component": sum(1 for i in miss if i in kinds and nodes is not None and i not in nodes
                                              and not any(i in s for s in other_hosts.values())),
            }
        out[os.path.basename(f)[:-4]] = r
    return out


def cmd_build(a):
    from pdp_engine.schema import Registry
    con = connect(a.database, a.db_host)
    kinds = node_kinds(con)
    part_dir = a.out
    nodes = load_partition(part_dir, a.host_key) if a.host_key else None
    others = {}
    if a.host_key:
        z = np.load(os.path.join(part_dir, "host_partition.npz"))
        others = {k: {str(i) for i in z[k].tolist()} for k in z.files if k != a.host_key.replace(":", "_")}
    if a.edr:
        from pdp_engine.sources.edr_replay import EdrPostgresReplay
        src = EdrPostgresReplay(a.database, nodes=nodes, registry=not a.no_registry, host=a.db_host)
    else:
        from pdp_engine.sources.pg_replay import PostgresReplay
        src = PostgresReplay(a.database, host=a.db_host)
    lookup = src.entity_index()
    hdir = os.path.join(a.out, a.host)
    train, val, test = a.train.split(","), a.val, a.test.split(",")
    reg = Registry()
    stats, ops = {}, collections.Counter()
    base = build_store(os.path.join(hdir, "baseline"), train + [val], src, lookup, reg, stats, ops)
    ev_root = os.path.join(hdir, "eval-test")
    os.makedirs(ev_root, exist_ok=True)
    shutil.copy(os.path.join(base.root, "registry.json"), os.path.join(ev_root, "registry.json"))
    from pdp_engine.data import WindowStore
    reg = WindowStore(ev_root).load_registry()
    build_store(ev_root, test, src, lookup, reg, stats, ops)
    raw = raw_rows_per_day(con, train + [val] + test, nodes)
    for d in stats:
        stats[d] = {**raw[d], **stats[d]}
    gt_files = [g for g in a.gt.split(",") if g]
    man = {
        "dataset": a.dataset, "host": a.host, "host_partition_key": a.host_key, "platform": a.platform,
        "database": a.database, "source": "EdrPostgresReplay" if a.edr else "PostgresReplay",
        "registry_events_included": (not a.no_registry) if a.edr else None,
        "train_days": train, "val_day": val, "test_days": test, "split_rule": a.split_note,
        "flags": [f for f in a.flags.split(";") if f],
        "day_boundaries": "US/Eastern calendar days, timestamp_rec strictly inside (PostgresReplay / PIDSMaker graph construction)",
        "window": "15 min fused windows (WindowBuilder, chunks of 1024)",
        "entity_uuid": "framework index_id (orthrus ground truth column 3); label formats 'subject <exe> <cmdline>', 'file <path>', 'netflow <ip> <port>'",
        "eval_test_registry": "starts as a copy of the baseline registry (dense ids agree), extended by the test days",
        "ground_truth_dir": a.gt_dir_host, "ground_truth": gt_counts(a.gt_dir, gt_files, reg.ids, kinds, nodes, others),
        "days": stats,
        "entities": {"baseline_registry": len(base.load_registry()), "eval_test_registry": len(reg)},
        "format_notes": {**format_notes(reg, ops), "notes": [n for n in a.notes.split(";") if n]},
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": "pdp_server.tools.heldout_prep",
    }
    json.dump(man, open(os.path.join(hdir, "manifest.json"), "w"), indent=1, default=str)
    log(f"manifest written: {os.path.join(hdir, 'manifest.json')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["partition", "survey", "build"])
    ap.add_argument("--database", required=True)
    ap.add_argument("--db-host", default="postgres")
    ap.add_argument("--out", required=True, help="dataset directory, e.g. /data/heldout/ATLASV2_EDR")
    ap.add_argument("--edr", action="store_true", help="Carbon Black EDR operation vocabulary")
    ap.add_argument("--no-registry", action="store_true")
    ap.add_argument("--dataset"); ap.add_argument("--host"); ap.add_argument("--host-key", default="")
    ap.add_argument("--platform", default=""); ap.add_argument("--train"); ap.add_argument("--val"); ap.add_argument("--test")
    ap.add_argument("--gt", default=""); ap.add_argument("--gt-dir", default="/gt")
    ap.add_argument("--gt-dir-host", default="/root/PIDSMaker/Ground_Truth/orthrus (= /data/gt/orthrus in the pdp containers)")
    ap.add_argument("--split-note", default=""); ap.add_argument("--flags", default=""); ap.add_argument("--notes", default="")
    a = ap.parse_args()
    if a.cmd == "partition":
        hosts, summary = host_partition(connect(a.database, a.db_host))
        save_partition(a.out, hosts, summary)
        print(json.dumps(summary, indent=1, default=str))
    elif a.cmd == "survey":
        res = survey(connect(a.database, a.db_host), a.out, a.edr)
        for h, days in res.items():
            print(h)
            for d, v in days.items():
                print(f"  {d} rows {v['rows']:>10} mapped {v['mapped_events']:>10}")
    else:
        cmd_build(a)


if __name__ == "__main__":
    main()
