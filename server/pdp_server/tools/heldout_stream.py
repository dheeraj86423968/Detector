"""Held-out WindowStores from a PIDSMaker DARPA TC dump that is too large to restore (TRACE_E3: ~100 GB restored,
39 M subject rows), streaming `pg_restore -a -t <table> -f - dump` output instead of a database.

Produces exactly what heldout_prep's database path produces (PostgresReplay + ingest_day):
  entities  built with the same Entity constructors and the same str() conversions as PostgresReplay.entities()
            (NULL -> None -> 'None'; entity uuid = str(index_id); raw_uuid / local_ip / local_port display fields), and
            the same precedence (subject, then file, then netflow table; a later row with the same index id wins).
            Only entities referenced by a kept event of the prepared days are held in memory (the lookup contents
            for those events are identical; others can never be registered).
  events    rows with timestamp_rec strictly inside the US/Eastern day, strict op mapping (normalise_op strict),
            Event(int(ts), src_index_id, op, dst_index_id, event_uuid) with the database strings, ordered by
            (timestamp_rec, event_uuid). The research database collates event_uuid with en_US.utf8; for canonical
            fixed-format upper-case uuids (checked for every row; the run aborts otherwise) that order equals byte
            order. Rows tied on both keys keep dump order (PostgreSQL's order for such ties is unspecified).
  windows   the real ingest_day / WindowBuilder / WindowStore code.

Inputs are FIFOs fed by the caller (so no stream passes through a container's stdout log):
  --nodes FIFO   `pg_restore -a -t subject_node_table -t file_node_table -t netflow_node_table -f - dump`
  --events FIFO  `pg_restore -a -t event_table -f - dump | cut -s -f2,3,5,6,7`, opened once per pass
  --referenced   npz with arrays `base` / `test` of referenced index ids (survey pass)

Subcommands: `survey` (one counting pass over the event FIFO: per-day rows / kept events, stream checks, referenced
ids, day sizes), the default conversion, and `manifest`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timedelta

import numpy as np

from pdp_engine.data import WindowStore, ingest_day
from pdp_engine.schema import Entity, Event, Registry, normalise_op
from pdp_engine.sources.pg_replay import ns

WINDOW_NS = 15 * 60 * 1_000_000_000
UUID_RE = re.compile(rb"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}")
_ESC = {ord("b"): "\b", ord("f"): "\f", ord("n"): "\n", ord("r"): "\r", ord("t"): "\t", ord("v"): "\v"}


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def free_gb(path: str) -> float:
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize / 2**30


def copy_unescape(f: str) -> str | None:
    """One field of PostgreSQL COPY text format -> the value psycopg2 would return (None for NULL)."""
    if f == "\\N":
        return None
    if "\\" not in f:
        return f
    out, i, n = [], 0, len(f)
    while i < n:
        c = f[i]
        if c != "\\" or i + 1 == n:
            out.append(c); i += 1; continue
        d = f[i + 1]
        if d in "01234567":
            j = i + 1
            while j < n and j < i + 4 and f[j] in "01234567":
                j += 1
            out.append(chr(int(f[i + 1:j], 8))); i = j
        elif d == "x" and i + 2 < n and f[i + 2] in "0123456789abcdefABCDEF":
            j = i + 2
            while j < n and j < i + 4 and f[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(chr(int(f[i + 2:j], 16))); i = j
        else:
            out.append(_ESC.get(ord(d), d)); i += 2
    return "".join(out)


def copy_tables(stream):
    """pg_restore -a output -> (table, fields) for every data row (bytes stream, UTF-8)."""
    table = None
    for raw in stream:
        line = raw.decode("utf-8").rstrip("\n")
        if table is None:
            m = re.match(r"COPY public\.(\w+) .*FROM stdin;$", line)
            if m:
                table = m.group(1)
            continue
        if line == "\\.":
            table = None
            continue
        yield table, line.split("\t")


def load_entities(nodes_path: str, needed: np.ndarray) -> dict[str, Entity]:
    """Entities for the needed index ids, exactly as PostgresReplay.entities() / entity_index() build them."""
    per = {"subject_node_table": {}, "file_node_table": {}, "netflow_node_table": {}}
    seen = {k: 0 for k in per}
    with open(nodes_path, "rb") as fh:
        for table, p in copy_tables(fh):
            seen[table] += 1
            if table == "subject_node_table":          # node_uuid, hash_id, path, cmd, index_id
                uuid, _, path, cmd, idx = (copy_unescape(x) for x in p)
            elif table == "file_node_table":           # node_uuid, hash_id, path, index_id
                uuid, _, path, idx = (copy_unescape(x) for x in p)
            else:                                      # node_uuid, hash_id, src_addr, src_port, dst_addr, dst_port, index_id
                uuid, _, sa, sp, da, dp, idx = (copy_unescape(x) for x in p)
            if idx is None:
                continue                               # str(None) = 'None' never matches an event's index id
            i = int(idx)
            if i < 0 or i >= len(needed) or not needed[i]:
                continue
            if table == "subject_node_table":
                e = Entity.process(str(i), str(path), str(cmd), raw_uuid=uuid)
            elif table == "file_node_table":
                e = Entity.file(str(i), str(path), raw_uuid=uuid)
            else:
                e = Entity.socket(str(i), str(da), str(dp), raw_uuid=uuid, local_ip=str(sa), local_port=str(sp))
            per[table][e.uuid] = e
    log(f"node rows streamed: {seen}; kept {[len(v) for v in per.values()]}")
    out: dict[str, Entity] = {}
    for t in ("subject_node_table", "file_node_table", "netflow_node_table"):   # entity_index precedence
        out.update(per[t])
    return out


def collect_days(events_path: str, days: list[str], sizes: dict[str, int], chunk: int = 2_000_000):
    """One pass over the event stream: kept events of `days`, as numpy columns per day (unsorted, dump order).
    Columns are preallocated from the survey's per-day counts (checked at the end)."""
    bounds = {d: (ns(f"{d} 00:00:00"), ns(f"{(datetime.strptime(d, '%Y-%m-%d') + timedelta(days=1)).strftime('%Y-%m-%d')} 00:00:00")) for d in days}
    B = np.array(sorted({b for v in bounds.values() for b in v}), dtype=np.int64)
    day_of_interval = {}
    for d, (a, b) in bounds.items():
        k = int(np.searchsorted(B, a))
        assert B[k + 1] == b
        day_of_interval[k] = d
    ops: dict[bytes, int] = {}
    names: list[str] = []
    DT = (np.int64, np.int64, np.int64, np.int8, np.uint64, np.uint64)
    cols = {d: [np.empty(int(sizes[d]), dt) for dt in DT] for d in days}
    fill = {d: 0 for d in days}
    rows = 0

    def opcode(o: bytes) -> int:
        c = ops.get(o)
        if c is None:
            n = normalise_op(o.decode(), strict=True)
            if n is None:
                c = -1
            else:
                if n not in names:
                    names.append(n)
                c = names.index(n)
            ops[o] = c
        return c

    def flush(src, op, dst, uu, ts):
        joined = b"\n".join(uu)
        if len(joined) != 37 * len(uu) - 1 or len(UUID_RE.findall(joined)) != len(uu):
            raise SystemExit("non-canonical event_uuid in the stream: byte order may differ from the en_US collation")
        t = np.array(ts, dtype=np.int64)
        oc = np.array([opcode(o) for o in op], dtype=np.int8)
        k = np.searchsorted(B, t, side="left") - 1
        inside = (k >= 0) & (k < len(B) - 1) & ~np.isin(t, B) & (oc >= 0)   # strictly inside, strict op
        for kk, d in day_of_interval.items():
            sel = np.nonzero(inside & (k == kk))[0]
            if not len(sel):
                continue
            s = [src[i] for i in sel]; dd = [dst[i] for i in sel]
            for x in s + dd:
                if not x.isdigit() or (len(x) > 1 and x[:1] == b"0"):
                    raise SystemExit(f"non-canonical index id {x!r}")
            u = np.frombuffer(bytes.fromhex(b"".join(uu[i] for i in sel).replace(b"-", b"").decode()), dtype=">u8").reshape(-1, 2)
            a, b = fill[d], fill[d] + len(sel)
            if b > len(cols[d][0]):
                raise SystemExit(f"{d}: more kept events than the survey counted")
            for c, v in zip(cols[d], (t[sel], np.array(s, dtype=np.int64), np.array(dd, dtype=np.int64), oc[sel], u[:, 0], u[:, 1])):
                c[a:b] = v
            fill[d] = b

    src, op, dst, uu, ts = [], [], [], [], []
    with open(events_path, "rb") as fh:
        for line in fh:
            p = line.rstrip(b"\n").split(b"\t")
            if p[4] == b"\\N":
                continue                                # NULL timestamp: never inside a day
            src.append(p[0]); op.append(p[1]); dst.append(p[2]); uu.append(p[3]); ts.append(int(p[4]))
            rows += 1
            if len(ts) == chunk:
                flush(src, op, dst, uu, ts); src, op, dst, uu, ts = [], [], [], [], []
    if ts:
        flush(src, op, dst, uu, ts)
    for d in days:
        if fill[d] != len(cols[d][0]):
            raise SystemExit(f"{d}: kept {fill[d]} events, survey counted {len(cols[d][0])}")
    log(f"event pass: {rows} rows streamed; kept " + ", ".join(f"{d}: {fill[d]}" for d in days))
    return cols, names


def day_events(cols, names):
    """Kept events of one day in the replay's order (timestamp_rec, event_uuid), as Event objects."""
    t, s, d, oc, uh, ul = cols
    order = np.lexsort((ul, uh, t))                    # stable: full ties keep dump order
    for a in range(0, len(order), 1_000_000):
        o = order[a:a + 1_000_000]
        for ti, si, oi, di, hi, lo in zip(t[o].tolist(), s[o].tolist(), oc[o].tolist(), d[o].tolist(), uh[o].tolist(), ul[o].tolist()):
            h = f"{hi:016X}{lo:016X}"
            yield Event(ti, str(si), names[oi], str(di), f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}")


def plan_passes(sizes: dict[str, int], days: list[str], budget_events: int) -> list[list[str]]:
    passes, cur, n = [], [], 0
    for d in days:
        if cur and n + sizes[d] > budget_events:
            passes.append(cur); cur, n = [], 0
        cur.append(d); n += sizes[d]
    if cur:
        passes.append(cur)
    return passes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", required=True); ap.add_argument("--events", required=True)
    ap.add_argument("--referenced", required=True)
    ap.add_argument("--out", required=True, help="<dataset dir>/<host>")
    ap.add_argument("--train", required=True); ap.add_argument("--val", required=True); ap.add_argument("--test", required=True)
    ap.add_argument("--day-sizes", required=True, help="json {day: kept events} from the survey (to plan passes)")
    ap.add_argument("--pass-budget", type=int, default=120_000_000, help="kept events held in memory per pass")
    ap.add_argument("--min-free-gb", type=float, default=26.0)
    ap.add_argument("--stats", required=True, help="where to write per-day stats json")
    a = ap.parse_args()
    train, val, test = a.train.split(","), a.val, a.test.split(",")
    z = np.load(a.referenced)
    ids = np.union1d(z["base"], z["test"])
    needed = np.zeros(int(ids.max()) + 1 if len(ids) else 1, dtype=bool)
    needed[ids] = True
    log(f"loading entities for {len(ids)} referenced index ids")
    lookup = load_entities(a.nodes, needed)
    log(f"lookup: {len(lookup)} entities")
    sizes = json.load(open(a.day_sizes))
    stats = {}
    for part, days in (("baseline", train + [val]), ("eval-test", test)):
        root = os.path.join(a.out, part)
        store = WindowStore(root)
        if part == "baseline":
            reg = Registry()
        else:
            # the database path copies baseline/registry.json and loads it; continuing the in-memory baseline registry
            # gives the same registry (same uuids, types, labels, display, order) without a second copy in memory
            shutil.copy(os.path.join(a.out, "baseline", "registry.json"), os.path.join(root, "registry.json"))
        for group in plan_passes(sizes, days, a.pass_budget):
            log(f"{part}: event pass for {group}")
            cols_by_day, names = collect_days(a.events, group, sizes)
            for d in group:
                if free_gb(a.out) < a.min_free_gb:
                    raise SystemExit(f"free disk below {a.min_free_gb} GB; stopping before {d}")
                before, st = len(reg), {}
                n = store.add_day(d, ingest_day(reg, day_events(cols_by_day[d], names), lookup, window_ns=WINDOW_NS, stats=st))
                edges = sum(len(w.src) for w in store.windows(d))
                stats[d] = {"events": int(len(cols_by_day[d][0])), "dropped_unknown_entity": st.get("dropped", 0), "windows": n,
                            "fused_edges": edges, "new_entities": len(reg) - before, "registry_size": len(reg),
                            "events_by_type": {names[k]: int(v) for k, v in zip(*np.unique(cols_by_day[d][3], return_counts=True))}}
                del cols_by_day[d]
                log(f"{root}: {d} {stats[d]}; free {free_gb(a.out):.1f} GB")
                json.dump(stats, open(a.stats, "w"), indent=1)
            del cols_by_day
        store.save_registry(reg)                       # the database path saves after every day; the final file is the same
        log(f"{root}: registry saved ({len(reg)} entities)")
    json.dump(stats, open(a.stats, "w"), indent=1)


def survey(argv):
    """survey --events FIFO --first-day D --last-day D --base d1,d2 --test d3,d4 --out-prefix P

    One pass over the event stream (same `cut -s -f2,3,5,6,7` FIFO as the converter). Counts only, no content:
    raw rows and strictly-mapped events per US/Eastern day of [first-day, last-day], rows per operation, the stream
    checks the converter relies on, and the referenced index ids of the kept events of the base (train + val) and
    test days. Writes P_survey.json, P_ref.npz (arrays base / test, for --referenced) and P_sizes.json (kept events
    per day, for --day-sizes)."""
    import collections
    ap = argparse.ArgumentParser()
    for k in ("events", "first_day", "last_day", "base", "test", "out_prefix"):
        ap.add_argument("--" + k.replace("_", "-"), required=True)
    a = ap.parse_args(argv)
    d0, d1 = datetime.strptime(a.first_day, "%Y-%m-%d"), datetime.strptime(a.last_day, "%Y-%m-%d")
    days = [(d0 + timedelta(days=i)).strftime("%Y-%m-%d") for i in range((d1 - d0).days + 2)]   # + end boundary
    B = np.array([ns(f"{d} 00:00:00") for d in days], dtype=np.int64)
    days = days[:-1]
    base_k = np.array([days.index(d) for d in a.base.split(",")])
    test_k = np.array([days.index(d) for d in a.test.split(",")])
    ref = {"base": np.zeros(1 << 20, bool), "test": np.zeros(1 << 20, bool)}
    ops, rows_day, kept_day = collections.Counter(), collections.Counter(), collections.Counter()
    c = collections.Counter()
    opmap: dict[bytes, bool] = {}

    def mark(part, ids):
        if not len(ids):
            return
        m = int(ids.max()) + 1
        if m > len(ref[part]):
            ref[part] = np.concatenate([ref[part], np.zeros(max(m, 2 * len(ref[part])) - len(ref[part]), bool)])
        ref[part][ids] = True

    def flush(src, op, dst, uu, ts):
        joined = b"\n".join(uu)
        if len(joined) != 37 * len(uu) - 1 or len(UUID_RE.findall(joined)) != len(uu):
            c["bad_uuid"] += sum(1 for u in uu if not (len(u) == 36 and UUID_RE.fullmatch(u)))
        t = np.array(ts, dtype=np.int64)
        k = np.searchsorted(B, t, side="left") - 1
        on_b = np.isin(t, B)
        c["exactly_midnight"] += int(on_b.sum())
        ok = (k >= 0) & (k < len(days)) & ~on_b
        c["outside_days_or_null_ts"] += int((~ok).sum())
        mapped = np.array([opmap.setdefault(o, normalise_op(o.decode(), strict=True) is not None) for o in op])
        for o in op:
            ops[o] += 1
        for kk, n in zip(*np.unique(k[ok], return_counts=True)):
            rows_day[days[kk]] += int(n)
        sel = ok & mapped
        for kk, n in zip(*np.unique(k[sel], return_counts=True)):
            kept_day[days[kk]] += int(n)
        idx = np.nonzero(sel & (np.isin(k, base_k) | np.isin(k, test_k)))[0]
        s = [src[i] for i in idx]; d = [dst[i] for i in idx]
        bad = [x for x in s + d if not x.isdigit() or (len(x) > 1 and x[:1] == b"0")]
        c["noncanonical_index_ids"] += len(bad)
        si = np.array([int(x) if x.isdigit() else -1 for x in s], dtype=np.int64)
        di = np.array([int(x) if x.isdigit() else -1 for x in d], dtype=np.int64)
        kk = k[idx]
        for part, ks in (("base", base_k), ("test", test_k)):
            m = np.isin(kk, ks)
            for arr in (si[m], di[m]):
                mark(part, arr[arr >= 0])

    rows = 0
    src, op, dst, uu, ts = [], [], [], [], []
    with open(a.events, "rb") as fh:
        for line in fh:
            p = line.rstrip(b"\n").split(b"\t")
            src.append(p[0]); op.append(p[1]); dst.append(p[2]); uu.append(p[3])
            ts.append(int(p[4]) if p[4] != b"\\N" else -1)
            rows += 1
            if len(ts) == 2_000_000:
                flush(src, op, dst, uu, ts); src, op, dst, uu, ts = [], [], [], [], []
                if rows % 50_000_000 == 0:
                    log(f"survey: {rows} rows")
    if ts:
        flush(src, op, dst, uu, ts)
    rb, rt = np.nonzero(ref["base"])[0], np.nonzero(ref["test"])[0]
    np.savez_compressed(a.out_prefix + "_ref.npz", base=rb, test=rt)
    json.dump({d: kept_day[d] for d in days}, open(a.out_prefix + "_sizes.json", "w"), indent=1)
    res = {"rows": rows, "rows_per_day": {d: rows_day[d] for d in days if rows_day[d]},
           "mapped_per_day": {d: kept_day[d] for d in days if kept_day[d]},
           "ops": {o.decode(): n for o, n in ops.items()},
           "ops_dropped_by_strict_map": sorted(o.decode() for o, m in opmap.items() if not m),
           **{k: c[k] for k in ("outside_days_or_null_ts", "exactly_midnight", "bad_uuid", "noncanonical_index_ids")},
           "referenced_base": len(rb), "referenced_test": len(rt), "referenced_any": len(np.union1d(rb, rt)),
           "referenced_test_not_base": len(np.setdiff1d(rt, rb))}
    json.dump(res, open(a.out_prefix + "_survey.json", "w"), indent=1)
    log(json.dumps(res, indent=1))


def write_manifest(argv):
    """manifest --out <host dir> --dataset D --host H --platform P --dump PATH --train ... --val ... --test ...
    --stats stats.json --survey survey.json --referenced ref.npz --gt a.csv,b.csv [--gt-dir /gt] [--split-note ..] [--notes a;b]"""
    import collections
    from pdp_server.tools.darpa_eval import load_gt
    from pdp_server.tools.heldout_prep import format_notes
    ap = argparse.ArgumentParser()
    for k in ("out", "dataset", "host", "platform", "dump", "train", "val", "test", "stats", "survey", "referenced", "gt"):
        ap.add_argument(f"--{k}", required=True)
    ap.add_argument("--gt-dir", default="/gt"); ap.add_argument("--split-note", default=""); ap.add_argument("--notes", default="")
    ap.add_argument("--flags", default="", help="';'-separated")
    ap.add_argument("--verified", default="verified identical to PostgresReplay + ingest_day on a 5M-row sample (trace_e3_sample)",
                    help="how the stream path was checked against the database path for this dump")
    a = ap.parse_args(argv)
    train, test = a.train.split(","), a.test.split(",")
    stats, survey = json.load(open(a.stats)), json.load(open(a.survey))
    reg = WindowStore(os.path.join(a.out, "eval-test")).load_registry()
    base_n = len(WindowStore(os.path.join(a.out, "baseline")).load_registry())
    ops = collections.Counter()
    for d, v in stats.items():
        ops.update(v["events_by_type"])
        v["rows"] = survey["rows_per_day"].get(d, 0)
    z = np.load(a.referenced)
    refb, reft = set(map(str, z["base"].tolist())), set(map(str, z["test"].tolist()))
    gt = {}
    for f in [g for g in a.gt.split(",") if g]:
        ids = next(iter(load_gt(a.gt_dir, [f]).values()))
        found = {i for i in ids if i in reg.ids}
        miss = ids - found
        r = {"csv": f, "gt_nodes": len(ids), "found_in_eval_test_registry": len(found), "not_found": len(miss),
             "found_by_type": dict(collections.Counter(reg.entities[reg.ids[i]].ntype for i in found))}
        if miss:
            r["not_found_breakdown"] = {"no_kept_event_on_prepared_days_or_not_in_database": sum(1 for i in miss if i not in refb and i not in reft),
                                        "referenced_but_entity_missing": sum(1 for i in miss if i in refb or i in reft)}
        gt[os.path.basename(f)[:-4]] = r
    man = {
        "dataset": a.dataset, "host": a.host, "platform": a.platform,
        "database": f"not restored (disk): streamed from {a.dump} with pdp_server.tools.heldout_stream; {a.verified}",
        "source": "heldout_stream (PostgresReplay-equivalent)",
        "train_days": train, "val_day": a.val, "test_days": test, "split_rule": a.split_note,
        "flags": [f for f in a.flags.split(";") if f],
        "day_boundaries": "US/Eastern calendar days, timestamp_rec strictly inside (PostgresReplay / PIDSMaker graph construction)",
        "window": "15 min fused windows (WindowBuilder, chunks of 1024)",
        "entity_uuid": "framework index_id (orthrus ground truth column 3); label formats 'subject <exe> <cmdline>', 'file <path>', 'netflow <ip> <port>'",
        "eval_test_registry": "starts as a copy of the baseline registry (dense ids agree), extended by the test days",
        "ground_truth_dir": "/root/PIDSMaker/Ground_Truth/orthrus (= /data/gt/orthrus in the pdp containers)", "ground_truth": gt,
        "days": stats, "entities": {"baseline_registry": base_n, "eval_test_registry": len(reg)},
        "stream_checks": {k: survey[k] for k in ("rows", "ops", "outside_days_or_null_ts", "exactly_midnight", "bad_uuid", "noncanonical_index_ids")},
        "format_notes": {**format_notes(reg, ops), "notes": [n for n in a.notes.split(";") if n]},
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": "pdp_server.tools.heldout_stream",
    }
    json.dump(man, open(os.path.join(a.out, "manifest.json"), "w"), indent=1, default=str)
    log(f"manifest written: {os.path.join(a.out, 'manifest.json')}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "manifest":
        sys.exit(write_manifest(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "survey":
        sys.exit(survey(sys.argv[2:]))
    sys.exit(main())
