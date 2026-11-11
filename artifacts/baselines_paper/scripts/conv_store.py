"""Convert one lab host (our WindowStore: registry.json + windows/<day>/*.npz of fused edges) into a NEW PostgreSQL
database in PIDSMaker's schema, so that PIDSMaker and ProvFusion see exactly the nodes, edges, days and ids our lab
used. Read-only on the lab store. Mapping:
  node tables  : index_id = our entity uuid (= the framework index_id, ground-truth CSV column 3);
                 node_uuid = display.raw_uuid (else the uuid); hash_id = str(index_id) (events reference hash_id)
                 subject.path = label without the 'subject ' prefix (our label is '<exe or None> <cmdline or None>';
                 both PIDSMaker and ProvFusion concatenate path and cmd before tokenising), subject.cmd = ''
                 file.path = label without 'file '; netflow: label 'netflow <ip> <port>' -> dst_addr/dst_port
                 (the columns both systems read as the remote end), src_addr/src_port = ''
  event_table  : one row per fused edge of the days in the manifest's train + val + test lists (baseline store for
                 train/val, eval-test store for test), operation = 'EVENT_' + our edge type (our 10 types are the
                 10 types of both systems' relation vocabulary), timestamp_rec = the fused edge's time (first
                 event of the run), event_uuid = its first event's uuid.
Fused edges are the ORTHRUS consecutive-duplicate collapse per (src,dst) within 15-min windows; both systems apply
the same collapse (fuse_edge / per-day fusion), which is idempotent across a time partition, so they reconstruct
the same graphs as from the raw events (modulo the windows). Usage:
  conv_store.py --set /data/heldout/X/h --db bl_x [--gt-csv rel.csv ...] --gt-out DIR"""
import argparse, csv, io, json, os, sys, time
import numpy as np, psycopg2
EDGE_TYPES = ["CONNECT", "EXECUTE", "OPEN", "READ", "RECVFROM", "RECVMSG", "SENDMSG", "SENDTO", "WRITE", "CLONE"]
ap = argparse.ArgumentParser(); ap.add_argument("--set", required=True); ap.add_argument("--db", required=True)
ap.add_argument("--gt-csv", nargs="*", default=[]); ap.add_argument("--gt-out", default=""); ap.add_argument("--gt-name", default="")
a = ap.parse_args()
log = lambda m: print(time.strftime("%H:%M:%S"), m, flush=True)
man = json.load(open(os.path.join(a.set, "manifest.json")))
H = dict(host=os.environ.get("DB_HOST", "postgres"), user="postgres", password="postgres")
c0 = psycopg2.connect(database="postgres", **H); c0.autocommit = True
cur0 = c0.cursor(); cur0.execute("select 1 from pg_database where datname=%s", (a.db,))
assert cur0.fetchone() is None, f"database {a.db} exists; refusing to touch it"
cur0.execute(f"CREATE DATABASE {a.db}"); c0.close()
con = psycopg2.connect(database=a.db, **H); cur = con.cursor()
cur.execute("""CREATE TABLE event_table (src_node varchar, src_index_id varchar, operation varchar, dst_node varchar,
 dst_index_id varchar, event_uuid varchar NOT NULL, timestamp_rec bigint, _id bigserial NOT NULL);
CREATE TABLE file_node_table (node_uuid varchar NOT NULL, hash_id varchar NOT NULL, path varchar, index_id bigint);
CREATE TABLE netflow_node_table (node_uuid varchar NOT NULL, hash_id varchar NOT NULL, src_addr varchar, src_port varchar,
 dst_addr varchar, dst_port varchar, index_id bigint);
CREATE TABLE subject_node_table (node_uuid varchar NOT NULL, hash_id varchar NOT NULL, path varchar, cmd varchar, index_id bigint);""")
con.commit()
def esc(x):
    return str(x).replace("\\", "\\\\").replace("\t", " ").replace("\n", " ").replace("\r", " ")
log("loading registry")
ents = json.load(open(os.path.join(a.set, "eval-test", "registry.json")))["entities"]
uuid_of = np.array([int(e["uuid"]) for e in ents], dtype=np.int64)
bufs = {"subject": io.StringIO(), "file": io.StringIO(), "netflow": io.StringIO()}
cnt = {"subject": 0, "file": 0, "netflow": 0}
for e in ents:
    t, lab, u = e["ntype"], e["label"], e["uuid"]
    nu = esc((e.get("display") or {}).get("raw_uuid") or u)
    if t == "subject":
        bufs[t].write(f"{nu}\t{u}\t{esc(lab[len('subject '):])}\t\t{u}\n")
    elif t == "file":
        bufs[t].write(f"{nu}\t{u}\t{esc(lab[len('file '):])}\t{u}\n")
    else:
        rest = lab[len("netflow "):]
        ip, _, port = rest.rpartition(" ") if " " in rest else (rest, "", "")
        bufs[t].write(f"{nu}\t{u}\t\t\t{esc(ip)}\t{esc(port)}\t{u}\n")
    cnt[t] += 1
del ents
for t, b in bufs.items():
    b.seek(0); cur.copy_expert(f"COPY {t}_node_table FROM STDIN", b)
con.commit(); bufs = None
log(f"nodes {cnt}")
days = [(d, "baseline") for d in man["train_days"] + [man["val_day"]]] + [(d, "eval-test") for d in man["test_days"]]
stats = {}
for d, store in days:
    wd = os.path.join(a.set, store, "windows", d)
    n = 0; b = io.StringIO()
    for f in sorted(os.listdir(wd)):
        z = np.load(os.path.join(wd, f), allow_pickle=False)
        su, du = uuid_of[z["src"]], uuid_of[z["dst"]]
        for s, dd, tt, et, eu in zip(su.tolist(), du.tolist(), z["t"].tolist(), z["etype"].tolist(), z["uuid"].tolist()):
            b.write(f"{s}\t{s}\tEVENT_{EDGE_TYPES[et]}\t{dd}\t{dd}\t{esc(eu)}\t{tt}\n")
        n += len(su)
        if b.tell() > 200_000_000:
            b.seek(0); cur.copy_expert("COPY event_table (src_node,src_index_id,operation,dst_node,dst_index_id,event_uuid,timestamp_rec) FROM STDIN", b); b = io.StringIO()
    b.seek(0); cur.copy_expert("COPY event_table (src_node,src_index_id,operation,dst_node,dst_index_id,event_uuid,timestamp_rec) FROM STDIN", b)
    con.commit(); stats[d] = n; log(f"{d} ({store}): {n} fused edges")
cur.execute("CREATE INDEX ON event_table (timestamp_rec)"); con.commit()
gt = {}
if a.gt_csv:
    ids = set(uuid_of.tolist())
    os.makedirs(a.gt_out, exist_ok=True)
    for rel in a.gt_csv:
        rows = [r for r in csv.reader(open(os.path.join("/gt", rel))) if len(r) >= 3 and r[2].strip()]
        keep = [r for r in rows if int(r[2]) in ids]
        name = (a.gt_name or "") + os.path.basename(rel)
        with open(os.path.join(a.gt_out, name), "w", newline="") as f:
            csv.writer(f).writerows(keep)
        gt[name] = {"csv_rows": len(rows), "in_host": len(keep)}
cur.execute(f"select pg_database_size('{a.db}')"); size = cur.fetchone()[0]
rep = {"set": a.set, "db": a.db, "nodes": cnt, "fused_edges_per_day": stats, "gt": gt, "db_bytes": size,
       "train_days": man["train_days"], "val_day": man["val_day"], "test_days": man["test_days"]}
json.dump(rep, open(os.path.join(a.gt_out or ".", f"conv_{a.db}.json"), "w"), indent=1)
log(json.dumps(rep))
