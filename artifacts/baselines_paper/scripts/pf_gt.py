"""Ground truth for ProvFusion runs: ORTHRUS/PIDSMaker node CSVs (column 3 = index_id) -> <out>/<DS>_gt_nids.pt
(sorted list of index ids) and <out>/<DS>_attack_to_nids.pt ({attack: {"nids": [...], "time_range": []}}), the two
formats ProvFusion's evaluation reads. Checks every id exists in the database's node tables and that node_uuid
(column 1) agrees with the database. Usage: pf_gt.py DS DB --out DIR csv1 csv2 ...  (paths relative to /gt)"""
import argparse, csv, json, os, sys
import psycopg2, torch
ap = argparse.ArgumentParser(); ap.add_argument("ds"); ap.add_argument("db"); ap.add_argument("--out", required=True)
ap.add_argument("--by-uuid", action="store_true", help="resolve column 1 (node UUID) instead of column 3 (index_id)")
ap.add_argument("--db-name-prefix", default=""); ap.add_argument("csvs", nargs="+"); a = ap.parse_args()
con = psycopg2.connect(database=a.db, host=os.environ.get("DB_HOST", "postgres"), user="postgres", password="postgres")
cur = con.cursor()
amap, allids, rep = {}, set(), {}
for f in a.csvs:
    rows = [r for r in csv.reader(open(os.path.join("/gt", f))) if len(r) >= 1 and r[0].strip()]
    if a.by_uuid:
        res = []
        for r in rows:
            hit = None
            for t in ("subject_node_table", "file_node_table", "netflow_node_table"):
                cur.execute(f"select index_id from {t} where node_uuid=%s", (r[0].strip(),))
                x = cur.fetchone()
                if x:
                    hit = x[0]; break
            if hit is not None:
                res.append([r[0], r[1] if len(r) > 1 else "", str(hit)])
        rep_missing = len(rows) - len(res); rows = res
    rows = [r for r in rows if len(r) >= 3 and r[2].strip()]
    ids = sorted({int(r[2]) for r in rows})
    found, uuid_ok = 0, 0
    for r in rows:
        for t in ("subject_node_table", "file_node_table", "netflow_node_table"):
            cur.execute(f"select node_uuid from {t} where index_id=%s", (int(r[2]),))
            x = cur.fetchone()
            if x:
                found += 1; uuid_ok += int(x[0].upper() == r[0].upper()); break
    name = os.path.basename(f)[:-4]
    amap[name] = {"nids": ids, "time_range": []}
    allids |= set(ids)
    rep[name] = {"uuid_not_in_db": rep_missing if a.by_uuid else None, "rows": len(rows), "ids": len(ids), "found_in_db": found, "node_uuid_matches": uuid_ok}
os.makedirs(a.out, exist_ok=True)
torch.save(sorted(allids), os.path.join(a.out, f"{a.ds}_gt_nids.pt"))
torch.save(amap, os.path.join(a.out, f"{a.ds}_attack_to_nids.pt"))
json.dump(rep, open(os.path.join(a.out, f"{a.ds}_gt_report.json"), "w"), indent=1)
print(json.dumps(rep, indent=1), len(allids))
