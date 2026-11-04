"""Raw-event partitions against a real telemetry database (run in a server container of a stack, e.g. staging):
  docker compose -p pdp-staging --env-file staging.env -f docker-compose.yml run --rm --no-deps -T -v $PWD/..:/src:ro \
      -e PYTHONPATH=/src/server:/src/engine --entrypoint python worker-ingest /src/tests/e2e/partitions_check.py"""
import sys
import uuid

from pdp_server import db

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


eid = str(uuid.uuid4())
s = db.init_telemetry(eid)
D = db.DAY_NS
base = 20_400 * D                        # some UTC day
rows = [(base + k * (D // 8), "a", "READ", "b", f"e{k}", "b1") for k in range(24)]   # 3 days, 8 rows each
try:
    with db.conn(db.TELEMETRY_DSN) as c:
        check(db.is_partitioned(c, s), "a new endpoint's raw events are partitioned")
        db.ensure_partitions(c, s, rows[0][0], rows[-1][0])
        db.ensure_partitions(c, s, rows[0][0], rows[-1][0])          # idempotent
        with c.cursor() as cur:
            cur.executemany(f"INSERT INTO {s}.events (ts_ns, src, op, dst, event_uuid, batch_id) VALUES (%s,%s,%s,%s,%s,%s)", rows)
            cur.execute("SELECT count(*) FROM pg_inherits i JOIN pg_class p ON p.oid=i.inhparent JOIN pg_namespace n ON n.oid=p.relnamespace WHERE n.nspname=%s AND p.relname='events'", (s,))
            check(cur.fetchone()[0] == 3, "three daily partitions")
    with db.conn(db.TELEMETRY_DSN) as c:      # a tz day: from the middle of day 0 to the middle of day 1
        dropped = db.delete_events(c, s, base + D // 2, base + D + D // 2)
        with c.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {s}.events"); left = cur.fetchone()[0]
        check(dropped == 0 and left == 24 - 8, f"a partial range deletes rows only ({left} left)")
    with db.conn(db.TELEMETRY_DSN) as c:      # the previous tz day: day 0 is now empty and dropped
        dropped = db.delete_events(c, s, base - D // 2, base + D // 2)
        with c.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {s}.events"); left = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM pg_inherits i JOIN pg_class p ON p.oid=i.inhparent JOIN pg_namespace n ON n.oid=p.relnamespace WHERE n.nspname=%s AND p.relname='events'", (s,))
            parts = cur.fetchone()[0]
        check(dropped == 1 and parts == 2 and left == 12, f"an emptied day is dropped as a table ({parts} partitions, {left} rows)")
    with db.conn(db.TELEMETRY_DSN) as c:
        dropped = db.delete_events(c, s, base + 2 * D, base + 3 * D)
        check(dropped == 1, "a whole day inside the range is dropped without deleting rows")
finally:
    db.drop_telemetry(eid)
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
