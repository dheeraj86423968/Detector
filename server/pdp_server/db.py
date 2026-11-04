"""Postgres access for the server (platform DB) and the telemetry DB (one schema per endpoint)."""
from __future__ import annotations

import os
import re
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
import psycopg2.pool

def _dsn(name: str, db: str, host: str) -> str:
    """Explicit PDP_<NAME>_DSN, else built from PDP_DB_PASSWORD (a generated secret in deploy/.env)."""
    if os.environ.get(f"PDP_{name}_DSN"):
        return os.environ[f"PDP_{name}_DSN"]
    pw = os.environ.get("PDP_DB_PASSWORD", "pdp")
    return f"dbname={db} user=pdp password={pw} host={host}"


PLATFORM_DSN = _dsn("PLATFORM", "platform", "platform-db")
TELEMETRY_DSN = _dsn("TELEMETRY", "telemetry", "telemetry-db")

_pools: dict[str, psycopg2.pool.ThreadedConnectionPool] = {}


def pool(dsn: str) -> psycopg2.pool.ThreadedConnectionPool:
    if dsn not in _pools:
        _pools[dsn] = psycopg2.pool.ThreadedConnectionPool(1, 16, dsn)
    return _pools[dsn]


@contextmanager
def conn(dsn: str = PLATFORM_DSN):
    p = pool(dsn)
    c = p.getconn()
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        p.putconn(c)


def q(c, sql: str, args=(), one=False):
    with c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, args)
        if cur.description is None:
            return None
        return cur.fetchone() if one else cur.fetchall()


def init_platform(schema_path: str) -> bool:
    """Apply schema.sql (and, via the caller, the telemetry DDL) once per schema version. Even an
    `ALTER TABLE ... IF NOT EXISTS` takes an exclusive table lock, so re-running DDL on every start would block - or
    deadlock with - the replicas still serving during a rolling update. Returns True when the DDL was applied."""
    import hashlib
    ddl = open(schema_path).read()
    digest = hashlib.sha256((ddl + TELEMETRY_DDL).encode()).hexdigest()
    with conn() as c:
        with c.cursor() as cur:
            cur.execute("SELECT to_regclass('public.kv') IS NOT NULL")
            if cur.fetchone()[0]:
                cur.execute("SELECT v FROM kv WHERE k='schema_sha256'")
                row = cur.fetchone()
                if row and row[0] == digest:
                    return False
            cur.execute("SET LOCAL lock_timeout = '15s'")   # fail this start (the old replicas keep serving) rather than queue behind traffic
            cur.execute(ddl)
            cur.execute("INSERT INTO kv (k, v, updated_at) VALUES ('schema_sha256', to_jsonb(%s::text), now()) "
                        "ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v, updated_at=now()", (digest,))
    return True


# ---- telemetry: one schema per endpoint -------------------------------------------------
def tschema(endpoint_id: str) -> str:
    s = "ep_" + re.sub(r"[^0-9a-f]", "", endpoint_id.lower())
    if len(s) != 35:
        raise ValueError("bad endpoint id")
    return s


TELEMETRY_DDL = """
CREATE SCHEMA IF NOT EXISTS {s};
CREATE TABLE IF NOT EXISTS {s}.entities (uuid TEXT PRIMARY KEY, dense_id INT UNIQUE, ntype TEXT NOT NULL, label TEXT NOT NULL, display JSONB);
CREATE SEQUENCE IF NOT EXISTS {s}.dense_seq START 0 MINVALUE 0;
CREATE TABLE IF NOT EXISTS {s}.events (ts_ns BIGINT NOT NULL, src TEXT NOT NULL, op TEXT NOT NULL, dst TEXT NOT NULL, event_uuid TEXT NOT NULL,
                                       batch_id TEXT NOT NULL) PARTITION BY RANGE (ts_ns);
ALTER TABLE {s}.events DROP CONSTRAINT IF EXISTS events_pkey;
CREATE INDEX IF NOT EXISTS {s}_events_ts ON {s}.events (ts_ns);
"""


# Raw baseline events are partitioned by UTC day (endpoints created from server 0.6; older ones keep one table until
# they finish learning): a day that has been cut into windows is dropped as a table instead of deleted row by row
# (on a busy host 60 M rows a day - slow, and it bloats the table). Partitions are created as uploads need them.
DAY_NS = 86400 * 10**9


def is_partitioned(c, s: str) -> bool:
    with c.cursor() as cur:
        cur.execute("SELECT c.relkind = 'p' FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname='events'", (s,))
        r = cur.fetchone()
    return bool(r and r[0])


def ensure_partitions(c, s: str, lo_ns: int, hi_ns: int) -> None:
    """Daily partitions covering [lo_ns, hi_ns] (no-op for an unpartitioned table). Looked up in the catalog on every
    upload (no cache: the worker drops partitions of days already cut into windows)."""
    days = range(int(lo_ns) // DAY_NS, int(hi_ns) // DAY_NS + 1)
    if not is_partitioned(c, s):
        return
    with c.cursor() as cur:
        cur.execute("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class p ON p.oid=i.inhparent "
                    "JOIN pg_namespace n ON n.oid=p.relnamespace WHERE n.nspname=%s AND p.relname='events'", (s,))
        known = {int(r[0].rsplit("_d", 1)[1]) for r in cur.fetchall()}
    import psycopg2
    for d in days:
        if d in known:
            continue
        with c.cursor() as cur:
            try:
                cur.execute("SAVEPOINT p")
                cur.execute(f"CREATE TABLE IF NOT EXISTS {s}.events_d{d} PARTITION OF {s}.events FOR VALUES FROM ({d * DAY_NS}) TO ({(d + 1) * DAY_NS})")
                cur.execute("RELEASE SAVEPOINT p")
            except psycopg2.Error:            # created concurrently by the other API replica
                cur.execute("ROLLBACK TO SAVEPOINT p")



def delete_events(c, s: str, t0: int, t1: int) -> int:
    """Delete raw events with t0 <= ts_ns < t1: partitions entirely inside are dropped, the rest deleted; partitions
    that end before t1 and are empty afterwards are dropped too. Returns partitions dropped."""
    dropped = 0
    with c.cursor() as cur:
        if not is_partitioned(c, s):
            cur.execute(f"DELETE FROM {s}.events WHERE ts_ns >= %s AND ts_ns < %s", (t0, t1))
            return 0
        cur.execute("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class p ON p.oid=i.inhparent "
                    "JOIN pg_namespace n ON n.oid=p.relnamespace WHERE n.nspname=%s AND p.relname='events'", (s,))
        parts = [r[0] for r in cur.fetchall()]
        for name in parts:
            d = int(name.rsplit("_d", 1)[1])
            lo, hi = d * DAY_NS, (d + 1) * DAY_NS
            if lo >= t0 and hi <= t1:
                cur.execute(f"DROP TABLE {s}.{name}"); dropped += 1
            elif lo < t1 and hi > t0:
                cur.execute(f"DELETE FROM {s}.{name} WHERE ts_ns >= %s AND ts_ns < %s", (t0, t1))
                cur.execute(f"SELECT 1 FROM {s}.{name} LIMIT 1")
                if cur.fetchone() is None:          # emptied (the rest of its day went with an earlier day): drop it;
                    cur.execute(f"DROP TABLE {s}.{name}"); dropped += 1   # an upload would simply recreate it
    return dropped


def init_telemetry(endpoint_id: str) -> str:
    s = tschema(endpoint_id)
    with conn(TELEMETRY_DSN) as c:
        with c.cursor() as cur:
            cur.execute(TELEMETRY_DDL.format(s=s))
    return s


def drop_telemetry(endpoint_id: str) -> None:
    s = tschema(endpoint_id)
    with conn(TELEMETRY_DSN) as c:
        with c.cursor() as cur:
            cur.execute(f"DROP SCHEMA IF EXISTS {s} CASCADE")
