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
                                       batch_id TEXT NOT NULL);
ALTER TABLE {s}.events DROP CONSTRAINT IF EXISTS events_pkey;
CREATE INDEX IF NOT EXISTS {s}_events_ts ON {s}.events (ts_ns);
"""


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
