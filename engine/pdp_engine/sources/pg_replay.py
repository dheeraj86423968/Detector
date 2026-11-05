"""Replay source over a PIDSMaker-style DARPA TC database (cadets_e3, theia_e3, ...).

Yields entities and time-ordered events for a date range with the same filtering as the framework
(10 edge types, direction already normalised in the database). Used for benchmarks, parity tests and
the simulation harness.

DARPA OpTC (Windows, eCAR; databases optc_051 / optc_201 / optc_501) uses its own actions (OPEN, READ, CREATE,
MESSAGE, MODIFY, START, RENAME, DELETE, TERMINATE, WRITE). They are translated to the DARPA TC types with
PIDSMaker's context-dependent table (`OPTC_TO_TC_EDGE_MAP`: the action plus the source and destination node types),
so the same models run on both. Actions with no TC equivalent: creating, renaming or deleting a file count as a
write to it (the content or name changes; Linux agents record them as opens for writing), a process terminating is
dropped (process ends are lifecycle state for the product, not graph edges).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterator

import psycopg2
import pytz

from ..schema import EDGE_TYPE_ID, Entity, Event, normalise_op

TZ = pytz.timezone("US/Eastern")      # also OpTC's (Etc/GMT+4 in September 2019 = US/Eastern daylight time)

# PIDSMaker (pidsmaker/utils/dataset_utils.py, OPTC_TO_TC_EDGE_MAP): (source type, OpTC action, destination type)
# -> DARPA TC type; plus the product's choices for the OpTC-only actions (see the module docstring)
OPTC_TO_TC = {
    ("subject", "CREATE", "subject"): "CLONE", ("subject", "START", "subject"): "CLONE",
    ("subject", "OPEN", "subject"): "OPEN",
    ("subject", "MODIFY", "file"): "WRITE", ("subject", "WRITE", "file"): "WRITE",
    ("subject", "MESSAGE", "netflow"): "SENDMSG", ("subject", "START", "netflow"): "CONNECT",
    ("file", "READ", "subject"): "READ",
    ("netflow", "MESSAGE", "subject"): "RECVMSG", ("netflow", "OPEN", "subject"): "OPEN",
    ("netflow", "START", "subject"): "RECVFROM",
    ("subject", "CREATE", "file"): "WRITE", ("subject", "RENAME", "file"): "WRITE", ("subject", "DELETE", "file"): "WRITE",
}


def optc_op(op: str, src_type: str | None, dst_type: str | None) -> str | None:
    """An OpTC action between nodes of these types -> the product's edge type, or None (dropped)."""
    return OPTC_TO_TC.get((src_type, str(op).upper(), dst_type))


def ns(date_str: str) -> int:
    """'YYYY-MM-DD HH:MM:SS' in US/Eastern -> ns since epoch (framework convention)."""
    dt = TZ.localize(datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S"))
    return int(dt.timestamp() * 1_000_000_000)


class PostgresReplay:
    def __init__(self, database: str, host: str = "postgres", user: str = "postgres", password: str = "postgres", port: int = 5432):
        self.con = psycopg2.connect(dbname=database, host=host, user=user, password=password, port=port)
        self.optc = database.lower().startswith("optc")
        self._types: dict[str, str] | None = None

    def node_types(self) -> dict[str, str]:
        """index id -> subject | file | netflow (OpTC's actions are translated by the types they connect)."""
        if self._types is None:
            cur = self.con.cursor()
            t: dict[str, str] = {}
            for table, kind in (("subject_node_table", "subject"), ("file_node_table", "file"), ("netflow_node_table", "netflow")):
                cur.execute(f"SELECT index_id FROM {table}")
                for (i,) in cur:
                    t[str(i)] = kind
            self._types = t
        return self._types

    def entities(self) -> Iterator[Entity]:
        cur = self.con.cursor()
        cur.execute("SELECT node_uuid, index_id, path, cmd FROM subject_node_table")
        for uuid, idx, path, cmd in cur:
            yield Entity.process(str(idx), str(path), str(cmd), raw_uuid=uuid)
        cur.execute("SELECT node_uuid, index_id, path FROM file_node_table")
        for uuid, idx, path in cur:
            yield Entity.file(str(idx), str(path), raw_uuid=uuid)
        cur.execute("SELECT node_uuid, index_id, src_addr, src_port, dst_addr, dst_port FROM netflow_node_table")
        for uuid, idx, sa, sp, da, dp in cur:
            yield Entity.socket(str(idx), str(da), str(dp), raw_uuid=uuid, local_ip=str(sa), local_port=str(sp))

    def entity_index(self) -> dict[str, Entity]:
        """uuid (framework index id) -> Entity, for lazy registration of entities on first sight."""
        return {e.uuid: e for e in self.entities()}

    def events(self, date: str, name: str = "replay") -> Iterator[Event]:
        """Time-ordered events of one day (date 'YYYY-MM-DD'), using the framework's ordering."""
        t0 = ns(f"{date} 00:00:00")
        t1 = ns(f"{(datetime.strptime(date, '%Y-%m-%d') + timedelta(days=1)).strftime('%Y-%m-%d')} 00:00:00")
        cur = self.con.cursor(name=f"{name}_{date}")
        cur.itersize = 200_000
        cur.execute("SELECT src_index_id, operation, dst_index_id, event_uuid, timestamp_rec FROM event_table "
                    "WHERE timestamp_rec > %s AND timestamp_rec < %s ORDER BY timestamp_rec, event_uuid", (t0, t1))
        types = self.node_types() if self.optc else None
        for s, op, d, uuid, t in cur:
            if types is not None:
                e = optc_op(op, types.get(str(s)), types.get(str(d)))
            else:
                e = normalise_op(op, strict=True)
            if e is None:
                continue
            yield Event(int(t), str(s), e, str(d), uuid)
        cur.close()
