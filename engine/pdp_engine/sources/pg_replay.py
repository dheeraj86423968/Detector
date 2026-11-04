"""Replay source over a PIDSMaker-style DARPA TC database (cadets_e3, theia_e3, ...).

Yields entities and time-ordered events for a date range with the same filtering as the framework
(10 edge types, direction already normalised in the database). Used for benchmarks, parity tests and
the simulation harness.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterator

import psycopg2
import pytz

from ..schema import EDGE_TYPE_ID, Entity, Event, normalise_op

TZ = pytz.timezone("US/Eastern")


def ns(date_str: str) -> int:
    """'YYYY-MM-DD HH:MM:SS' in US/Eastern -> ns since epoch (framework convention)."""
    dt = TZ.localize(datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S"))
    return int(dt.timestamp() * 1_000_000_000)


class PostgresReplay:
    def __init__(self, database: str, host: str = "postgres", user: str = "postgres", password: str = "postgres", port: int = 5432):
        self.con = psycopg2.connect(dbname=database, host=host, user=user, password=password, port=port)

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
        for s, op, d, uuid, t in cur:
            e = normalise_op(op, strict=True)
            if e is None:
                continue
            yield Event(int(t), str(s), e, str(d), uuid)
        cur.close()
