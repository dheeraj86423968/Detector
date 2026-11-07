"""Replay source over PIDSMaker's Carbon Black EDR databases (atlasv2_edr, carbanakv2_edr).

These databases use the DARPA TC table layout (subject / file / netflow node tables, event_table with
src_index_id / operation / dst_index_id / event_uuid / timestamp_rec), so entities, uuids (the framework index id),
day boundaries (US/Eastern, as PIDSMaker's graph construction) and the event order (timestamp_rec, event_uuid) are
exactly PostgresReplay's. Only the operation vocabulary differs: Carbon Black's 33 event types
(PIDSMaker `rel2id_graph_processor_carbon_black_edr`) instead of DARPA TC's EVENT_*; the strict TC mapping would
drop every event.

Each Carbon Black type is translated by (source type, operation, destination type), like OpTC in pg_replay, to the
product's edge types in the direction the product's own collectors emit them (pdp_agent/sources/common.py,
windows_etw.py: CLONE parent -> child, OPEN / READ / EXECUTE file -> process, WRITE process -> file, CONNECT /
SENDMSG process -> socket, RECVMSG socket -> process). In the database FILE_OPENED and REGISTRY_KEY_OPENED are stored
process -> file; they are emitted file -> process (the product's OPEN direction).

  process   PROCESS_EXECUTED -> CLONE (parent -> child, as OpTC START/CREATE); CROSS_PROCESS_INTERACTION -> OPEN (as
            OpTC's process OPEN process); PROCESS_KILLED dropped (lifecycle, as OpTC TERMINATE)
  file      FILE_OPENED -> OPEN; FILE_READ -> READ; MODULE_LOADED -> READ (a library is read into the process; the
            Linux collectors see library loads as open/read too); FILE_CREATED / WRITTEN / TRUNCATED / DELETED /
            RENAMED / COPIED / LINKED / RESTORED -> WRITE (content or name changes; the product's OpTC choice);
            FILE_CLOSED dropped (lifecycle)
  registry  registry keys/values are file nodes in these databases (paths like HKLM\\SOFTWARE\\...).
            REGISTRY_KEY_OPENED -> OPEN; REGISTRY_KEY_LOADED / REGISTRY_VALUE_READ -> READ; key or value created /
            written / deleted / renamed / replaced / restored -> WRITE; REGISTRY_KEY_CLOSED / UNLOADED dropped.
            `registry=False` drops all registry events instead.
  network   NETFLOW_CREATED / NETFLOW_CONNECTED -> CONNECT (as OpTC START flow); NETFLOW_PACKET_SENT -> SENDMSG;
            NETFLOW_PACKET_RECEIVED -> RECVMSG; NETFLOW_DISCONNECTED dropped (lifecycle)

There is no EXECUTE edge: Carbon Black process events carry the image path on the process node but there is no
executable file node (the product's Windows layers already handle collectors without EXECUTE events).

Any (type, operation, type) combination not listed is dropped (strict, like the TC replay).

Multi-host databases: the node tables have no host column. `nodes` restricts the replay to one host's nodes (see
pdp_server.tools.heldout_prep.host_partition: connected components of the provenance graph); events are kept when
both endpoints belong to the set.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterator

from ..schema import Event
from .pg_replay import PostgresReplay, ns

_W, _R = "WRITE", "READ"
# (source type, Carbon Black operation, destination type) -> (product edge type, reverse the direction)
CB_TO_TC: dict[tuple[str, str, str], tuple[str, bool]] = {
    ("subject", "PROCESS_EXECUTED", "subject"): ("CLONE", False),
    ("subject", "CROSS_PROCESS_INTERACTION", "subject"): ("OPEN", False),
    ("subject", "FILE_OPENED", "file"): ("OPEN", True),
    ("file", "FILE_READ", "subject"): (_R, False),
    ("file", "MODULE_LOADED", "subject"): (_R, False),
    **{("subject", op, "file"): (_W, False) for op in (
        "FILE_CREATED", "FILE_WRITTEN", "FILE_TRUNCATED", "FILE_DELETED", "FILE_RENAMED", "FILE_COPIED",
        "FILE_LINKED", "FILE_RESTORED")},
    ("subject", "NETFLOW_CREATED", "netflow"): ("CONNECT", False),
    ("subject", "NETFLOW_CONNECTED", "netflow"): ("CONNECT", False),
    ("subject", "NETFLOW_PACKET_SENT", "netflow"): ("SENDMSG", False),
    ("netflow", "NETFLOW_PACKET_RECEIVED", "subject"): ("RECVMSG", False),
}
CB_REGISTRY: dict[tuple[str, str, str], tuple[str, bool]] = {
    ("subject", "REGISTRY_KEY_OPENED", "file"): ("OPEN", True),
    ("file", "REGISTRY_KEY_LOADED", "subject"): (_R, False),
    ("file", "REGISTRY_VALUE_READ", "subject"): (_R, False),
    **{("subject", op, "file"): (_W, False) for op in (
        "REGISTRY_KEY_CREATED", "REGISTRY_KEY_DELETED", "REGISTRY_KEY_RENAMED", "REGISTRY_KEY_REPLACED",
        "REGISTRY_KEY_RESTORED", "REGISTRY_VALUE_CREATED", "REGISTRY_VALUE_WRITTEN", "REGISTRY_VALUE_DELETED")},
}


def cb_op(op: str, src_type: str | None, dst_type: str | None, registry: bool = True) -> tuple[str, bool] | None:
    """A Carbon Black event between nodes of these types -> (product edge type, reversed?), or None (dropped)."""
    k = (src_type, str(op).upper(), dst_type)
    return CB_TO_TC.get(k) or (CB_REGISTRY.get(k) if registry else None)


class EdrPostgresReplay(PostgresReplay):
    """PostgresReplay for the Carbon Black EDR databases; optionally restricted to one host's nodes."""

    def __init__(self, database: str, nodes: set[str] | None = None, registry: bool = True, **kw):
        super().__init__(database, **kw)
        self.optc = False
        self.nodes, self.registry = nodes, registry

    def events(self, date: str, name: str = "replay") -> Iterator[Event]:
        t0 = ns(f"{date} 00:00:00")
        t1 = ns(f"{(datetime.strptime(date, '%Y-%m-%d') + timedelta(days=1)).strftime('%Y-%m-%d')} 00:00:00")
        cur = self.con.cursor(name=f"{name}_{date}")
        cur.itersize = 200_000
        cur.execute("SELECT src_index_id, operation, dst_index_id, event_uuid, timestamp_rec FROM event_table "
                    "WHERE timestamp_rec > %s AND timestamp_rec < %s ORDER BY timestamp_rec, event_uuid", (t0, t1))
        types, nodes = self.node_types(), self.nodes
        for s, op, d, uuid, t in cur:
            s, d = str(s), str(d)
            if nodes is not None and (s not in nodes or d not in nodes):
                continue
            m = cb_op(op, types.get(s), types.get(d), self.registry)
            if m is None:
                continue
            e, rev = m
            yield Event(int(t), d, e, s, uuid) if rev else Event(int(t), s, e, d, uuid)
        cur.close()
