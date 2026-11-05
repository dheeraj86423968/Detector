"""DARPA OpTC replay: every OpTC action PIDSMaker builds its graphs from (possible_events_optc) maps to one of the
product's edge types, except process termination (dropped on purpose), following PIDSMaker's OpTC -> TC table."""
import sys

from pdp_engine.schema import EDGE_TYPE_ID
from pdp_engine.sources.pg_replay import optc_op

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


# PIDSMaker possible_events_optc ((source type, destination type) -> actions), copied
possible = {("subject", "subject"): ["CREATE", "OPEN", "TERMINATE"],
            ("subject", "file"): ["CREATE", "DELETE", "MODIFY", "RENAME", "WRITE"],
            ("subject", "netflow"): ["MESSAGE", "START"],
            ("file", "subject"): ["READ"],
            ("netflow", "subject"): ["MESSAGE", "OPEN", "START"]}
unmapped = [(s, a, d) for (s, d), acts in possible.items() for a in acts if optc_op(a, s, d) is None]
check(unmapped == [("subject", "TERMINATE", "subject")], f"every OpTC action maps, except process termination ({unmapped})")
check(all(optc_op(a, s, d) in EDGE_TYPE_ID for (s, d), acts in possible.items() for a in acts if optc_op(a, s, d)),
      "translations are product edge types")
# PIDSMaker's OPTC_TO_TC_EDGE_MAP, spot checks (context decides: START is a process start or a connection)
check(optc_op("START", "subject", "subject") == "CLONE" and optc_op("START", "subject", "netflow") == "CONNECT"
      and optc_op("START", "netflow", "subject") == "RECVFROM", "START by context: process start, outbound and inbound connection")
check(optc_op("READ", "file", "subject") == "READ" and optc_op("MESSAGE", "netflow", "subject") == "RECVMSG"
      and optc_op("MESSAGE", "subject", "netflow") == "SENDMSG", "reads and messages keep their direction")
check(optc_op("read", "file", "subject") == "READ" and optc_op("READ", None, "subject") is None, "case-insensitive; unknown node types dropped")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
