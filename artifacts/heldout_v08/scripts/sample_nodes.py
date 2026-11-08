"""argv: sample dir, node-stream path (pg_restore -a of the three node tables). Keep raw COPY rows whose index_id (last
column) is referenced by <dir>/events.copy (full 8-column event rows). Writes <dir>/<table>.copy and <dir>/nodes.stream
(headers + kept rows + '\\.', as pg_restore emits) for heldout_stream --nodes."""
import re, sys
d, src = sys.argv[1], sys.argv[2]
ids = set()
for line in open(f"{d}/events.copy", "rb"):
    p = line.rstrip(b"\n").split(b"\t")
    ids.add(p[1]); ids.add(p[4])
print("sample referenced ids", len(ids), flush=True)
out = {}; table = None; stream = open(f"{d}/nodes.stream", "wb"); kept = {}
for raw in open(src, "rb"):
    if table is None:
        m = re.match(rb"COPY public\.(\w+) .*FROM stdin;", raw)
        if m:
            table = m.group(1).decode(); out[table] = open(f"{d}/{table}.copy", "wb"); kept[table] = 0
            stream.write(raw)
        continue
    if raw.rstrip(b"\n") == b"\\.":
        stream.write(raw); table = None; continue
    if raw.rstrip(b"\n").rsplit(b"\t", 1)[1] in ids:
        out[table].write(raw); stream.write(raw); kept[table] += 1
print("kept", kept)
