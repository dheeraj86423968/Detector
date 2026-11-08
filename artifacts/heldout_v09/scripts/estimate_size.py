"""Disk-size estimate for the conversion (counting only; no content is stored, nothing is scored).

argv: events FIFO (same `cut -s -f2,3,5,6,7` stream as the converter), sizes json (survey), days (comma list), out json.
One pass with heldout_stream.collect_days (the converter's own event collection); per day the kept events are put in the
replay order (timestamp_rec, event_uuid), cut into windows with WindowBuilder's chunk rule (chunks of 1024, a window
closes when a chunk's last timestamp is > 15 min after the window start; next start = that timestamp), and fused edges
are counted as in windows.fuse (per (src, dst) pair, in time order, runs of the same operation count once).
Approximation: events the converter would drop for an unknown endpoint entity are counted here (THEIA_E5: 0 dropped).
Bytes: each fused edge is stored as src/dst/t/etype int64 + uuid <U36 = 176 B (np.savez, uncompressed)."""
import json, sys
import numpy as np
from pdp_server.tools.heldout_stream import collect_days, WINDOW_NS

ev, sizes_p, days, out = sys.argv[1], sys.argv[2], sys.argv[3].split(","), sys.argv[4]
sizes = json.load(open(sizes_p))
cols, names = collect_days(ev, days, sizes)
res = {}
for d in days:
    t, s, dd, oc, uh, ul = cols[d]
    o = np.lexsort((ul, uh, t))
    t, s, dd, oc = t[o], s[o], dd[o], oc[o]
    n = len(t)
    # window boundaries (indices where a window ends, exclusive)
    ends, start = [], (int(t[0]) if n else 0)
    for c_end in range(1024, n + 1024, 1024):
        e = min(c_end, n)
        last_t = int(t[e - 1])
        if last_t > start + WINDOW_NS or e == n:
            ends.append(e); start = last_t
    fused, a = 0, 0
    for e in ends:
        pair = s[a:e] * (1 << 32) + dd[a:e]
        k = np.argsort(pair, kind="stable")
        p, q = pair[k], oc[a:e][k]
        fused += 1 + int(((p[1:] != p[:-1]) | (q[1:] != q[:-1])).sum()) if e > a else 0
        a = e
    res[d] = {"events": int(n), "windows": len(ends), "fused_edges_est": fused, "bytes_est": fused * 176}
    print(d, res[d], flush=True)
    del cols[d]
tot = sum(v["bytes_est"] for v in res.values())
res["_total_window_bytes_est"] = tot
print("TOTAL window bytes est", tot, f"{tot / 2**30:.2f} GiB", flush=True)
json.dump(res, open(out, "w"), indent=1)
