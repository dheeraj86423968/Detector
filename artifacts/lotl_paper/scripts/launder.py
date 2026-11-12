"""Taint laundering on top of the LotL relabelling (artifacts/lotl_paper/PROTOCOL.md, variant iv).

Payload = a file node F that, in the test windows, is (a) written (WRITE edge into F, any writer) and (b) run by an
attacker process P (P a ground-truth node or a LotL-relabelled node): an EXECUTE edge F -> P, or P an interpreter
reading F as its script argument (layer 2's own script_exec test, TagEngine._script_of / _same_file).
Laundering: every WRITE edge into F is redirected to a new intermediate file T1 (same directory, name '<F>.~1'), and
right after it (timestamps +1..+6 ns, same window) three copies are inserted:
    T1 -READ-> c1 -WRITE-> T2 -READ-> c2 -WRITE-> T3 -READ-> c3 -WRITE-> F
c1..c3 are new process nodes with the most frequent baseline process label of the host's most frequent baseline
program (a known program: layer 1 stays silent), T1..T3 new file nodes; one set of six nodes per payload, reused for
each of its writes. Layer 2 regains read_attenuation (0.2) of integrity per file hop: a payload written with
integrity 0 reaches 0.6, above the 0.5 alarm level. Nothing else changes; the new nodes are not ground truth.
New entities are appended to the registry before the Runtime is built; edges are appended to the window arrays."""
from collections import Counter, defaultdict
import numpy as np
from pdp_engine.layers import DeterministicLayers, UNKNOWN_PROGRAM, executable, file_path
from pdp_engine.schema import EDGE_TYPE_ID, Entity
import json

EX, RD, WR = EDGE_TYPE_ID["EXECUTE"], EDGE_TYPE_ID["READ"], EDGE_TYPE_ID["WRITE"]


class Launder:
    def __init__(self, S, reg, bdir, N, st, renamed):
        lay = DeterministicLayers.load(bdir, N)
        tags, nov = lay.tags, lay.novelty
        known_raw = set(json.load(open(f"{bdir}/layers.json"))["known_executables"])
        ents = reg.entities
        attacker = set(renamed) | {reg.get(u) for u in S.allgt if reg.get(u) is not None}
        attacker = {i for i in attacker if ents[i].ntype == "subject"}
        written, run_by = set(), defaultdict(set)
        for d in S.test_days:
            for w in st.windows(d):
                src, dst, et = w.src, w.dst, w.etype
                m = et == WR
                written.update(dst[m].tolist())
                m = et == EX
                for s, p in zip(src[m].tolist(), dst[m].tolist()):
                    if p in attacker and ents[s].ntype == "file":
                        run_by[s].add(("execute", p))
                m = et == RD
                for s, p in zip(src[m].tolist(), dst[m].tolist()):
                    if p in attacker and ents[s].ntype == "file":
                        scr = tags._script_of(reg, p)
                        if scr and tags._same_file(file_path(ents[s].label), scr):
                            run_by[s].add(("script", p))
        # a file with no recorded path ('None') is not a payload (it matches a script argument 'None' by accident)
        payloads = sorted(f for f in run_by if f in written and file_path(ents[f].label) not in UNKNOWN_PROGRAM)
        # copier label: the most frequent baseline label of the most frequent baseline program
        cnt, labs = Counter(), defaultdict(Counter)
        for i in range(min(N, len(ents))):
            e = ents[i]
            if e.ntype != "subject":
                continue
            x = executable(e.label, nov.full_paths, getattr(nov, "backslash_paths", False))
            if x in UNKNOWN_PROGRAM or x not in known_raw:
                continue
            k = nov.key(x); cnt[k] += 1; labs[k][e.label] += 1
        top = sorted(cnt, key=lambda k: (-cnt[k], k))[0]
        clabel = sorted(labs[top].items(), key=lambda z: (-z[1], z[0]))[0][0]
        self.chain = {}
        for f in payloads:
            e = ents[f]; p = file_path(e.label)
            ids = []
            for k in (1, 2, 3):
                ids.append(reg.add(Entity(f"lotl-launder-{e.uuid}-t{k}", "file", f"file {p}.~{k}", {})))
            for k in (1, 2, 3):
                ids.append(reg.add(Entity(f"lotl-launder-{e.uuid}-c{k}", "subject", clabel, {})))
            self.chain[f] = ids          # t1, t2, t3, c1, c2, c3
        self.payload_arr = np.array(payloads, dtype=np.int64)
        self.added = 0
        self.report = {"payloads": len(payloads), "copier_label": clabel[:160],
                       "items": [{"file": ents[f].label[:160], "gt": ents[f].uuid in S.allgt,
                                  "run_by": sorted({(k, ents[p].label[:100]) for k, p in run_by[f]})[:5]} for f in payloads],
                       "candidates_not_written": len([f for f in run_by if f not in written])}

    def window(self, w):
        if not len(self.payload_arr):
            return w
        m = (w.etype == WR) & np.isin(w.dst, self.payload_arr)
        if not m.any():
            return w
        src, dst, t, et, uu = list(w.src.tolist()), w.dst.copy(), list(w.t.tolist()), list(w.etype.tolist()), list(w.event_uuid)
        for j in np.where(m)[0].tolist():
            f = int(dst[j]); t1, t2, t3, c1, c2, c3 = self.chain[f]
            dst[j] = t1
            tw = int(w.t[j])
            for k, (s, d, e) in enumerate([(t1, c1, RD), (c1, t2, WR), (t2, c2, RD), (c2, t3, WR), (t3, c3, RD), (c3, f, WR)]):
                src.append(s); t.append(tw + k + 1); et.append(e); uu.append(f"lotl-launder-{f}-{j}-{k}")
                dst = np.append(dst, d)
            self.added += 6
        w.src = np.array(src, dtype=np.int64); w.dst = dst.astype(np.int64); w.t = np.array(t, dtype=np.int64)
        w.etype = np.array(et, dtype=np.int64); w.event_uuid = uu
        return w
