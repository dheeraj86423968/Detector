"""Exploration (before any protocol; CPU): for the released layer-1 new-program alerts (first runs per program and
day, as alerted), three context signals and how they split ground truth: (a) the program file was written earlier
in the stream by a writer whose lineage root does / does not drop-and-run programs in the baseline, (b) the new
process talks to an untrusted address, (c) its parent is itself a new program. Usage: explore2.py SET"""
import json, sys
from collections import Counter, defaultdict
import numpy as np
from pdp_engine.layers import DeterministicLayers, executable, canonical_path, program_key, file_path, EXECUTE, CLONE, WRITE, SEND
from common8 import Set
BUNDLE = {s: "b07rel" for s in [f"CARBANAKV2_EDR-h{i}" for i in range(1, 6)] + ["THEIA_E5-theia"]}
name = sys.argv[1]; S = Set(name)
bdir = f"{S.work}/{BUNDLE.get(name, 'v07rel')}"
spec = json.load(open(f"{bdir}/layers.json")); npre = json.load(open(f"{bdir}/manifest.json"))["num_nodes"]
pk = lambda x: program_key(x, True, True)
cp = lambda p: canonical_path(p)
SENDS = set(SEND)


class Lineage:
    def __init__(self):
        self.root = {}            # canonical path of a written file -> (direct writer key, lineage root key)
        self.started = set()
        self.droppers = defaultdict(set); self.roots = defaultdict(set)

    def feed(self, w, reg, day):
        ents = reg.entities; out = {}
        order = np.argsort(w.t, kind="stable")
        for s_, d_, e in zip(w.src[order].tolist(), w.dst[order].tolist(), w.etype[order].tolist()):
            if e == WRITE and ents[d_].ntype == "file" and ents[s_].ntype == "subject":
                p = cp(file_path(ents[d_].label))
                if p not in ("None", ""):
                    wexe = executable(ents[s_].label, True, True)
                    r = self.root.get(cp(wexe))
                    self.root[p] = (pk(wexe), r[1] if r else pk(wexe))
                    if len(self.root) > 400_000:
                        del self.root[next(iter(self.root))]
            elif e in (CLONE, EXECUTE) and ents[d_].ntype == "subject" and d_ not in self.started:
                self.started.add(d_)
                r = self.root.get(cp(executable(ents[d_].label, True, True)))
                out[d_] = (r, s_ if e == CLONE else None)
                if r:
                    self.droppers[r[0]].add(day); self.roots[r[1]].add(day)
        return out


bst = S.base_store(); breg = bst.load_registry(); base = Lineage()
for k, d in enumerate(spec["fit_days"]):
    for w in bst.windows(d):
        base.feed(w, breg, k)
st = S.eval_store(); reg = st.load_registry()
L = DeterministicLayers(spec, npre); lin = Lineage(); ents = reg.entities
novel = {}          # node -> record
novel_nodes = set()
for d in S.test_days:
    for w in st.windows(d):
        ids = w.nodes()
        hits = L.process(w, reg, ids)
        starts = lin.feed(w, reg, 0)
        for h in hits:
            if h.rule == "novel_executable":
                n = h.nodes[0]; r, par = starts.get(n, (None, None))
                if r is None:
                    r = lin.root.get(cp(executable(ents[n].label, True, True)))
                novel[n] = {"exe": h.key, "gt": ents[n].uuid in S.allgt, "drop": "none" if r is None else ("routine" if r[1] in base.roots or r[0] in base.droppers else "new"),
                            "writer": r[0] if r else None, "root": r[1] if r else None, "net": False, "parent_novel": par in novel_nodes if par is not None else False}
                novel_nodes.add(n)
            elif h.rule == "novel_executable_repeat":
                novel_nodes.add(h.nodes[0])
        m = np.isin(w.src, np.fromiter(novel, dtype=np.int64, count=len(novel))) & np.isin(w.etype, list(SENDS)) if novel else None
        if m is not None and m.any():
            for s_, d_ in zip(w.src[m].tolist(), w.dst[m].tolist()):
                if ents[d_].ntype == "netflow" and L.tags._tag(reg, d_).data < 0.5:
                    novel[s_]["net"] = True
cnt = Counter(); ex = defaultdict(list)
for n, r in novel.items():
    for sig, on in (("drop=" + r["drop"], True), ("net_untrusted", r["net"]), ("parent_novel", r["parent_novel"]),
                    ("new_drop|net", r["drop"] == "new" or r["net"]), ("any", True)):
        if on:
            cnt[(sig, "TP" if r["gt"] else "FP")] += 1
            if len(ex[(sig, r["gt"])]) < 10 and sig != "any":
                ex[(sig, r["gt"])].append(f"{r['exe'][-44:]} <= {str(r['writer'])[-30:]}")
print(json.dumps({"set": name, "roots": len(base.roots), "counts": {f"{k[0]}/{k[1]}": v for k, v in sorted(cnt.items())},
                  "examples": {f"{k[0]}/{'TP' if k[1] else 'FP'}": v for k, v in ex.items()}}))
