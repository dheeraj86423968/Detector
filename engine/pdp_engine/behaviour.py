"""Detector-3 (0.7): behavioural likelihood - what a program normally touches, learned per endpoint.

For every event of a window the process side p and the object side x are taken (for a process -> process edge,
CLONE, both views: the parent's view of the child and the child's view of the parent). The model estimates

    P(x | program of p, operation, direction)

from the endpoint's baseline with hierarchical Witten-Bell smoothing over two hierarchies:

  context (who):   exact program  ->  program directory  ->  any program
  object (what):   exact object   ->  its directory / remote address  ->  its class (top directory + extension;
                                                                          address class + port bucket; "process")

A known program doing something it has done before scores ~0; a program doing something new for *it* scores by how
new (only the file, the directory too, the whole class) and by how often this program produces new objects at all
(the Witten-Bell escape probability: an installer writes new files all the time, a web server never executes one).
A program never seen before has no exact context and is judged by its directory and the endpoint as a whole - which
is how this detector covers what the 0.3-0.6 "new executable" rule did, without alerting on every update: a new
executable started by a package manager is ordinary, a new executable in /tmp started by a web server is not.

Edge score = -log P (nats). Within a window, novelty is paid once per process instance: when the same process
instance touches a directory (or address) again with the same operation, only the within-directory novelty counts,
and the j-th new object in the same directory costs at most log(1 + j) - one installer run is one anomaly, not five
hundred. Node score = max of its edges' scores.

Volatile name parts (GUIDs, long hex ids, random alphanumeric tokens, digit runs) are generalised before counting, so
cache files, temp names and versioned paths do not look new every time.

Everything is counted per endpoint; nothing here depends on a dataset or a client. The model is a set of sorted
count tables (numpy) plus the key vocabulary, saved in the bundle as detector-3.npz / detector-3-vocab.json.
"""
from __future__ import annotations

import json
import os
import re

import numpy as np

from .layers import canonical_path, executable, file_path, is_local, is_private, program_key, remote_ip, remote_port
from .schema import EDGE_TYPE_ID, Registry

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEX = re.compile(r"(?<![0-9a-z])[0-9a-f]{8,}(?![0-9a-z])", re.I)
_MIX = re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9_]*\d)(?=[A-Za-z0-9_]*[A-Za-z])[A-Za-z0-9_]{6,}(?![A-Za-z0-9])")
_DIG = re.compile(r"\d+")
WELL_KNOWN = {20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138, 139, 143, 389, 443, 445, 465, 514, 587,
              636, 993, 995, 1433, 1521, 3306, 3389, 5353, 5355, 5432, 5985, 5986, 6379, 8080, 8443, 9200}
NUM_OPS = 10
B = np.int64(1 << 26)            # key ids are below 2^26; composite keys (role-op, context, object) fit in int64
UNSEEN = int(B) - 2              # id of a key string the model has never seen (+1 offset -> B-1, never counted)
LEVELS = 3                       # context levels and object levels


def gen(s: str) -> str:
    """Generalise volatile name parts: GUIDs, hex ids, random alphanumeric tokens, digit runs."""
    s = _UUID.sub("<u>", s)
    s = _HEX.sub("<h>", s)
    s = _MIX.sub("<r>", s)
    return _DIG.sub("#", s)


def port_bucket(p) -> str:
    try:
        p = int(p)
    except (TypeError, ValueError):
        return "?"
    return str(p) if p in WELL_KNOWN or p < 1024 else ("hi" if p >= 49152 else "reg")


def addr_class(ip) -> str:
    if ip in (None, "None", "NA", "", "null"):
        return "na"
    if is_local(ip, multicast=True, strict=True):
        return "local"
    return "private" if is_private(ip) else "public"


def entity_keys(ntype: str, label: str) -> tuple:
    """(ctx0, ctx1, x0, x1, x2): ctx* when the entity acts as the process, x* when it is the object of an event."""
    if ntype == "subject":
        exe = executable(label)
        k = program_key(exe, strict=True) if exe not in ("None", "") else "None"
        if k == "None":                                   # no image path recorded: the command name
            parts = label.split(" ")
            k = "cmd:" + (parts[2] if len(parts) > 2 else "None")
        g = gen(k)
        d = g.rsplit("/", 1)[0] if "/" in g else "<nodir>"
        return ("s:" + g, "sd:" + d, "s:" + g, "sd:" + d, "S")
    if ntype == "file":
        p = file_path(label)
        if p in ("None", "", "null"):
            return (None, None, "f:None", "fd:None", "F:None")
        c = gen(canonical_path(p))
        d = c.rsplit("/", 1)[0] if "/" in c else "<nodir>"
        base = c.rsplit("/", 1)[-1]
        ext = base.rsplit(".", 1)[-1][:8] if "." in base else ""
        top = "/".join(c.split("/")[:3])
        return (None, None, "f:" + c, "fd:" + d, f"F:{top}|{ext}")
    ip, port = remote_ip(label), remote_port(label)
    pb, cls = port_bucket(port), addr_class(ip)
    net = f"n:{ip}" if cls != "public" else "n24:" + ".".join(str(ip).split(".")[:3])
    return (None, None, f"n:{ip}|{pb}", net, f"N:{cls}|{pb}")


class _Counts:
    """Sorted (key, count) table built from many np.unique batches."""

    def __init__(self):
        self.parts: list[tuple[np.ndarray, np.ndarray]] = []

    def add(self, keys: np.ndarray) -> None:
        if len(keys):
            u, c = np.unique(keys, return_counts=True)
            self.parts.append((u, c.astype(np.int64)))
            if len(self.parts) > 64:
                self.compact()

    def compact(self) -> None:
        if len(self.parts) > 1:
            u = np.concatenate([p[0] for p in self.parts])
            c = np.concatenate([p[1] for p in self.parts])
            uu, inv = np.unique(u, return_inverse=True)
            cc = np.zeros(len(uu), np.int64)
            np.add.at(cc, inv, c)
            self.parts = [(uu, cc)]

    def table(self) -> tuple[np.ndarray, np.ndarray]:
        self.compact()
        return self.parts[0] if self.parts else (np.zeros(0, np.int64), np.zeros(0, np.int64))


def _lookup(table, keys: np.ndarray) -> np.ndarray:
    u, c = table
    if len(u) == 0 or len(keys) == 0:
        return np.zeros(len(keys), np.float64)
    i = np.minimum(np.searchsorted(u, keys), len(u) - 1)
    return np.where(u[i] == keys, c[i], 0).astype(np.float64)


def _ck(r, c):
    return r.astype(np.int64) * B + c


def _cxk(r, c, x):
    return (r.astype(np.int64) * B + c) * B + x


class EntityKeys:
    """Key ids of a registry's entities, grown lazily as the registry grows (the agent's registry is append-only
    between compactions; call remap() after a compaction)."""

    def __init__(self, model: "BehaviourModel", reg: Registry):
        self.model, self.reg = model, reg
        self.isproc = np.zeros(0, bool)
        self.isnet = np.zeros(0, bool)
        self.k = np.zeros((0, 5), np.int64)
        self.grow()

    def grow(self) -> None:
        n, m = len(self.reg), len(self.isproc)
        if n <= m:
            return
        isp = np.zeros(n - m, bool)
        isn = np.zeros(n - m, bool)
        kk = np.empty((n - m, 5), np.int64)
        for j, i in enumerate(range(m, n)):
            e = self.reg.entities[i]
            isp[j] = e.ntype == "subject"
            isn[j] = e.ntype == "netflow"
            kk[j] = [self.model.key_id(s) for s in entity_keys(e.ntype, e.label)]
        self.isproc = np.concatenate([self.isproc, isp])
        self.isnet = np.concatenate([self.isnet, isn])
        self.k = np.concatenate([self.k, kk])

    def remap(self, old2new) -> None:
        o2n = np.asarray(old2new, dtype=np.int64)
        keep = o2n >= 0
        n = len(self.isproc)
        self.isproc, self.isnet, self.k = self.isproc[:n][keep[:n]], self.isnet[:n][keep[:n]], self.k[:n][keep[:n]]


def edge_events(w, K: EntityKeys):
    """A window's edges as scored events: (process, object, role-op, edge index). role-op = op * 2 + (1 if the data
    flows object -> process). CLONE (process -> process) gives two events, one per view."""
    s, d, t = w.src, w.dst, w.etype
    ps, pd = K.isproc[s], K.isproc[d]
    idx = np.arange(len(s))
    m1, m2, m3 = ps & ~pd, pd & ~ps, ps & pd
    p = np.concatenate([s[m1], d[m2], s[m3], d[m3]])
    x = np.concatenate([d[m1], s[m2], d[m3], s[m3]])
    r = np.concatenate([t[m1] * 2, t[m2] * 2 + 1, t[m3] * 2, t[m3] * 2 + 1])
    e = np.concatenate([idx[m1], idx[m2], idx[m3], idx[m3]])
    return p, x, r, e


def _first(p, keys):
    """True for the first occurrence of (p, key) in array order."""
    _, first = np.unique(p.astype(np.int64) * B * 64 + keys, return_index=True)
    f = np.zeros(len(p), bool)
    f[first] = True
    return f


class BehaviourModel:
    """Counts per context level k (0 exact program, 1 program directory, 2 any) and object level l (0..2)."""

    def __init__(self):
        self.vocab: dict[str, int] = {}
        self.frozen = False
        self._c_cx = {(k, l): _Counts() for k in range(LEVELS) for l in range(LEVELS)}
        self._c_c = {k: _Counts() for k in range(LEVELS)}
        self._c_pair = {l: _Counts() for l in range(LEVELS - 1)}
        self.tables: dict | None = None
        self.role_prior = True           # 0.7: add -log P(operation | program), once per process instance and window

    # ---- keys ----
    def key_id(self, s: str | None) -> int:
        if s is None:
            return -1
        i = self.vocab.get(s)
        if i is None:
            if self.frozen or len(self.vocab) >= UNSEEN:
                return UNSEEN
            i = len(self.vocab)
            self.vocab[s] = i
        return i

    def keys(self, reg: Registry) -> EntityKeys:
        return EntityKeys(self, reg)

    @staticmethod
    def _ctx(K, p, k):
        return np.zeros(len(p), np.int64) if k == 2 else K.k[p, k] + 1     # 0 = the global context

    # ---- fitting ----
    def fit_window(self, w, K: EntityKeys, exclude: np.ndarray | None = None) -> None:
        """Count a window's events. exclude: boolean mask over registry positions whose activity must not become
        normal (nodes of unreleased alerts)."""
        if self.frozen:
            raise RuntimeError("model is frozen (loaded for scoring)")
        K.grow()
        p, x, r, _ = edge_events(w, K)
        if exclude is not None and len(p):
            ok = ~(exclude[p] | exclude[x])
            p, x, r = p[ok], x[ok], r[ok]
        if not len(p):
            return
        for k in range(LEVELS):
            c = self._ctx(K, p, k)
            self._c_c[k].add(_ck(r, c))
            for l in range(LEVELS):
                self._c_cx[(k, l)].add(_cxk(r, c, K.k[x, 2 + l] + 1))
        for l in range(LEVELS - 1):
            self._c_pair[l].add(_cxk(r, K.k[x, 3 + l] + 1, K.k[x, 2 + l] + 1))

    def finish(self) -> "BehaviourModel":
        t = {}
        for (k, l), v in self._c_cx.items():
            t[f"cx{k}{l}"] = v.table()
            u, _ = t[f"cx{k}{l}"]
            uu, cnt = np.unique(u // B, return_counts=True)
            t[f"T{k}{l}"] = (uu, cnt.astype(np.int64))
        for k, v in self._c_c.items():
            t[f"c{k}"] = v.table()
        for l, v in self._c_pair.items():
            u, _ = v.table()
            uu, cnt = np.unique(u // B, return_counts=True)
            t[f"D{l}"] = (uu, cnt.astype(np.int64))
        if self.role_prior:      # per context: all its events, and how many distinct operations it does
            for k in range(LEVELS):
                u, c = t[f"c{k}"]
                cc = u % B
                order = np.argsort(cc, kind="stable")
                cs, ns = cc[order], c[order]
                uu, start = np.unique(cs, return_index=True)
                t[f"R{k}"] = (uu, np.add.reduceat(ns, start).astype(np.int64) if len(ns) else np.zeros(0, np.int64))
                t[f"RT{k}"] = (uu, np.diff(np.r_[start, len(cs)]).astype(np.int64))
        self.tables = t
        return self

    def _role_probs(self, K, p, r):
        """P(operation and direction | program), Witten-Bell over contexts, for operations the exact program has never
        done (1 otherwise): a program with plenty of history that has never done this kind of operation (a web server
        starting a process) is penalised for it; an unknown program is judged by its directory and the endpoint."""
        prev = None
        for k in (2, 1, 0):
            c = self._ctx(K, p, k)
            n = _lookup(self.tables[f"c{k}"], _ck(r, c))
            N = _lookup(self.tables[f"R{k}"], c)
            T = _lookup(self.tables[f"RT{k}"], c)
            base = np.full(len(p), 1.0 / (2 * NUM_OPS)) if prev is None else prev
            den = N + T
            prev = np.where(den > 0, (n + T * base) / np.maximum(den, 1e-12), base)
        # only an operation this exact program has never done costs anything (a known one is not surprising, however
        # rare among the program's operations)
        return np.where(n > 0, 1.0, np.clip(prev, 1e-300, 1.0))

    # ---- scoring ----
    def _probs(self, K, p, x, r):
        """(P0, P1, P2): probabilities of the object at levels 0..2 under the exact program context."""
        E = len(p)
        prev = None
        for k in (2, 1, 0):
            c = self._ctx(K, p, k)
            nc = _lookup(self.tables[f"c{k}"], _ck(r, c))
            P = {}
            for l in (2, 1, 0):
                xl = K.k[x, 2 + l] + 1
                n = _lookup(self.tables[f"cx{k}{l}"], _cxk(r, c, xl))
                T = _lookup(self.tables[f"T{k}{l}"], _ck(r, c))
                if prev is None:            # any program: classes uniform over those seen (+1), finer levels spread
                    if l == 2:              # the coarser level's mass over the finer objects seen under it (+1)
                        base = 1.0 / (T + 1.0)
                    else:
                        D = _lookup(self.tables[f"D{l}"], _ck(r, K.k[x, 3 + l] + 1))
                        base = P[l + 1] / (D + 1.0)
                elif l == 2:                # top object level: back off to the parent context
                    base = prev[2]
                else:                       # finer level: coarser probability x the parent context's fine/coarse ratio
                    base = P[l + 1] * (prev[l] / np.maximum(prev[l + 1], 1e-300))
                den = nc + T
                P[l] = np.where(den > 0, (n + T * base) / np.maximum(den, 1e-12), base)
            prev = P
        return tuple(np.clip(prev[l], 1e-300, 1.0) for l in (0, 1, 2))

    def edge_scores(self, w, K: EntityKeys):
        """Per event: (process, object, edge index, score in nats), novelty paid once per process instance."""
        K.grow()
        p, x, r, e = edge_events(w, K)
        if not len(p):
            z = np.zeros(0, np.int64)
            return z, z, z, np.zeros(0)
        P0, P1, P2 = self._probs(K, p, x, r)
        s_full = -np.log(P0)
        s_in = -np.log(P0 / P1)                       # novelty of the object inside its directory / address
        o = np.argsort(w.t[e], kind="stable")
        inv = np.empty_like(o)
        inv[o] = np.arange(len(o))
        po, ro = p[o], r[o].astype(np.int64)
        x1o = K.k[x[o], 3] + 1
        f1 = _first(po, ro * B + x1o)[inv]            # first time this instance touches this directory with this op
        s = np.where(f1, s_full, s_in)
        nov = s_in > 2.0
        key = (po.astype(np.int64) * B + x1o) * 2 + nov[o]
        so = np.argsort(key, kind="stable")
        ks = key[so]
        start = np.r_[True, ks[1:] != ks[:-1]] if len(ks) else np.zeros(0, bool)
        ii = np.arange(len(ks))
        j = ii - np.maximum.accumulate(np.where(start, ii, 0))
        jj = np.empty_like(j)
        jj[so] = j
        jj = jj[inv]
        rep = (~f1) & nov & (jj > 0)                  # the j-th new object in a directory already touched: log(1 + j)
        s = np.where(rep, np.minimum(s, np.log1p(jj)), s)
        if "R0" in self.tables:                       # an operation new for this program: paid once per instance
            fr = _first(po, ro)[inv]
            s = s + np.where(fr, -np.log(self._role_probs(K, p, r)), 0.0)
        return p, x, e, s

    def node_scores(self, w, K: EntityKeys, n: int):
        """(node score array of length n, per-edge score array of length w.num_edges)."""
        p, x, e, s = self.edge_scores(w, K)
        own = np.zeros(n)
        es = np.zeros(w.num_edges)
        if len(s):
            np.maximum.at(own, p, s)
            np.maximum.at(own, x, s)
            np.maximum.at(es, e, s)
        return own, es

    # ---- persistence ----
    def save(self, bundle_dir: str, prefix: str = "detector-3") -> list[str]:
        if self.tables is None:
            self.finish()
        arrays = {}
        for name, (u, c) in self.tables.items():
            arrays[f"{name}_k"], arrays[f"{name}_v"] = u, c
        np.savez_compressed(os.path.join(bundle_dir, f"{prefix}.npz"), **arrays)
        with open(os.path.join(bundle_dir, f"{prefix}-vocab.json"), "w") as f:
            json.dump(sorted(self.vocab, key=self.vocab.get), f)
        return [f"{prefix}.npz", f"{prefix}-vocab.json"]

    @staticmethod
    def load(bundle_dir: str, prefix: str = "detector-3") -> "BehaviourModel":
        m = BehaviourModel()
        z = np.load(os.path.join(bundle_dir, f"{prefix}.npz"), allow_pickle=False)
        names = {k[:-2] for k in z.files}
        m.tables = {n: (z[f"{n}_k"], z[f"{n}_v"]) for n in names}
        vocab = json.load(open(os.path.join(bundle_dir, f"{prefix}-vocab.json")))
        m.vocab = {s: i for i, s in enumerate(vocab)}
        m.frozen = True
        m.role_prior = "R0" in m.tables
        m._c_cx = m._c_c = m._c_pair = None
        return m

    @staticmethod
    def fit(store, days: list[str], reg: Registry, exclude_nodes=None, log=print) -> tuple["BehaviourModel", EntityKeys]:
        m = BehaviourModel()
        K = m.keys(reg)
        excl = None
        if exclude_nodes is not None and len(exclude_nodes):
            excl = np.zeros(len(reg), bool)
            excl[np.asarray(list(exclude_nodes), dtype=np.int64)] = True
        n = 0
        for d in days:
            for w in store.windows(d):
                if excl is not None and len(excl) < len(reg):
                    excl = np.concatenate([excl, np.zeros(len(reg) - len(excl), bool)])
                m.fit_window(w, K, excl)
                n += w.num_edges
        m.finish()
        log(f"detector-3: {n} edges, {len(m.vocab)} keys, {sum(len(u) for u, _ in m.tables.values())} table rows")
        return m, K


def top_threshold(scores: np.ndarray, budget: int) -> float:
    """The (budget+1)-th largest score: the threshold that lets `budget` benign validation nodes through (0 = the
    maximum, the 0.3-0.6 rule)."""
    s = np.sort(scores[np.isfinite(scores)])[::-1]
    if not len(s):
        return 1.0
    return float(max(s[min(budget, len(s) - 1)], 1e-6))


OPEN_ID = EDGE_TYPE_ID["OPEN"]


def propagate(level: np.ndarray, own: np.ndarray, w, edge_score: np.ndarray, delta: float, gate: float, clip: float,
              seed: float, passes: int) -> None:
    """Learned-seeded propagation (0.7), in place. level: carried suspicion per registry position (ratio units).
    level = max(level, own); then, `passes` times, every unusual data-flow edge (edge score >= gate, in units of the
    process threshold; OPEN excluded) carries delta * min(level[src], clip) to its destination, from sources whose
    level is at least `seed`. Unusual edges only: a common edge (any process reading a shared library) carries
    nothing, which keeps a suspicious node from tainting everything it touches; clip bounds how far one extreme score
    reaches; delta < 1 makes suspicion fade with every hop."""
    np.maximum(level, own, out=level)
    if delta <= 0 or not w.num_edges:
        return
    keep = (w.etype != OPEN_ID) & (edge_score >= gate)
    s, d = w.src[keep], w.dst[keep]
    for _ in range(passes):
        ps = level[s]
        ok = ps >= seed
        if not ok.any():
            break
        before = level[d[ok]].copy()
        np.maximum.at(level, d[ok], delta * np.minimum(ps[ok], clip))
        if np.array_equal(level[d[ok]], before):
            break


# 0.7b: per-activity thresholds. Different kinds of activity have very different amounts of benign novelty (a busy
# host contacts new addresses all day; it rarely starts a program from a new place), so one threshold per node type
# is set by the noisiest kind and hides the quiet ones. Groups by what the event touches:
GROUP_NAMES = ("process", "network", "file-write", "file-read")
_WRITE_ID = EDGE_TYPE_ID["WRITE"]


def event_groups(K: EntityKeys, x: np.ndarray, r: np.ndarray) -> np.ndarray:
    """Group id per event: 0 the object is a process (starts, the parent of a start), 1 a network endpoint, 2 a file
    written to, 3 a file read / opened / executed."""
    g = np.full(len(x), 3, np.int64)
    g[K.isproc[x]] = 0
    g[K.isnet[x]] = 1
    g[(g == 3) & ((r // 2) == _WRITE_ID)] = 2
    return g


def grouped_node_scores(model: "BehaviourModel", w, K: EntityKeys, n: int, thr: np.ndarray):
    """(node ratio, edge ratio): each event's score over its group's threshold; a node's ratio is the max over its
    events (any group), an edge's the max over its events."""
    p, x, e, s = model.edge_scores(w, K)
    own = np.zeros(n)
    es = np.zeros(w.num_edges)
    if len(s):
        r = edge_events(w, K)[2]
        q = s / thr[event_groups(K, x, r)]
        np.maximum.at(own, p, q)
        np.maximum.at(own, x, q)
        np.maximum.at(es, e, q)
    return own, es


def grouped_raw_scores(model: "BehaviourModel", w, K: EntityKeys, n: int) -> np.ndarray:
    """(len(GROUP_NAMES), n): each node's max raw score per group (for calibration)."""
    p, x, e, s = model.edge_scores(w, K)
    out = np.zeros((len(GROUP_NAMES), n))
    if len(s):
        r = edge_events(w, K)[2]
        g = event_groups(K, x, r)
        for k in range(len(GROUP_NAMES)):
            m = g == k
            np.maximum.at(out[k], p[m], s[m])
            np.maximum.at(out[k], x[m], s[m])
    return out


# 0.8: evidence accumulated over a process's activities ("breadth"). One maximum per process cannot tell one strange
# benign event (a tool reading a directory it never read: 50-70 nats on a busy host) from an attack whose steps are each
# only moderately strange (a program started from /tmp that then connects out and writes files: ~20 nats each). Per
# process instance, the most unusual event of each kind of activity (BREADTH_GROUPS) within a time horizon counts,
# capped (beyond `cap` nats a rarity estimate says nothing more: P < 5e-5 is "never seen" either way) and above a
# floor (mild novelty is everyday noise); the process's evidence is their sum. Unusual in several kinds of activity
# at once is what attack steps look like; a single extreme event no longer outranks them. Objects (files,
# addresses) keep their own capped maximum; they rise through propagation from the processes that touch them.
BREADTH_GROUPS = ("process", "network", "file-write", "file-read")


class Breadth:
    """Per-process breadth state: for each registry position and activity group, the largest event score seen
    within `horizon_ns` and when it was set (carried across windows; grows with the registry, remapped on
    compaction)."""

    def __init__(self, cap: float, floor: float, horizon_ns: int):
        self.cap, self.floor, self.horizon_ns = float(cap), float(floor), int(horizon_ns)
        self.reset()

    # storage: float32 maxima and int64 times in buffers with spare capacity (the registry grows a little every
    # window; re-allocating the whole state each time would copy it per window). val / ts are views of the used part.
    @property
    def val(self) -> np.ndarray:
        return self._val[:, :self.n]

    @property
    def ts(self) -> np.ndarray:
        return self._ts[:, :self.n]

    def _alloc(self, capacity: int) -> None:
        v = np.zeros((len(BREADTH_GROUPS), capacity), np.float32)
        t = np.zeros((len(BREADTH_GROUPS), capacity), np.int64)
        v[:, :self.n], t[:, :self.n] = self._val[:, :self.n], self._ts[:, :self.n]
        self._val, self._ts = v, t

    def grow(self, n: int) -> None:
        if n <= self.n:
            return
        if n > self._val.shape[1]:
            self._alloc(max(n, 2 * self._val.shape[1], 1024))
        self._val[:, self.n:n] = 0.0          # positions freed by an earlier remap may hold old values
        self._ts[:, self.n:n] = 0
        self.n = n

    def reset(self) -> None:
        self.n = 0
        self._val = np.zeros((len(BREADTH_GROUPS), 0), np.float32)
        self._ts = np.zeros((len(BREADTH_GROUPS), 0), np.int64)

    def remap(self, keep: np.ndarray) -> None:
        k = min(self.n, len(keep))
        idx = np.nonzero(keep[:k])[0]
        v, t = self._val[:, idx], self._ts[:, idx]
        self.n = len(idx)
        self._val, self._ts = v, t

    def update(self, p: np.ndarray, g: np.ndarray, s: np.ndarray, now_ns: int) -> np.ndarray:
        """Fold a window's process events (process p, group g, score s) into the state; returns the processes
        touched (unique) and their breadth after the update."""
        if not len(p):
            return np.zeros(0, np.int64), np.zeros(0)
        G = len(BREADTH_GROUPS)
        key = p.astype(np.int64) * G + g
        u, inv = np.unique(key, return_inverse=True)
        m = np.zeros(len(u), np.float32)
        np.maximum.at(m, inv, s)
        up, ug = u // G, u % G
        old, t0 = self._val[ug, up], self._ts[ug, up]
        expired = now_ns - t0 > self.horizon_ns
        repl = expired | (m >= old)
        self._val[ug[repl], up[repl]] = m[repl]
        self._ts[ug[repl], up[repl]] = now_ns
        procs = np.unique(up)
        live = (now_ns - self._ts[:, procs]) <= self.horizon_ns
        ev = np.clip(np.minimum(self._val[:, procs].astype(np.float64), self.cap) - self.floor, 0.0, None) * live
        return procs, ev.sum(0)


def breadth_groups(K: EntityKeys, x: np.ndarray, r: np.ndarray) -> np.ndarray:
    """BREADTH_GROUPS id per event (what the process touched): 0 a process, 1 a network endpoint, 2 a file written
    to, 3 a file read / opened / executed."""
    return event_groups(K, x, r)


def breadth_node_scores(model: "BehaviourModel", w, K: EntityKeys, n: int, state: Breadth):
    """(node evidence of length n, per-edge raw score of length w.num_edges): processes touched in the window get
    their breadth (state updated with the window's events at the window end), objects min(max event score, cap)."""
    K.grow()
    p, x, e, s = model.edge_scores(w, K)
    own = np.zeros(n)
    es = np.zeros(w.num_edges)
    if not len(s):
        return own, es
    np.maximum.at(es, e, s)
    r = edge_events(w, K)[2]
    state.grow(n)
    procs, ev = state.update(p, breadth_groups(K, x, r), s, int(w.end_ns))
    obj = ~K.isproc[x]
    np.maximum.at(own, x[obj], np.minimum(s[obj], state.cap))
    own[procs] = ev
    return own, es
