"""Detector-3 prototype: behavioural likelihood. Hierarchical Witten-Bell model of P(object | process, op, role)
fitted on the endpoint's baseline; edge score = -log P; node score = aggregate of its edges' scores."""
import re
import numpy as np
from pdp_engine.layers import executable, program_key, canonical_path, file_path, remote_ip, remote_port, is_local, is_private
from pdp_engine.schema import EDGE_TYPE_ID

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_HEX = re.compile(r"(?<![0-9a-z])[0-9a-f]{8,}(?![0-9a-z])", re.I)
_MIX = re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9_]*\d)(?=[A-Za-z0-9_]*[A-Za-z])[A-Za-z0-9_]{6,}(?![A-Za-z0-9])")
_DIG = re.compile(r"\d+")
WELL_KNOWN = {20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138, 139, 143, 389, 443, 445, 465, 514, 587,
              636, 993, 995, 1433, 1521, 3306, 3389, 5353, 5355, 5432, 5985, 5986, 6379, 8080, 8443, 9200}


def gen(s):
    """Generalise volatile name parts: GUIDs, hex ids, random alnum tokens, digit runs."""
    s = _UUID.sub("<u>", s); s = _HEX.sub("<h>", s); s = _MIX.sub("<r>", s)
    return _DIG.sub("#", s)


def port_bucket(p):
    try:
        p = int(p)
    except (TypeError, ValueError):
        return "?"
    return str(p) if p in WELL_KNOWN or p < 1024 else ("hi" if p >= 49152 else "reg")


def addr_class(ip):
    if ip in ("None", "NA", "", "null") or ip is None:
        return "na"
    if is_local(ip, multicast=True, strict=True):
        return "local"
    return "private" if is_private(ip) else "public"


def entity_keys(e):
    """(ctx0, ctx1, x0, x1, x2) strings for an entity: ctx* when it acts as the process, x* when it is the object."""
    lab = e.label
    if e.ntype == "subject":
        exe = executable(lab)
        k = program_key(exe, strict=True) if exe not in ("None", "") else "None"
        if k == "None":    # no image path (CADETS): the command name
            parts = lab.split(" ")
            k = "cmd:" + (parts[2] if len(parts) > 2 else "None")
        g = gen(k)
        d = g.rsplit("/", 1)[0] if "/" in g else "<nodir>"
        return ("s:" + g, "sd:" + d, "s:" + g, "sd:" + d, "S")
    if e.ntype == "file":
        p = file_path(lab)
        if p in ("None", "", "null"):
            return (None, None, "f:None", "fd:None", "F:None")
        c = gen(canonical_path(p))
        d = c.rsplit("/", 1)[0] if "/" in c else "<nodir>"
        base = c.rsplit("/", 1)[-1]
        ext = base.rsplit(".", 1)[-1][:8] if "." in base else ""
        top = "/".join(c.split("/")[:3])
        return (None, None, "f:" + c, "fd:" + d, f"F:{top}|{ext}")
    ip, port = remote_ip(lab), remote_port(lab)
    pb = port_bucket(port)
    cls = addr_class(ip)
    return (None, None, f"n:{ip}|{pb}", f"n:{ip}" if cls != "public" else f"n24:{'.'.join(ip.split('.')[:3])}", f"N:{cls}|{pb}")


class Vocab:
    def __init__(self):
        self.ix = {}

    def get(self, s, add=True):
        if s is None:
            return -1
        i = self.ix.get(s)
        if i is None:
            if not add:
                return -2
            i = len(self.ix); self.ix[s] = i
        return i


class Keyed:
    """Per-registry entity key ids (shared vocabularies so baseline and test registries agree)."""

    def __init__(self, vocab, reg):
        n = len(reg)
        self.isproc = np.zeros(n, bool)
        self.k = np.full((n, 5), -1, np.int64)
        for i, e in enumerate(reg.entities):
            ks = entity_keys(e)
            self.isproc[i] = e.ntype == "subject"
            self.k[i] = [vocab.get(x) for x in ks]


NOP = 10


def edge_events(w, K):
    """Expand a window's edges into scored events (process side p, object side x, op*2+role). CLONE edges give two
    events (parent's view: child; child's view: parent)."""
    s, d, t = w.src, w.dst, w.etype
    ps, pd = K.isproc[s], K.isproc[d]
    ev_p, ev_x, ev_r, ev_e = [], [], [], []
    idx = np.arange(len(s))
    m = ps & ~pd                         # process -> object (writes, sends, connect)
    ev_p.append(s[m]); ev_x.append(d[m]); ev_r.append(t[m] * 2); ev_e.append(idx[m])
    m = pd & ~ps                         # object -> process (reads, recv, execute)
    ev_p.append(d[m]); ev_x.append(s[m]); ev_r.append(t[m] * 2 + 1); ev_e.append(idx[m])
    m = ps & pd                          # process -> process (clone): both views
    ev_p.append(s[m]); ev_x.append(d[m]); ev_r.append(t[m] * 2); ev_e.append(idx[m])
    ev_p.append(d[m]); ev_x.append(s[m]); ev_r.append(t[m] * 2 + 1); ev_e.append(idx[m])
    return np.concatenate(ev_p), np.concatenate(ev_x), np.concatenate(ev_r), np.concatenate(ev_e)


class Counter:
    def __init__(self):
        self.parts = []

    def add(self, keys):
        u, c = np.unique(keys, return_counts=True)
        self.parts.append((u, c))
        if len(self.parts) > 64:
            self.compact()

    def compact(self):
        if len(self.parts) <= 1:
            return
        u = np.concatenate([p[0] for p in self.parts]); c = np.concatenate([p[1] for p in self.parts])
        uu, inv = np.unique(u, return_inverse=True)
        cc = np.zeros(len(uu), np.int64); np.add.at(cc, inv, c)
        self.parts = [(uu, cc)]

    def table(self):
        self.compact()
        return self.parts[0] if self.parts else (np.zeros(0, np.int64), np.zeros(0, np.int64))


def lookup(table, keys):
    u, c = table
    if len(u) == 0:
        return np.zeros(len(keys), np.int64)
    i = np.searchsorted(u, keys); i = np.minimum(i, len(u) - 1)
    return np.where(u[i] == keys, c[i], 0)


B = np.int64(1 << 26)   # vocabulary ids < 2^26 (67M)


def ck(r, c):          # context key: (op-role, context id)
    return r.astype(np.int64) * B + c


def cxk(r, c, x):      # (op-role, context, object)  - fits in int64: 20 * 2^52
    return (r.astype(np.int64) * B + c) * B + x


class BL:
    """Counts per context level k (0 = exact program, 1 = program directory, 2 = any) and object level l (0..2)."""

    def __init__(self):
        self.c_cx = {(k, l): Counter() for k in range(3) for l in range(3)}   # n(c, x_l)
        self.c_c = {k: Counter() for k in range(3)}                            # n(c)
        self.c_pair = {l: Counter() for l in range(2)}                          # (r, x_{l+1}, x_l) at global
        self.floor = "proper"

    def _ctx(self, K, p, k):
        if k == 2:
            return np.zeros(len(p), np.int64)
        return K.k[p, k] + 1          # +1: 0 is reserved for the global context

    def fit_window(self, w, K, exclude=None):
        p, x, r, _ = edge_events(w, K)
        if exclude is not None:              # nodes that alerted: their activity does not become normal
            ok = ~(exclude[p] | exclude[x])
            p, x, r = p[ok], x[ok], r[ok]
        for k in range(3):
            c = self._ctx(K, p, k)
            self.c_c[k].add(ck(r, c))
            for l in range(3):
                self.c_cx[(k, l)].add(cxk(r, c, K.k[x, 2 + l] + 1))
        for l in range(2):
            self.c_pair[l].add(cxk(r, K.k[x, 3 + l] + 1, K.k[x, 2 + l] + 1))

    def finish(self):
        self.t_cx = {kl: v.table() for kl, v in self.c_cx.items()}
        self.t_c = {k: v.table() for k, v in self.c_c.items()}
        # distinct objects per context: T_l(c)
        self.t_T = {}
        for (k, l), (u, _) in self.t_cx.items():
            cc = u // B
            uu, cnt = np.unique(cc, return_counts=True)
            self.t_T[(k, l)] = (uu, cnt)
        # global conditional G(x_l | x_{l+1}) per op-role: counts of x_l and of x_{l+1} at the global context, and
        # distinct x_l per x_{l+1} (needs the pairing x_l -> x_{l+1}, kept from fitting via the object keys)
        # D_l(r, x_{l+1}): distinct x_l seen under x_{l+1}
        self.t_D = {}
        for l in range(2):
            u, _ = self.c_pair[l].table()
            uu, cnt = np.unique(u // B, return_counts=True)
            self.t_D[l] = (uu, cnt)
        # counters are kept: the model can be updated incrementally (daily) and finished again

    def logp(self, K, p, x, r, parts=False):
        """log P(x_0 | c_0) with backoff over object levels inside each context and over contexts at the top
        object level; returns natural-log probabilities (E,)."""
        E = len(p)
        # P at context level k, object level l, computed from the top (k=2, l=2) down
        P_top_prev = None
        out = None
        for k in (2, 1, 0):
            c = self._ctx(K, p, k)
            nc = lookup(self.t_c[k], ck(r, c)).astype(np.float64)
            P_l = None
            for l in (2, 1, 0):
                xl = K.k[x, 2 + l] + 1
                n = lookup(self.t_cx[(k, l)], cxk(r, c, xl)).astype(np.float64)
                T = lookup(self.t_T[(k, l)], ck(r, c)).astype(np.float64)
                if self.floor == "proper" and P_top_prev is None:
                    # global context: top level uniform over the classes seen (+1 unseen); finer levels: the coarser
                    # level's probability spread over the finer objects seen under it (+1 unseen)
                    if l == 2:
                        base = 1.0 / (T + 1.0)
                    else:
                        Dl = lookup(self.t_D[l], ck(r, K.k[x, 3 + l] + 1)).astype(np.float64)
                        base = P_l / (Dl + 1.0)
                elif l == 2:
                    base = P_top_prev[2] if P_top_prev is not None else np.full(E, 1.0 / 64)
                else:
                    # within-context backoff to the coarser object level, spread over the finer objects seen
                    # globally under that coarser object (approximated by the coarser level's probability at the
                    # parent context, divided by the parent context's own coarse->fine ratio)
                    base = P_l * (P_top_prev[l] / np.maximum(P_top_prev[l + 1], 1e-300) if P_top_prev is not None else 1.0 / 64)
                with np.errstate(divide="ignore", invalid="ignore"):
                    P = np.where(nc + T > 0, (n + T * base) / np.maximum(nc + T, 1e-12), base)
                P_l = P
                if l == 2:
                    P2 = P
                elif l == 1:
                    P1 = P
                else:
                    P0 = P
            P_top_prev = {0: P0, 1: P1, 2: P2}
        if parts:
            return P_top_prev
        return np.log(np.clip(P_top_prev[0], 1e-300, 1.0))


def first_flags(p, keys):
    """True for the first occurrence of (p, key) in the given order."""
    a = p.astype(np.int64) * B * 64 + keys
    _, first = np.unique(a, return_index=True)
    f = np.zeros(len(p), bool); f[first] = True
    return f


def instance_scores(m, K, w, mode="once"):
    """Edge scores with novelty paid once per process instance and window: an event whose object directory (x1)
    the same process instance already touched with the same op in this window pays only the within-directory
    novelty, and repeated within-directory novelty in that directory is discounted to log(1 + j)."""
    p, x, r, e = edge_events(w, K)
    P = m.logp(K, p, x, r, parts=True)
    P0, P1, P2 = (np.clip(P[i], 1e-300, 1.0) for i in (0, 1, 2))
    s_full = -np.log(P0)
    if mode == "none":
        return p, x, r, e, s_full
    o = np.argsort(w.t[e], kind="stable")
    inv = np.empty_like(o); inv[o] = np.arange(len(o))
    po, ro = p[o], r[o].astype(np.int64)
    x1o, x2o = K.k[x[o], 3] + 1, K.k[x[o], 4] + 1
    f2 = first_flags(po, ro * B + x2o)[inv]          # first time this instance touches this object class
    f1 = first_flags(po, ro * B + x1o)[inv]          # first time this instance touches this directory / address
    s_in = -np.log(P0 / P1)                           # novelty of the object inside its directory
    s_dir = -np.log(P1 / P2)
    s_cls = -np.log(P2)
    s = np.where(f1, s_full, np.where(f2, s_in + s_dir * 0 + 0, s_in))
    # repeated within-directory novelty by the same instance: the j-th novel object in a directory costs log(1+j)
    nov = s_in > 2.0
    key = (po.astype(np.int64) * B + x1o) * 2 + nov[o]
    so = np.argsort(key, kind="stable")
    ks = key[so]
    grp_start = np.r_[True, ks[1:] != ks[:-1]]
    idx = np.arange(len(ks))
    j = idx - np.maximum.accumulate(np.where(grp_start, idx, 0))
    jj = np.empty_like(j); jj[so] = j
    jj = jj[inv]
    rep = (~f1) & nov & (jj > 0)
    s = np.where(rep, np.minimum(s, np.log1p(jj)), s)
    return p, x, r, e, s
