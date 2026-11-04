"""Detector models, faithful to the research configurations evaluated with PIDSMaker.

detector-1 (Velox):   h = Linear(x);  logits = EdgeMLP(h_src, h_dst);  loss = CE(edge type)
detector-2 (ORTHRUS): per 1024-edge batch, the TGN last-neighbour loader returns the batch nodes plus their
                      last 20 neighbours and the past edges among them; node input = src_lin(x if node is a
                      source in the batch else 0) + dst_lin(x if node is a destination in the batch else 0);
                      2-layer TransformerConv (8 heads, edge feature = past edge type one-hot);
                      logits = EdgeMLP(h_src, h_dst); loss = CE(edge type). No memory, no time encoding.

Both are self-supervised: the per-edge cross-entropy of the true edge type is the anomaly score.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
try:                                    # the server trains with PyG; the slim agent image has the pure-torch copy
    from torch_geometric.nn import TransformerConv
except ImportError:
    from .tconv import TransformerConv

from .schema import NUM_EDGE_TYPES


# --------------------------------------------------------------------------- shared decoder
class EdgeMLP(nn.Module):
    """PIDSMaker CustomEdgeMLP with architecture 'linear(0.5) | relu' and src_dst_projection_coef 2."""

    def __init__(self, in_dim: int, out_dim: int = NUM_EDGE_TYPES, coef: int = 2):
        super().__init__()
        self.lin_src = nn.Linear(in_dim, in_dim * coef)
        self.lin_dst = nn.Linear(in_dim, in_dim * coef)
        d = in_dim * 2 * coef
        self.mlp = nn.Sequential(nn.Linear(d, int(d * 0.5)), nn.ReLU(), nn.Linear(int(d * 0.5), out_dim))

    def forward(self, h_src, h_dst):
        return self.mlp(torch.cat([self.lin_src(h_src), self.lin_dst(h_dst)], dim=-1))


def edge_losses(logits: torch.Tensor, etype: torch.Tensor, reduce: bool) -> torch.Tensor:
    return F.cross_entropy(logits, etype, reduction="mean" if reduce else "none")


# --------------------------------------------------------------------------- detector-1
DEG_DIM = 4


def window_degrees(src: torch.Tensor, dst: torch.Tensor, etype: torch.Tensor | None = None) -> tuple[torch.Tensor, torch.Tensor]:
    """Explicit structural input for detector-1: per node, log1p of its out-degree, in-degree, distinct successors
    and distinct predecessors in the window, gathered for every edge's source and destination ((E, DEG_DIM) each).

    The published Velox received degree-dependent inputs only implicitly, through a buffer-reuse defect in its
    reindexer (Moon et al., arXiv 2609.33532); a faithful port without the defect has no structural signal at all,
    which is the likely reason detector-1 failed on CADETS. Per-edge-type counts are deliberately not used: they
    would contain the label being predicted (the edge's own type). Computed over the whole window, identically in
    training and in the runtime."""
    E = src.shape[0]
    nodes, inv = torch.unique(torch.cat([src, dst]), return_inverse=True)
    s_i, d_i = inv[:E], inv[E:]
    U = nodes.shape[0]
    deg = torch.zeros((U, DEG_DIM), dtype=torch.float32, device=src.device)
    one = torch.ones(E, dtype=torch.float32, device=src.device)
    deg[:, 0].index_add_(0, s_i, one)
    deg[:, 1].index_add_(0, d_i, one)
    pairs = torch.unique(s_i * U + d_i)
    ps, pd = pairs // U, pairs % U
    one_p = torch.ones(pairs.shape[0], dtype=torch.float32, device=src.device)
    deg[:, 2].index_add_(0, ps, one_p)
    deg[:, 3].index_add_(0, pd, one_p)
    deg = torch.log1p(deg) / 7.0          # log1p(1000) ~ 6.9: typical values in [0, 1]
    return deg[s_i], deg[d_i]


class VeloxModel(nn.Module):
    def __init__(self, in_dim: int, out_dim: int = 256):
        super().__init__()
        self.encoder = nn.Linear(in_dim, out_dim)
        self.decoder = EdgeMLP(out_dim)

    def forward(self, x_src: torch.Tensor, x_dst: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x_src), self.encoder(x_dst))

    def losses(self, x_src, x_dst, etype, reduce=False):
        return edge_losses(self(x_src, x_dst), etype, reduce)


# --------------------------------------------------------------------------- detector-2
class LastNeighborLoader:
    """Port of PIDSMaker's LastNeighborLoader (undirected, keeps the `size` most recent edges per node).

    Each neighbour slot also stores the type of its edge. PIDSMaker keeps a global edge-id -> type history instead,
    which grows by one entry per event forever (on a busy host ~60 M a day); only the edges still held in a slot are
    ever looked up, so the per-slot copy gives identical results in bounded memory."""

    def __init__(self, num_nodes: int, size: int = 20, device=None):
        self.size = size
        self.device = device
        self.neighbors = torch.empty((num_nodes, size), dtype=torch.long, device=device)
        self.e_id = torch.empty((num_nodes, size), dtype=torch.long, device=device)
        self.etype = torch.zeros((num_nodes, size), dtype=torch.int8, device=device)
        self._assoc = torch.empty(num_nodes, dtype=torch.long, device=device)
        self.reset_state()

    def reset_state(self):
        self.cur_e_id = 0
        self.e_id.fill_(-1)

    def __call__(self, n_id: torch.Tensor, with_etype: bool = False):
        """with_etype: also return the type of each returned past edge (aligned with e_id)."""
        neighbors = self.neighbors[n_id]
        nodes = n_id.view(-1, 1).repeat(1, self.size)
        e_id = self.e_id[n_id]
        et = self.etype[n_id] if with_etype else None
        mask = e_id >= 0
        neighbors, nodes, e_id = neighbors[mask], nodes[mask], e_id[mask]
        n_id = torch.cat([n_id, neighbors]).unique()
        self._assoc[n_id] = torch.arange(n_id.size(0), device=n_id.device)
        neighbors, nodes = self._assoc[neighbors], self._assoc[nodes]
        if with_etype:
            return n_id, torch.stack([neighbors, nodes]), e_id, et[mask]
        return n_id, torch.stack([neighbors, nodes]), e_id

    def insert(self, src: torch.Tensor, dst: torch.Tensor, etype: torch.Tensor | None = None):
        neighbors = torch.cat([src, dst], dim=0)
        nodes = torch.cat([dst, src], dim=0)
        e_id = torch.arange(self.cur_e_id, self.cur_e_id + src.size(0), device=src.device).repeat(2)
        et = (etype.to(device=src.device, dtype=torch.int8) if etype is not None
              else torch.zeros(src.size(0), dtype=torch.int8, device=src.device)).repeat(2)
        self.cur_e_id += src.numel()
        nodes, perm = nodes.sort()
        neighbors, e_id, et = neighbors[perm], e_id[perm], et[perm]
        n_id = nodes.unique()
        self._assoc[n_id] = torch.arange(n_id.numel(), device=n_id.device)
        edge_counts = torch.bincount(self._assoc[nodes], minlength=n_id.numel())
        temp_size = edge_counts.max().item() if edge_counts.numel() > 0 else 1
        cum = torch.cat([torch.tensor([0], device=nodes.device), edge_counts.cumsum(0)])
        local = torch.arange(nodes.size(0), device=nodes.device) - cum[self._assoc[nodes]]
        dense_id = local + (self._assoc[nodes] * temp_size)
        dense_e_id = e_id.new_full((n_id.numel() * temp_size,), -1)
        dense_e_id[dense_id] = e_id
        dense_e_id = dense_e_id.view(-1, temp_size)
        dense_neighbors = e_id.new_full((n_id.numel() * temp_size,), -1)
        dense_neighbors[dense_id] = neighbors
        dense_neighbors = dense_neighbors.view(-1, temp_size)
        dense_et = et.new_zeros((n_id.numel() * temp_size,))
        dense_et[dense_id] = et
        dense_et = dense_et.view(-1, temp_size)
        e_id = torch.cat([self.e_id[n_id, : self.size], dense_e_id], dim=-1)
        neighbors = torch.cat([self.neighbors[n_id, : self.size], dense_neighbors], dim=-1)
        et = torch.cat([self.etype[n_id, : self.size], dense_et], dim=-1)
        e_id, perm = e_id.topk(self.size, dim=-1)
        self.e_id[n_id] = e_id
        self.neighbors[n_id] = torch.gather(neighbors, 1, perm)
        self.etype[n_id] = torch.gather(et, 1, perm)

    # ---- persistence (bundle) ----
    def state(self) -> dict:
        return {"neighbors": self.neighbors.cpu(), "e_id": self.e_id.cpu(), "cur_e_id": self.cur_e_id, "slot_etype": self.etype.cpu()}

    def load_state(self, st: dict):
        """Restore a snapshot; the loader may be larger than the snapshot (entities registered after the bundle
        was built), in which case the extra rows stay empty. Snapshots from before per-slot edge types carry the
        global history (`etype`, indexed by edge id) instead; the slot types are derived from it."""
        nb, ei = st["neighbors"].to(self.device), st["e_id"].to(self.device)
        n = nb.shape[0]
        if n > self.neighbors.shape[0]:
            raise ValueError(f"snapshot has {n} nodes but loader only {self.neighbors.shape[0]}")
        if st.get("slot_etype") is not None:
            se = st["slot_etype"].to(device=self.device, dtype=torch.int8)
        else:
            hist = st["etype"].to(torch.int8)
            se = hist[ei.cpu().clamp(min=0)].to(self.device) if hist.numel() else torch.zeros_like(ei, dtype=torch.int8)
            se[ei < 0] = 0
        self.neighbors[:n].copy_(nb)
        self.e_id[:n].copy_(ei)
        self.etype[:n].copy_(se)
        self.neighbors[n:] = 0
        self.e_id[n:] = -1
        self.etype[n:] = 0
        self.cur_e_id = int(st["cur_e_id"])


class TGNState:
    """Neighbour loader (with the type of each held edge, the equivalent of PIDSMaker's full_data.edge_type[e_id]);
    grows with the node space. Snapshot/restore for bundles."""

    def __init__(self, num_nodes: int, size: int = 20, device=None, capacity: int = 0):
        self.loader = LastNeighborLoader(num_nodes, size, device)
        self.device = device
        self.n = 0                      # edges inserted so far (informational)

    def insert(self, src: torch.Tensor, dst: torch.Tensor, etype: torch.Tensor):
        self.n += src.numel()
        self.loader.insert(src, dst, etype)

    @staticmethod
    def edge_feats(etype: torch.Tensor) -> torch.Tensor:
        return F.one_hot(etype.long(), NUM_EDGE_TYPES).float()

    def state(self) -> dict:
        st = self.loader.state()
        st["n"] = self.n
        return st

    def load_state(self, st: dict):
        self.loader.load_state(st)
        self.n = int(st.get("n", 0))

    def compact(self, keep: torch.Tensor, old2new: torch.Tensor):
        """Keep rows `keep` (old ids, ascending) renumbered by `old2new` (old id -> new id, -1 dropped). Slots that
        point to a dropped node are emptied (the caller keeps every node a kept node still points to)."""
        L = self.loader
        keep = keep.to(L.neighbors.device)
        o2n = old2new.to(L.neighbors.device)
        nb, ei, et = L.neighbors[keep], L.e_id[keep].clone(), L.etype[keep]
        valid = ei >= 0
        mapped = torch.where(valid, o2n[nb.clamp(min=0, max=o2n.numel() - 1)], torch.zeros_like(nb))
        lost = valid & (mapped < 0)
        ei[lost] = -1
        L.neighbors, L.e_id, L.etype = mapped.clamp(min=0), ei, et
        L._assoc = torch.empty(keep.numel(), dtype=torch.long, device=L.device)
        return int(lost.sum())

    def grow(self, num_nodes: int):
        """Enlarge the node space (new entities seen at runtime)."""
        L = self.loader
        if num_nodes <= L.neighbors.shape[0]:
            return
        old = L.neighbors.shape[0]
        nb = torch.empty((num_nodes, L.size), dtype=torch.long, device=L.device)
        ei = torch.full((num_nodes, L.size), -1, dtype=torch.long, device=L.device)
        et = torch.zeros((num_nodes, L.size), dtype=torch.int8, device=L.device)
        nb[:old] = L.neighbors
        ei[:old] = L.e_id
        et[:old] = L.etype
        L.neighbors, L.e_id, L.etype = nb, ei, et
        L._assoc = torch.empty(num_nodes, dtype=torch.long, device=L.device)


def save_tgn_state(path: str, st: dict) -> None:
    """Bundle file of a TGN snapshot (neighbour ids, edge ids, per-slot edge types)."""
    np.savez(path, neighbors=st["neighbors"].cpu().numpy(), e_id=st["e_id"].cpu().numpy(), cur_e_id=np.int64(st["cur_e_id"]),
             slot_etype=st["slot_etype"].cpu().numpy(), n=np.int64(st.get("n", 0)))


def load_tgn_state(path: str) -> dict:
    """Read a snapshot written by save_tgn_state, or an older one with the global edge-type history."""
    z = np.load(path, allow_pickle=False)
    st = {"neighbors": torch.from_numpy(z["neighbors"]), "e_id": torch.from_numpy(z["e_id"]), "cur_e_id": int(z["cur_e_id"]),
          "n": int(z["n"]) if "n" in z.files else 0}
    if "slot_etype" in z.files:
        st["slot_etype"] = torch.from_numpy(z["slot_etype"])
    else:
        st["etype"] = torch.from_numpy(z["etype"])
    return st


@dataclass
class TGNBatch:
    n_id: torch.Tensor            # global ids of batch nodes + neighbours
    edge_index: torch.Tensor      # past edges among n_id (local ids), neighbour -> node
    edge_feats: torch.Tensor      # one-hot type of those past edges
    x_from: torch.Tensor          # (len(n_id), d): x for nodes that are sources in the batch, else 0
    x_to: torch.Tensor
    src_local: torch.Tensor       # batch edges in local ids
    dst_local: torch.Tensor


def make_tgn_batch(src: torch.Tensor, dst: torch.Tensor, x: torch.Tensor, state: TGNState) -> TGNBatch:
    """src/dst: global ids of the batch edges; x: (num_nodes, d) static node features on the same device.
    Mirrors PIDSMaker's compute_tgn_graphs (insert_neighbors_before=False, fix flags off)."""
    L = state.loader
    dev = L.neighbors.device                 # compute device (may differ from the feature matrix's device)
    batch_nodes = torch.cat([src, dst]).unique()
    n_id, edge_index, e_id, past_et = L(batch_nodes, with_etype=True)
    assoc = L._assoc  # n_id -> local, set by the loader call
    num = n_id.size(0)
    # x_is_tuple reindexing: mean of x over edges where the node is src (resp. dst); static features -> x itself.
    # x may live on CPU to spare GPU memory for a large registry; gather with its own device's indices, then move.
    xf = x[src.to(x.device)].to(dev)
    xt = x[dst.to(x.device)].to(dev)
    x_from = torch.zeros((num, x.shape[1]), device=dev)
    x_to = torch.zeros((num, x.shape[1]), device=dev)
    s_loc, d_loc = assoc[src], assoc[dst]
    x_from[s_loc] = xf
    x_to[d_loc] = xt
    return TGNBatch(n_id, edge_index, TGNState.edge_feats(past_et).to(dev), x_from, x_to, s_loc, d_loc)


class OrthrusModel(nn.Module):
    def __init__(self, in_dim: int, memory_dim: int = 100, hid_dim: int = 256, out_dim: int = 256,
                 heads: int = 8, dropout: float = 0.3):
        super().__init__()
        self.src_linear = nn.Linear(in_dim, memory_dim)
        self.dst_linear = nn.Linear(in_dim, memory_dim)
        self.conv1 = TransformerConv(memory_dim, hid_dim, heads=heads, dropout=dropout, edge_dim=NUM_EDGE_TYPES, concat=True)
        self.conv2 = TransformerConv(hid_dim * heads, out_dim, heads=1, concat=False, dropout=dropout, edge_dim=NUM_EDGE_TYPES)
        self.drop = nn.Dropout(dropout)
        self.decoder = EdgeMLP(out_dim)

    def forward(self, b: TGNBatch) -> torch.Tensor:
        h = self.src_linear(b.x_from) + self.dst_linear(b.x_to)
        h = self.drop(F.relu(self.conv1(h, b.edge_index, b.edge_feats)))
        h = self.conv2(h, b.edge_index, b.edge_feats)
        return self.decoder(h[b.src_local], h[b.dst_local])

    def losses(self, b: TGNBatch, etype: torch.Tensor, reduce=False):
        return edge_losses(self(b), etype, reduce)


def seed_everything(seed: int):
    import random
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed); torch.cuda.manual_seed_all(seed)
