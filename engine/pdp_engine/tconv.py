"""Pure-PyTorch TransformerConv, numerically equivalent to torch_geometric 2.5.3's (the subset ORTHRUS uses:
edge features, concat or head mean, root weight without beta). Same parameter names, so bundles load into either.

The endpoint agent uses this instead of PyG: PyG pulls SciPy, scikit-learn, NetworkX and aiohttp into the image
(~250 MB) for this one layer. The server trains with PyG; tests/unit/test_tconv.py checks both give the same output.
"""
from __future__ import annotations

import math

import torch
import torch.nn as nn
import torch.nn.functional as F


def segment_softmax(src: torch.Tensor, index: torch.Tensor, num: int) -> torch.Tensor:
    """torch_geometric.utils.softmax over edges grouped by `index` (dim 0), same operations and order."""
    shape = (num,) + tuple(src.shape[1:])
    idx = index.view(-1, *([1] * (src.dim() - 1))).expand_as(src)
    src_max = src.new_zeros(shape).scatter_reduce_(0, idx, src.detach(), reduce="amax", include_self=False)
    out = (src - src_max.index_select(0, index)).exp()
    out_sum = out.new_zeros(shape).scatter_add_(0, idx, out) + 1e-16
    return out / out_sum.index_select(0, index)


class TransformerConv(nn.Module):
    def __init__(self, in_channels: int, out_channels: int, heads: int = 1, concat: bool = True, dropout: float = 0.0,
                 edge_dim: int | None = None, bias: bool = True, root_weight: bool = True, beta: bool = False):
        super().__init__()
        if beta:
            raise NotImplementedError("beta is not used by the detectors")
        self.in_channels, self.out_channels, self.heads, self.concat = in_channels, out_channels, heads, concat
        self.dropout, self.edge_dim, self.root_weight = dropout, edge_dim, root_weight
        self.lin_key = nn.Linear(in_channels, heads * out_channels)
        self.lin_query = nn.Linear(in_channels, heads * out_channels)
        self.lin_value = nn.Linear(in_channels, heads * out_channels)
        self.lin_edge = nn.Linear(edge_dim, heads * out_channels, bias=False) if edge_dim is not None else None
        if root_weight:
            self.lin_skip = nn.Linear(in_channels, heads * out_channels if concat else out_channels, bias=bias)
        else:
            self.lin_skip = None

    def forward(self, x, edge_index: torch.Tensor, edge_attr: torch.Tensor | None = None) -> torch.Tensor:
        H, C = self.heads, self.out_channels
        if isinstance(x, torch.Tensor):
            x = (x, x)
        query = self.lin_query(x[1]).view(-1, H, C)
        key = self.lin_key(x[0]).view(-1, H, C)
        value = self.lin_value(x[0]).view(-1, H, C)
        j, i = edge_index[0], edge_index[1]                 # flow source_to_target: messages j -> i
        query_i, key_j, value_j = query.index_select(0, i), key.index_select(0, j), value.index_select(0, j)
        if self.lin_edge is not None:
            e = self.lin_edge(edge_attr).view(-1, H, C)
            key_j = key_j + e
        alpha = (query_i * key_j).sum(dim=-1) / math.sqrt(C)
        alpha = segment_softmax(alpha, i, x[1].size(0))
        alpha = F.dropout(alpha, p=self.dropout, training=self.training)
        msg = value_j
        if self.lin_edge is not None:
            msg = msg + e
        msg = msg * alpha.view(-1, H, 1)
        out = msg.new_zeros((x[1].size(0), H, C)).scatter_add_(0, i.view(-1, 1, 1).expand_as(msg), msg)   # aggr "add"
        out = out.view(-1, H * C) if self.concat else out.mean(dim=1)
        if self.lin_skip is not None:
            out = out + self.lin_skip(x[1])
        return out
