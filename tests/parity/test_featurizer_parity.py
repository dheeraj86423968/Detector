"""Parity: pdp_engine featuriser (transform step) vs the framework's per-edge features.

Loads the framework's word2vec.model, computes node vectors with pdp_engine for the nodes of one stored
feat_inference window, and compares them with the src/dst embedding slices of that window's msg.

Usage: python tests/parity/test_featurizer_parity.py <featurization stored_models dir> <feat_inference edge_embeds window file> <emb_dim>
"""
import sys

import numpy as np
import torch

sys.path.insert(0, "/home/platform/engine")
from pdp_engine.featurizer import Word2VecFeaturizer  # noqa: E402
from pdp_engine.sources.pg_replay import PostgresReplay  # noqa: E402

models_dir, window_file, emb_dim = sys.argv[1], sys.argv[2], int(sys.argv[3])
feat = Word2VecFeaturizer.from_gensim(models_dir + "/word2vec.model", emb_dim)
data = torch.load(window_file)
src, dst, msg = data.src.numpy(), data.dst.numpy(), data.msg.numpy()
ntype_dim = 3
ref = {}
for i in range(len(src)):
    ref[int(src[i])] = msg[i, ntype_dim : ntype_dim + emb_dim]
    ref[int(dst[i])] = msg[i, ntype_dim + emb_dim + 10 + ntype_dim :]
print(f"{len(ref)} nodes in window")

pg = PostgresReplay("cadets_e3")
ent = {int(e.uuid): e for e in pg.entities()}  # uuid field holds the framework index id
maxdiff, n = 0.0, 0
for nid, vec in ref.items():
    e = ent[nid]
    mine = feat.vector(e.label, e.ntype)
    d = float(np.abs(mine - vec).max())
    maxdiff = max(maxdiff, d)
    n += 1
    if d > 1e-5 and n < 5:
        print("diff", nid, e.ntype, repr(e.label)[:60], d)
print(f"compared {n} nodes, max abs diff {maxdiff:.2e}")
print("PARITY OK" if maxdiff < 1e-5 else "PARITY FAILED")
