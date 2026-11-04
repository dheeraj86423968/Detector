"""Node featurisation: word2vec over tokenised entity labels (PIDSMaker's `word2vec` featurization +
`feat_inference_word2vec`), fitted on the baseline (training) labels only.

Node feature = [ sentence vector (emb_dim) | node-type one-hot (3) ]  (PIDSMaker `node_features: node_emb,node_type`).
"""
from __future__ import annotations

import json
import os
import re
from typing import Iterable

import numpy as np

from .schema import NODE_TYPE_ID, NUM_NODE_TYPES


def _word_tokenize(s: str) -> list[str]:
    from nltk import word_tokenize  # punkt data ships in the engine image
    return word_tokenize(s)


class _VectorLookup:
    """Minimal word-vector lookup (dict + matrix) so inference needs no gensim. Mirrors the `kv[w]` / `w in kv`
    interface the featurizer uses."""

    def __init__(self, vocab: list[str], vectors: np.ndarray):
        self.index = {w: i for i, w in enumerate(vocab)}
        self.vectors = vectors

    def __contains__(self, w: str) -> bool:
        return w in self.index

    def __getitem__(self, w: str) -> np.ndarray:
        return self.vectors[self.index[w]]


def tokenize(label: str, ntype: str) -> list[str]:
    """Identical to PIDSMaker's tokenize_label."""
    if label == "":
        return [""]
    if ntype in ("subject", "file"):
        return _word_tokenize(re.sub(r"\\+", "/", label).replace("/", " / "))
    if ntype == "netflow":
        return _word_tokenize(label.replace(":", " : ").replace(".", " . "))
    raise ValueError(ntype)


def word_weights(n: int, decline_percent: float) -> list[float]:
    d = -1 / n * decline_percent / 100
    a1 = 1 / n - 0.5 * (n - 1) * d
    return [a1 + i * d for i in range(n)]


class Word2VecFeaturizer:
    def __init__(self, emb_dim: int = 256, epochs: int = 50, window: int = 5, min_count: int = 1, skip_gram: bool = True,
                 negative: int = 5, alpha: float = 0.025, decline_rate: float = 30.0, seed: int = 0, workers: int = 1):
        self.emb_dim, self.epochs, self.window, self.min_count = emb_dim, epochs, window, min_count
        self.skip_gram, self.negative, self.alpha, self.decline_rate, self.seed, self.workers = skip_gram, negative, alpha, decline_rate, seed, workers
        self.kv = None  # gensim KeyedVectors after fit/load

    # ---- fit -------------------------------------------------------------------------------
    def fit(self, labels: Iterable[tuple[str, str]]) -> "Word2VecFeaturizer":
        """labels: (label, ntype) of the baseline nodes; duplicates are dropped (as in the framework)."""
        from gensim.models import Word2Vec
        seen, corpus = set(), []
        for label, ntype in labels:
            if label in seen:
                continue
            seen.add(label)
            corpus.append(tokenize(label, ntype))
        model = Word2Vec(corpus, alpha=self.alpha, vector_size=self.emb_dim, window=self.window, min_count=self.min_count,
                         sg=int(self.skip_gram), workers=self.workers, epochs=1, compute_loss=True, negative=self.negative, seed=self.seed)
        for _ in range(self.epochs - 1):
            model.running_training_loss = 0
            model.train(corpus, epochs=1, total_examples=len(corpus), compute_loss=True)
        model.init_sims(replace=True)  # unit-normalised word vectors, as in the framework
        self.kv = model.wv
        return self

    # ---- transform -------------------------------------------------------------------------
    def vector(self, label: str, ntype: str) -> np.ndarray:
        tokens = tokenize(label, ntype)
        weights = word_weights(len(tokens), self.decline_rate)
        zeros = np.zeros(self.emb_dim, dtype=np.float32)
        vecs = [self.kv[w] if w in self.kv else zeros for w in tokens]
        v = np.mean([w * x for w, x in zip(weights, vecs)], axis=0)
        return (v / (np.linalg.norm(v) + 1e-12)).astype(np.float32)

    def features(self, labels: list[str], types: list[str]) -> np.ndarray:
        """(N, emb_dim + 3) node features in dense-id order."""
        out = np.zeros((len(labels), self.emb_dim + NUM_NODE_TYPES), dtype=np.float32)
        cache: dict[tuple[str, str], np.ndarray] = {}
        for i, (lab, nt) in enumerate(zip(labels, types)):
            key = (lab, nt)
            v = cache.get(key)
            if v is None:
                v = self.vector(lab, nt)
                cache[key] = v
            out[i, : self.emb_dim] = v
            out[i, self.emb_dim + NODE_TYPE_ID[nt]] = 1.0
        return out

    # ---- persistence (no pickle: vocabulary json + float32 matrix) ---------------------------
    def save(self, directory: str) -> None:
        os.makedirs(directory, exist_ok=True)
        vocab = list(self.kv.index_to_key)
        np.save(os.path.join(directory, "vectors.npy"), np.stack([self.kv[w] for w in vocab]).astype(np.float32))
        json.dump({"vocab": vocab, "emb_dim": self.emb_dim, "decline_rate": self.decline_rate},
                  open(os.path.join(directory, "featurizer.json"), "w"))

    @classmethod
    def load(cls, directory: str) -> "Word2VecFeaturizer":
        meta = json.load(open(os.path.join(directory, "featurizer.json")))
        vecs = np.load(os.path.join(directory, "vectors.npy"))
        f = cls(emb_dim=meta["emb_dim"], decline_rate=meta["decline_rate"])
        f.kv = _VectorLookup(meta["vocab"], vecs)   # gensim-free at inference (slim endpoint image needs no gensim)
        return f

    @classmethod
    def from_gensim(cls, path: str, emb_dim: int, decline_rate: float = 30.0) -> "Word2VecFeaturizer":
        """Load a framework-trained word2vec.model (used by the parity tests)."""
        from gensim.models import Word2Vec
        f = cls(emb_dim=emb_dim, decline_rate=decline_rate)
        f.kv = Word2Vec.load(path).wv
        return f
