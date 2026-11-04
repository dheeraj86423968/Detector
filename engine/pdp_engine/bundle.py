"""Signed model bundles (no pickle): json manifest + npz weights/state + featuriser files.

Layout of a bundle directory:
  manifest.json      {version, created, endpoint, detectors:{...}, calibration:{...}, sha256:{file: digest}}
  featurizer/        vectors.npy, featurizer.json
  detector-1.npz     Velox weights
  detector-2-s<k>.npz ORTHRUS weights per seed
  tgn_state.npz      neighbour loader + edge-type history at the end of the baseline
  signature.json     Ed25519 signature of manifest.json (added by the server's signer)
"""
from __future__ import annotations

import hashlib
import json
import os
import time

import numpy as np
import torch


def save_state_dict(path: str, sd: dict) -> None:
    np.savez(path, **{k: v.detach().cpu().numpy() for k, v in sd.items()})


def load_state_dict(path: str) -> dict:
    z = np.load(path, allow_pickle=False)
    return {k: torch.from_numpy(z[k]) for k in z.files}


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(bundle_dir: str, meta: dict) -> dict:
    digests = {}
    for root, _, files in os.walk(bundle_dir):
        for f in files:
            if f in ("manifest.json", "signature.json"):
                continue
            p = os.path.join(root, f)
            digests[os.path.relpath(p, bundle_dir)] = sha256(p)
    manifest = {"format": 1, "created": int(time.time()), **meta, "sha256": digests}
    json.dump(manifest, open(os.path.join(bundle_dir, "manifest.json"), "w"), indent=1, sort_keys=True)
    return manifest


def verify_digests(bundle_dir: str) -> None:
    manifest = json.load(open(os.path.join(bundle_dir, "manifest.json")))
    for rel, digest in manifest["sha256"].items():
        if sha256(os.path.join(bundle_dir, rel)) != digest:
            raise ValueError(f"bundle file {rel} does not match its manifest digest")


# Signing is done with Ed25519 via `cryptography` when available (server image); verification on the
# endpoint uses the same library. The engine itself only handles digests so it stays dependency-light.
def sign_manifest(bundle_dir: str, private_key_pem: bytes) -> None:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(private_key_pem, password=None)
    data = open(os.path.join(bundle_dir, "manifest.json"), "rb").read()
    sig = key.sign(data)
    json.dump({"alg": "Ed25519", "sig": sig.hex()}, open(os.path.join(bundle_dir, "signature.json"), "w"))


def verify_signature(bundle_dir: str, public_key_pem: bytes) -> None:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    key = load_pem_public_key(public_key_pem)
    data = open(os.path.join(bundle_dir, "manifest.json"), "rb").read()
    sig = bytes.fromhex(json.load(open(os.path.join(bundle_dir, "signature.json")))["sig"])
    key.verify(sig, data)  # raises InvalidSignature
    verify_digests(bundle_dir)
