"""Signed model bundles (no pickle): json manifest + npz weights/state + featuriser files.

Layout of a bundle directory:
  manifest.json      {version, created, endpoint, detectors:{...}, calibration:{...}, sha256:{file: digest}}
  featurizer/        vectors.npy, featurizer.json
  detector-1-s<k>.npz  Velox weights per seed (window-degree / no structural input; 0.2: detector-1.npz)
  detector-1-bs-s<k>.npz  the same with the batch_scale input (0.5): a different name so that agents before 0.5,
                     which would score it without the input, fail to load the bundle and keep their previous one
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


# features a bundle can require of the runtime (manifest "requires"); a runtime refuses bundles needing others
SUPPORTED_FEATURES = {"detector-1:batch_scale", "fusion:max"}


def detector1_file(velox_input: str, k: int) -> str:
    return f"detector-1-bs-s{k}.npz" if velox_input == "batch_scale" else f"detector-1-s{k}.npz"


def requirements(velox_input: str, fusion_mode: str) -> list[str]:
    """What a bundle needs beyond the 0.4 runtime (manifest "requires")."""
    return (["detector-1:batch_scale"] if velox_input == "batch_scale" else []) + (["fusion:max"] if fusion_mode == "max" else [])


def check_requires(manifest: dict) -> None:
    missing = [f for f in manifest.get("requires") or [] if f not in SUPPORTED_FEATURES]
    if missing:
        raise ValueError(f"bundle needs runtime features this version does not have: {missing} (update the agent)")


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


# Files only the server needs (the simulator replays the validation day from this state); agents get bundles without
# them. Their digests are still in the signed manifest, so a present file must match.
OPTIONAL_FILES = {"tgn_state_val_start.npz"}


def verify_digests(bundle_dir: str) -> None:
    manifest = json.load(open(os.path.join(bundle_dir, "manifest.json")))
    for rel, digest in manifest["sha256"].items():
        p = os.path.join(bundle_dir, rel)
        if rel in OPTIONAL_FILES and not os.path.exists(p):
            continue
        if sha256(p) != digest:
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
