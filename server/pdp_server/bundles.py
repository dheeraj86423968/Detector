"""Model bundle archives served to agents: <bundle dir>.tar.gz, built once next to the bundle directory."""
from __future__ import annotations

import os
import tarfile
import tempfile


def archive(bundle_dir: str) -> str:
    """Path of the bundle's gzip archive (layout: bundle/...), building it if missing. Atomic: a concurrent
    request or worker never serves a half-written file."""
    path = bundle_dir.rstrip("/") + ".tar.gz"
    if os.path.exists(path):
        return path
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".bundle-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w:gz", compresslevel=1) as tar:
            tar.add(bundle_dir, arcname="bundle")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path
