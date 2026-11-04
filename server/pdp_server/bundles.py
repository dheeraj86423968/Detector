"""Model bundle archives served to agents: <bundle dir>.tar.gz, built once next to the bundle directory."""
from __future__ import annotations

import os
import tarfile
import tempfile


def archive(bundle_dir: str, slim: bool = False) -> str:
    """Path of the bundle's gzip archive (layout: bundle/...), building it if missing. Atomic: a concurrent
    request or worker never serves a half-written file. slim: without the files only the server uses
    (pdp_engine.bundle.OPTIONAL_FILES; agents 0.3.4+ ask for it)."""
    from pdp_engine.bundle import OPTIONAL_FILES
    path = bundle_dir.rstrip("/") + (".agent.tar.gz" if slim else ".tar.gz")
    if os.path.exists(path):
        return path
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".bundle-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f, tarfile.open(fileobj=f, mode="w:gz", compresslevel=1) as tar:
            tar.add(bundle_dir, arcname="bundle",
                    filter=(lambda ti: None if slim and os.path.basename(ti.name) in OPTIONAL_FILES else ti))
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path
