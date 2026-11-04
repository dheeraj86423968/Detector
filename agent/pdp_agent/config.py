"""Agent configuration (environment or /etc/pdp/agent.json)."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class Config:
    server_url: str = "https://localhost"            # enrolment (plain TLS)
    agent_url: str = "https://localhost:8443"        # mTLS agent API
    data_dir: str = "/var/lib/pdp"
    pki_dir: str = "/var/lib/pdp/pki"
    source: dict = field(default_factory=lambda: {"kind": "auditd", "log": "/var/log/audit/audit.log"})
    day_tz: str = "UTC"                              # calendar used for baseline days (benchmarks: US/Eastern)
    status_interval: float = 30.0
    heartbeat_interval: float = 60.0
    device: str = "cpu"                              # detection device; "cuda" only for benchmark agents on a GPU host
    feat_device: str | None = None                   # feature-matrix device; None -> CPU when detecting on GPU (avoids
                                                     # OOM for large registries), else same as device
    spool_max_mb: int = 1024                         # hard cap on the local event spool (the server config may override)
    spool_unscored_max_age_h: float = 6.0            # without a model, uploaded baseline events wait this long at most
    entity_max_age_h: float = 6.0                    # registry compaction: entities unseen this long may be dropped
    compact_min_entities: int = 200_000              # ... once the registry holds at least this many
    compact_interval_s: float = 3600.0               # ... checked this often

    @property
    def key_path(self): return os.path.join(self.pki_dir, "agent.key")
    @property
    def cert_path(self): return os.path.join(self.pki_dir, "agent.pem")
    @property
    def server_ca(self): return os.path.join(self.pki_dir, "ca.pem")
    @property
    def signing_pub(self): return os.path.join(self.pki_dir, "bundle_signing.pub")

    @staticmethod
    def load(path: str | None = None) -> "Config":
        cfg = Config()
        path = path or os.environ.get("PDP_AGENT_CONFIG", "/etc/pdp/agent.json")
        if os.path.exists(path):
            for k, v in json.load(open(path)).items():
                setattr(cfg, k, v)
        for k in ("server_url", "agent_url", "data_dir", "pki_dir"):
            if os.environ.get("PDP_" + k.upper()):
                setattr(cfg, k, os.environ["PDP_" + k.upper()])
        if os.environ.get("PDP_SOURCE_KIND"):        # e.g. docker run -e PDP_SOURCE_KIND=ebpf, without a config file
            cfg.source = {**(cfg.source if cfg.source.get("kind") == os.environ["PDP_SOURCE_KIND"] else {}), "kind": os.environ["PDP_SOURCE_KIND"]}
        cfg.pki_dir = cfg.pki_dir or os.path.join(cfg.data_dir, "pki")
        return cfg
