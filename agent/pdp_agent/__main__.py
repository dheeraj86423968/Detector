"""pdp agent CLI:
  python -m pdp_agent enroll <token> [--ca-sha256 <hex>]   enrol (idempotent); the fingerprint is shown in the console
  python -m pdp_agent run                                  collect, upload the baseline, detect locally
  python -m pdp_agent status                               print the local identity and phase
"""
import os
import sys

from .agent import Agent, log
from .config import Config


def main():
    cfg = Config.load()
    a = Agent(cfg)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "enroll":
        if len(sys.argv) < 3:
            print(__doc__); sys.exit(2)
        fp = sys.argv[sys.argv.index("--ca-sha256") + 1] if "--ca-sha256" in sys.argv else None
        a.enroll(sys.argv[2], ca_sha256=fp)
        return
    if cmd == "status":
        import json
        print(json.dumps({"endpoint_id": a.state.get("endpoint_id"), "phase": a.state.get("phase"), "bundle_id": a.state.get("bundle_id"),
                          "entities": len(a.reg), "days": a.state.days()}, indent=1))
        return
    if cmd != "run":
        print(__doc__); sys.exit(2)
    src = cfg.source
    if src["kind"] == "auditd":
        from .sources.live import AuditdLive
        source = AuditdLive(src.get("log", "/var/log/audit/audit.log"))
    elif src["kind"] == "db-replay":
        from .sources.live import DatabaseReplay
        source = DatabaseReplay(src["database"], src["days"], host=src.get("host", "postgres"), state=a.state, pace=float(src.get("pace", 0)))
    elif src["kind"] == "strace":
        from .sources.strace_src import StraceLive
        source = StraceLive(command=src["command"], trace_dir=src.get("trace_dir"), batch=int(src.get("batch", 1000)))
    elif src["kind"] == "ebpf":
        from .sources.ebpf import EbpfLive
        source = EbpfLive(batch=int(src.get("batch", 2000)), ring_pages=int(src.get("ring_pages", 1024)), proc=src.get("proc", "/proc"),
                          engine=src.get("engine"))   # "core" (libbpf CO-RE, default) or "bcc" (header-compiled fallback)
    elif src["kind"] == "etw":
        from .sources.windows_etw import EtwLive
        source = EtwLive(batch=int(src.get("batch", 2000)))
    elif src["kind"] == "sandbox":
        from .sources.sandbox import SandboxSource
        source = SandboxSource(src, state=a.state)
    else:
        raise SystemExit(f"unknown source kind {src['kind']}")
    log(f"agent {cfg.source['kind']} starting")
    a.run(source)


if __name__ == "__main__":
    main()
