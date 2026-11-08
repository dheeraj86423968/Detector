"""pdp agent CLI:
  python -m pdp_agent enroll <token> [--ca-sha256 <hex>]   enrol (idempotent); the fingerprint is shown in the console
  python -m pdp_agent run                                  collect, upload the baseline, detect locally
  python -m pdp_agent status                               print the local identity and phase
"""
import os
import sys

from .agent import Agent, log
from .config import Config


def enroll_token(arg: str) -> str:
    """The enrolment token: the argument itself, or - for `env` / `-` - PDP_ENROLL_TOKEN from the environment, else one
    line from stdin. A token on the command line is visible to every local user in /proc/*/cmdline for as long as
    the enrolment takes (the container shares the host's pid namespace), so the installers and the entrypoint pass
    it this way."""
    import os
    if arg not in ("env", "-"):
        return arg
    tok = os.environ.get("PDP_ENROLL_TOKEN", "").strip()
    if not tok and arg == "-":
        tok = sys.stdin.readline().strip()
    if not tok:
        print("enroll: no token (set PDP_ENROLL_TOKEN or pipe it on stdin)", file=sys.stderr); sys.exit(2)
    return tok


def main():
    cfg = Config.load()
    a = Agent(cfg)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "enroll":
        if len(sys.argv) < 3:
            print(__doc__); sys.exit(2)
        fp = sys.argv[sys.argv.index("--ca-sha256") + 1] if "--ca-sha256" in sys.argv else None
        a.enroll(enroll_token(sys.argv[2]), ca_sha256=fp)
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
        source = EbpfLive(batch=int(src.get("batch", 2000)), ring_pages=int(src.get("ring_pages", 4096)), proc=src.get("proc", "/proc"),
                          engine=src.get("engine"),    # "core" (libbpf CO-RE, default) or "bcc" (header-compiled fallback)
                          btf=a.kernel_btf,            # kernels without their own BTF: a file from the server
                          canary_s=float(src.get("canary_s", 60)), canary_dir=cfg.data_dir,   # 0.6: collector self-test (0 = off)
                          # 0.7.0: data on connected sockets, one record per (process, edge, peer) per interval (0 = off)
                          sockio_ms=int(src["sockio_interval_ms"]) if src.get("sockio_interval_ms") is not None else None)
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
    sys.exit(a.exit_code)


if __name__ == "__main__":
    main()
