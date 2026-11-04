"""Windows live collector: ETW kernel events -> normalised provenance events.

Maps the Windows kernel ETW providers (Microsoft-Windows-Kernel-Process, -File/FileIO, -Network / TcpIp) to the
same Entity/Event stream as the Linux collectors, so the server, detectors and console are identical across
platforms. Process identity, file nodes and socket nodes follow the shared schema.

The ETW consumer backend (pywintrace / the `etw` package, or an `logman` ETL session) is imported lazily and only
on Windows; `decode_event` takes a provider-agnostic dict and is pure Python, so the event mapping is unit-tested
on any OS (tests/unit/test_windows_etw.py). Deploying on Windows: install the agent with pywintrace and run an
elevated session subscribed to the three kernel providers below.
"""
from __future__ import annotations

import time
import uuid as uuidlib
from typing import Callable, Iterator

from pdp_engine.schema import Entity, Event

from .auditd import ProcessTable

# normalised ETW event kinds the decoder understands (the backend maps raw provider events to these dicts)
#   {"kind": "process_start", "pid", "ppid", "image", "cmdline"}
#   {"kind": "process_stop",  "pid"}
#   {"kind": "file", "pid", "path", "access": "read"|"write"|"open"}
#   {"kind": "net",  "pid", "raddr", "rport", "direction": "out"|"in"}


class EtwNormaliser:
    def __init__(self, host_id: str | None = None):
        self.host = host_id or uuidlib.uuid4().hex[:12]
        self.procs = ProcessTable(self.host)
        self._seq = 0

    def _eid(self) -> str:
        self._seq += 1
        return f"{self.host}:{self._seq:010d}"

    def decode_event(self, ev: dict, ts_ns: int | None = None) -> Iterator[tuple[list[Entity], Event]]:
        ts = ts_ns if ts_ns is not None else time.time_ns()
        out: list[tuple[Entity, str, Entity]] = []
        kind = ev.get("kind")
        if kind == "process_start":
            pid, ppid = int(ev["pid"]), int(ev.get("ppid", 0))
            image = ev.get("image") or "None"
            cmd = ev.get("cmdline") or image
            child = self.procs.get(pid, image, cmd, new_image=True)
            if ppid:
                parent = self.procs.get(ppid, None)
                out.append((parent, "CLONE", child))
            out.append((Entity.file(f"file:{image}", image), "EXECUTE", child))
        elif kind == "process_stop":
            self.procs.forget(int(ev["pid"])); return
        elif kind == "file":
            path = ev.get("path")
            if not path:
                return
            p = self.procs.get(int(ev["pid"]), None)
            f = Entity.file(f"file:{path}", path)
            access = ev.get("access", "open")
            out.append((f, "OPEN", p))
            if access in ("read", "open"):
                out.append((f, "READ", p))
            if access in ("write",):
                out.append((p, "WRITE", f))
        elif kind == "net":
            raddr, rport = ev.get("raddr"), ev.get("rport")
            if not raddr:
                return
            p = self.procs.get(int(ev["pid"]), None)
            n = Entity.socket(f"net:{raddr}:{rport}", raddr, rport)
            if ev.get("direction") == "in":
                out.append((n, "RECVFROM", p))
            else:
                out.append((p, "CONNECT", n))
        for src, op, dst in out:
            yield [src, dst], Event(ts, src.uuid, op, dst.uuid, self._eid())


# ETW provider GUIDs / names the Windows backend subscribes to (documented for the deployment)
PROVIDERS = {
    "Microsoft-Windows-Kernel-Process": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
    "Microsoft-Windows-Kernel-File": "{EDD08927-9CC4-4E65-B970-C2560FB5C289}",
    "Microsoft-Windows-Kernel-Network": "{7DD42A49-5329-4832-8DFD-43D979153A88}",
}


class EtwLive:
    """Consume a live ETW session on Windows. Yields lists of (entities, Event) like the other collectors."""
    chronological = True   # wall-clock timestamps: a calendar day is complete once it has ended

    def __init__(self, batch: int = 2000, providers: dict | None = None):
        self.batch = batch
        self.providers = providers or PROVIDERS
        self.norm = EtwNormaliser()
        self._buf: list = []

    def _map_raw(self, raw: dict) -> dict | None:
        """Translate a pywintrace event dict to the normaliser's provider-agnostic schema."""
        name = raw.get("Task Name") or raw.get("EventName") or ""
        d = raw
        if name in ("ProcessStart", "PROCESSSTART", "Process-Start"):
            return {"kind": "process_start", "pid": d.get("ProcessID") or d.get("ProcessId"),
                    "ppid": d.get("ParentProcessID") or d.get("ParentProcessId"),
                    "image": d.get("ImageName") or d.get("ImageFileName"), "cmdline": d.get("CommandLine")}
        if name in ("ProcessStop", "Process-Stop"):
            return {"kind": "process_stop", "pid": d.get("ProcessID") or d.get("ProcessId")}
        if name in ("Create", "Read", "Write", "NameCreate"):
            access = {"Read": "read", "Write": "write"}.get(name, "open")
            return {"kind": "file", "pid": d.get("ProcessID") or d.get("IssuingThreadId"),
                    "path": d.get("FileName") or d.get("FilePath"), "access": access}
        if name in ("connect", "Connect", "TcpConnect", "KERNEL_NETWORK_TASK_TCPIP"):
            return {"kind": "net", "pid": d.get("ProcessID"), "raddr": d.get("daddr") or d.get("DestinationAddress"),
                    "rport": d.get("dport") or d.get("DestinationPort"), "direction": "out"}
        return None

    def batches(self, stop: Callable[[], bool]) -> Iterator[list]:
        from etw import ETW, ProviderInfo, TraceProperties  # lazy: Windows + pywintrace only

        def on_event(evt):
            raw = evt[1] if isinstance(evt, tuple) else evt
            m = self._map_raw(raw)
            if m:
                self._buf.extend(self.norm.decode_event(m))

        providers = [ProviderInfo(n, g) for n, g in self.providers.items()]
        job = ETW(providers=providers, event_callback=on_event)
        job.start()
        last = time.time()
        try:
            while not stop():
                if len(self._buf) >= self.batch or (self._buf and time.time() - last > 2):
                    yield self._buf; self._buf = []; last = time.time()
                else:
                    yield []
                    time.sleep(0.2)
        finally:
            job.stop()
