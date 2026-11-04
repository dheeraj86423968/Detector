"""Deterministic detection layers (run on every window before the learned detectors are consulted).

Layer 1 - executable novelty. A process alerts when the program it runs never ran during the baseline (training +
validation days) and has not been approved since. This is the executable-allowlist baseline of Guerra et al.
("How Benchmarks and Evaluation Protocols Shape Conclusions in Provenance-Based Intrusion Detection", NDSS 2027),
which matched or beat the learned PIDS they re-evaluated under validation-only protocols. It is deterministic (no
run-to-run variance), explainable ("/tmp/x never ran here before") and blind to attacks that only use programs the
host already runs - which is what layer 2 is for.

Layer 2 - information-flow tags with benign-calibrated alarms, after Morse (tag propagation with attenuation and
decay) and CAPTAIN (Wang et al., NDSS 2025: the tag initialisation, propagation and alarm thresholds are adapted to
benign data only). Every node carries integrity tags in [0, 1] (1 = trusted) and a confidentiality tag in [0, 1]
(1 = carries sensitive data), propagated along the data-flow edges of the provenance stream in time order:

  netflow  integrity 1 if the remote address is local or was contacted during the baseline, else 0
  file     integrity 1 (pre-existing content) lowered by every writer; confidentiality 1 for credential stores
  process  code integrity  = integrity of the executed file (inherited on fork without exec)
           data integrity  = min over the data it consumed (+ attenuation per file hop), recovering with a half-life
           confidentiality = max over the data it read

  alarm                    fires when                                                            flags
  untrusted_exec           a file with untrusted content is executed                             process, file
  tainted_spawn            a process holding untrusted data starts a program                     process
  tainted_modify           a process with untrusted code/data writes a file that existed in the baseline  process, file
  exfiltration             a process that read sensitive data sends to an untrusted address      process, netflow
  untrusted_code_network   a program loaded from an untrusted file talks to an untrusted address process, netflow

Benign calibration (CAPTAIN's adaptive alarm thresholds, in a simple closed form): the engine is replayed over the
baseline days; every (alarm, key) that fires there - key = the program (and parent program / target directory) -
gets its own threshold just below the lowest tag value it reached on benign data, so a benign routine stays quiet
while the same alarm with a key never seen in the baseline, or a strictly more untrusted value, still fires. Nothing
here uses attack data; the parameters below were fixed before any evaluation (docs/DETECTION_LAYERS.md).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field

import numpy as np

from .schema import EDGE_TYPE_ID, Registry
from .windows import Window

EXECUTE, CLONE, READ, WRITE = (EDGE_TYPE_ID[k] for k in ("EXECUTE", "CLONE", "READ", "WRITE"))
RECV = {EDGE_TYPE_ID["RECVFROM"], EDGE_TYPE_ID["RECVMSG"]}
SEND = {EDGE_TYPE_ID["SENDTO"], EDGE_TYPE_ID["SENDMSG"], EDGE_TYPE_ID["CONNECT"]}

RULES = {
    "novel_executable": "runs a program that never ran during the baseline",
    "untrusted_exec": "executes a file whose content came from an untrusted source",
    "tainted_spawn": "a process holding untrusted data starts a program",
    "tainted_modify": "a process with untrusted code or data modifies a file that existed in the baseline",
    "exfiltration": "a process that read sensitive data sends to an untrusted address",
    "untrusted_code_network": "a program loaded from an untrusted file communicates with an untrusted address",
}

# credential / secret stores (initial confidentiality 1). Deliberately short: a broad list taints every process.
SENSITIVE = re.compile(r"(^/etc/(shadow|gshadow|sudoers|master\.passwd|spwd\.db)$|^/etc/sudoers\.d/|/\.ssh/|"
                       r"\.(bash|zsh|sh)_history$|/\.gnupg/|/\.aws/credentials$|/\.netrc$|^/etc/ssl/private/|"
                       r"/(logins\.json|key[34]\.db|cookies\.sqlite|Login Data)$)")
UNKNOWN_PROGRAM = {"None", "", "null"}
LOCAL_ADDR = {"", "NA", "None", "null", "localhost", "0.0.0.0", "::", "::1", "*"}


# ------------------------------------------------------------------------------------------------- label helpers
def executable(label: str) -> str:
    """The program of a process label 'subject <exe> <cmdline>': the exe path, or the first command-line token when
    the collector recorded no path (DARPA CADETS records only the process name)."""
    parts = label.split(" ", 2)
    p = parts[1] if len(parts) > 1 else "None"
    if p in ("None", "", "null"):
        rest = parts[2].split() if len(parts) > 2 else []
        p = rest[0] if rest else "None"
    return p


def file_path(label: str) -> str:
    return label[5:] if label.startswith("file ") else label


def remote_ip(label: str) -> str:
    parts = label.split(" ")
    return parts[1] if len(parts) > 1 else "None"


def is_local(ip: str) -> bool:
    if ip in LOCAL_ADDR:
        return True
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a.is_unspecified or a.is_link_local
    except ValueError:
        return True          # not an address (unix socket names, 'NA') -> not a remote host


def dir_key(path: str, depth: int = 2) -> str:
    """Directory part of a path, truncated to `depth` components ('/home/admin/.ssh/x' -> '/home/admin')."""
    if not path.startswith("/"):
        return path if path in ("None", "") else "relative"
    return "/" + "/".join(path.split("/")[1:-1][:depth])


# ------------------------------------------------------------------------------------------------- results
@dataclass
class Hit:
    layer: str                 # "novelty" | "rules"
    rule: str
    key: str
    value: float               # tag value that crossed the threshold (0 = fully untrusted); 0 for novelty
    nodes: tuple               # dense node ids flagged by this hit (first = the acting process)
    ts: int
    detail: str


# ------------------------------------------------------------------------------------------------- layer 1
class NoveltyLayer:
    def __init__(self, known: set[str], approved: set[str] | None = None):
        self.known = set(known)
        self.approved = set(approved or ())
        self._checked: set[int] = set()

    def reset(self):
        self._checked = set()

    def process(self, w: Window, reg: Registry, ids: np.ndarray) -> list[Hit]:
        out = []
        ents = reg.entities
        first_t = {}
        for n in ids.tolist():
            if n in self._checked:
                continue
            e = ents[n]
            if e.ntype != "subject":
                continue
            self._checked.add(n)
            exe = executable(e.label)
            if exe in self.known or exe in self.approved or exe in UNKNOWN_PROGRAM:
                continue   # no program recorded (collector missed the exec) is missing data, not a new program
            if not first_t:
                for s, d, t in zip(w.src.tolist(), w.dst.tolist(), w.t.tolist()):
                    first_t.setdefault(s, t); first_t.setdefault(d, t)
            out.append(Hit("novelty", "novel_executable", exe, 0.0, (n,), int(first_t.get(n, w.start_ns)),
                           f"runs {exe}, which never ran during the baseline"))
        return out

    @staticmethod
    def fit(windows_by_day, reg: Registry) -> set[str]:
        ents = reg.entities
        known = set()
        seen = set()
        for ws in windows_by_day:
            for w in ws:
                for n in np.unique(np.concatenate([w.src, w.dst])).tolist():
                    if n not in seen:
                        seen.add(n)
                        if ents[n].ntype == "subject":
                            known.add(executable(ents[n].label))
        return known


# ------------------------------------------------------------------------------------------------- layer 2
@dataclass
class TagParams:
    untrusted: float = 0.5          # a tag below this is untrusted (alarm default threshold)
    read_attenuation: float = 0.2   # integrity regained per file hop (file -> reader); limits dependency explosion
    conf_attenuation: float = 0.25  # confidentiality lost per write hop
    sensitive: float = 0.5          # confidentiality at or above this is sensitive
    half_life_s: float = 3600.0     # data integrity of a process recovers towards 1 with this half-life
    benign_margin: float = 0.05     # per-key threshold = lowest benign value - margin


class _Tag:
    __slots__ = ("code", "data", "t", "conf", "exec", "origin")

    def __init__(self, itg: float, conf: float, origin: int):
        self.code = 1.0       # processes: code integrity
        self.data = itg       # processes: data integrity; files / netflows: content / endpoint integrity
        self.t = 0            # time of the last lowering of `data` (decay reference)
        self.conf = conf
        self.exec = False     # process image has executed a file (live collectors: one node per image)
        self.origin = origin  # node that introduced the lowest integrity (for explanations)


class TagEngine:
    def __init__(self, params: TagParams, trusted_ips: set[str], thresholds: dict[str, dict[str, float]] | None,
                 n_preexisting: int, fit: bool = False):
        self.p = params
        self.trusted = set(trusted_ips)
        # private addresses are re-assigned (docker networks, DHCP): a private address in the /24 of a trusted private
        # address is trusted too. Public addresses must have been seen themselves.
        self.trusted_private24 = set()
        for ip in self.trusted:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.version == 4 and a.is_private and not a.is_loopback:
                self.trusted_private24.add(ipaddress.ip_network(f"{ip}/24", strict=False))
        self.allowed_nets: list = []        # console allow list: addresses / networks treated as trusted
        self.thr = thresholds or {}
        self.n_pre = int(n_preexisting)
        self.first_day: dict[int, int] | None = None   # fit mode: node -> index of the baseline day it was first seen
        self.cur_day = 0
        self.fit_mode = fit
        self.benign_min: dict[tuple[str, str], float] = {}       # fit mode: lowest value per (rule, key)
        self.benign_count: dict[str, int] = defaultdict(int)
        self.reset()

    def reset(self):
        self.tags: dict[int, _Tag] = {}
        self.parent_exe: dict[int, str] = {}
        self._fired: set[tuple[str, int]] = set()
        self._lbl: dict[int, str] = {}

    # ---- helpers
    def _label(self, reg: Registry, n: int) -> str:
        s = self._lbl.get(n)
        if s is None:
            e = reg.entities[n]
            s = executable(e.label) if e.ntype == "subject" else (file_path(e.label) if e.ntype == "file" else remote_ip(e.label))
            self._lbl[n] = s
        return s

    def _tag(self, reg: Registry, n: int) -> _Tag:
        t = self.tags.get(n)
        if t is None:
            e = reg.entities[n]
            if e.ntype == "netflow":
                ip = remote_ip(e.label)
                t = _Tag(1.0 if (is_local(ip) or ip in self.trusted or self._allowed(ip) or self._private_trusted(ip)) else 0.0, 0.0, n)
                self.__dict__.setdefault("_net_nodes", set()).add(n)
            elif e.ntype == "file":
                t = _Tag(1.0, 1.0 if SENSITIVE.search(file_path(e.label)) else 0.0, n)
            else:
                t = _Tag(1.0, 0.0, n)
            self.tags[n] = t
        return t

    def _data(self, t: _Tag, now: int) -> float:
        if t.data >= 1.0 or self.p.half_life_s <= 0:
            return t.data
        dt = max(0.0, (now - t.t) / 1e9)
        return 1.0 - (1.0 - t.data) * 0.5 ** (dt / self.p.half_life_s)

    def _lower(self, t: _Tag, v: float, origin: int, now: int):
        cur = self._data(t, now)
        if v < cur:
            t.data, t.t, t.origin = v, now, origin

    def set_allowed_addresses(self, items) -> None:
        import ipaddress
        nets = []
        for x in items or ():
            try:
                nets.append(ipaddress.ip_network(str(x).strip(), strict=False))
            except ValueError:
                continue
        if nets != self.allowed_nets:
            self.allowed_nets = nets
            for n in getattr(self, "_net_nodes", ()):        # re-evaluate network endpoints seen so far
                self.tags.pop(n, None)

    def _private_trusted(self, ip: str) -> bool:
        if not self.trusted_private24 or not ip:
            return False
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return a.version == 4 and a.is_private and any(a in n for n in self.trusted_private24)

    def _allowed(self, ip: str) -> bool:
        if not self.allowed_nets or not ip:
            return False
        import ipaddress
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.allowed_nets)

    def _check(self, out: list, rule: str, key: str, value: float, nodes: tuple, ts: int, detail: str):
        if self.fit_mode:
            if value < self.p.untrusted:
                k = (rule, key)
                if value < self.benign_min.get(k, 2.0):
                    self.benign_min[k] = value
                self.benign_count[rule] += 1
            return
        thr = self.thr.get(rule, {}).get(key, self.p.untrusted)
        if value < thr and (rule, nodes[0]) not in self._fired:
            self._fired.add((rule, nodes[0]))
            out.append(Hit("rules", rule, key, round(float(value), 3), nodes, ts, detail))

    def _why(self, reg: Registry, t: _Tag) -> str:
        o = t.origin
        e = reg.entities[o]
        return f"{e.ntype} {self._label(reg, o)}"

    # ---- stream
    def process(self, w: Window, reg: Registry) -> list[Hit]:
        out: list[Hit] = []
        order = np.argsort(w.t, kind="stable")
        src, dst, et, ts = w.src[order].tolist(), w.dst[order].tolist(), w.etype[order].tolist(), w.t[order].tolist()
        p, U = self.p, self.p.untrusted
        for s, d, e, now in zip(src, dst, et, ts):
            if e in RECV:                                   # netflow -> process
                n, q = self._tag(reg, s), self._tag(reg, d)
                self._lower(q, n.data, s, now)
                if q.code < U and n.data < U:
                    self._check(out, "untrusted_code_network", self._label(reg, d), max(q.code, n.data), (d, s), now,
                                f"{self._label(reg, d)} (loaded from untrusted {self._why(reg, q)}) receives from {self._label(reg, s)}")
            elif e == READ:                                 # file -> process
                f, q = self._tag(reg, s), self._tag(reg, d)
                if f.data < 1.0:
                    self._lower(q, min(1.0, f.data + p.read_attenuation), f.origin, now)
                if f.conf > q.conf:
                    q.conf = f.conf
            elif e == EXECUTE:                              # file -> process
                f, q = self._tag(reg, s), self._tag(reg, d)
                prog = self._label(reg, s)
                prog = prog if prog not in ("None", "") else self._label(reg, d)
                if f.data < U:
                    self._check(out, "untrusted_exec", prog, f.data, (d, s), now,
                                f"executes {prog}, whose content came from untrusted {self._why(reg, f)}")
                q.code, q.exec = f.data, True
                if f.data < 1.0:
                    q.origin = f.origin
                v = self._data(q, now)
                if v < U:
                    par = self.parent_exe.get(d, self._label(reg, d))
                    self._check(out, "tainted_spawn", f"{par} -> {prog}", v, (d,), now,
                                f"{par} holding untrusted data from {self._why(reg, q)} starts {prog}")
            elif e == CLONE:                                # parent process -> child process
                a, c = self._tag(reg, s), self._tag(reg, d)
                self.parent_exe[d] = self._label(reg, s)
                inherit = min(a.code, self._data(a, now))
                self._lower(c, inherit, a.origin, now)
                if a.conf > c.conf:
                    c.conf = a.conf
                if not c.exec:
                    c.code = min(c.code, a.code)
                else:                                       # live collectors: exec image first, then CLONE from the old image
                    v = self._data(c, now)
                    if v < U:
                        par, prog = self._label(reg, s), self._label(reg, d)
                        self._check(out, "tainted_spawn", f"{par} -> {prog}", v, (d,), now,
                                    f"{par} holding untrusted data from {self._why(reg, c)} starts {prog}")
            elif e == WRITE:                                # process -> file
                q, f = self._tag(reg, s), self._tag(reg, d)
                v = min(q.code, self._data(q, now))
                path = self._label(reg, d)
                if v < U and path.startswith("/") and (d < self.n_pre if self.first_day is None else self.first_day.get(d, self.cur_day) < self.cur_day):
                    self._check(out, "tainted_modify", f"{self._label(reg, s)} @ {dir_key(path)}", v, (s, d), now,
                                f"{self._label(reg, s)} with untrusted input from {self._why(reg, q)} modifies {path}")
                if v < f.data:
                    f.data, f.origin = v, (q.origin if v < 1.0 else f.origin)
                c = q.conf - p.conf_attenuation
                if c > f.conf:
                    f.conf = c
            elif e in SEND:                                 # process -> netflow
                q, n = self._tag(reg, s), self._tag(reg, d)
                if n.data < U:
                    prog = self._label(reg, s)
                    if q.conf >= p.sensitive:
                        self._check(out, "exfiltration", prog, max(1.0 - q.conf, n.data), (s, d), now,
                                    f"{prog}, which read sensitive data, sends to untrusted {self._label(reg, d)}")
                    if q.code < U:
                        self._check(out, "untrusted_code_network", prog, max(q.code, n.data), (s, d), now,
                                    f"{prog} (loaded from untrusted {self._why(reg, q)}) sends to untrusted {self._label(reg, d)}")
        return out

    # ---- calibration
    def thresholds(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = defaultdict(dict)
        for (rule, key), v in self.benign_min.items():
            out[rule][key] = round(float(v) - self.p.benign_margin, 4)
        return dict(out)


# ------------------------------------------------------------------------------------------------- both layers
# rules prone to dependency explosion (Morse / CAPTAIN): on their own they flag every long-lived process that ever
# received untrusted data, so their hits are evidence - the node alerts only when the learned score agrees.
# Revision after the first DARPA E3 evaluation (docs/DETECTION_LAYERS.md, "pre-registered vs revised").
EVIDENCE_RULES = ("tainted_modify", "tainted_spawn")


@dataclass
class LayerConfig:
    novelty: bool = True
    rules: bool = True
    tags: TagParams = field(default_factory=TagParams)
    evidence_rules: tuple = EVIDENCE_RULES


class DeterministicLayers:
    """Layers 1 + 2 as one stateful object used by the runtime (one call per window, in stream order)."""

    FILE = "layers.json"

    def __init__(self, spec: dict, n_preexisting: int, approved: set[str] | None = None):
        self.spec = spec
        cfg = spec.get("config", {})
        self.novelty = NoveltyLayer(set(spec["known_executables"]), approved) if cfg.get("novelty", True) else None
        self.tags = TagEngine(TagParams(**cfg.get("tags", {})), set(spec.get("trusted_ips", [])), spec.get("thresholds", {}),
                              n_preexisting) if cfg.get("rules", True) else None

    @classmethod
    def load(cls, bundle_dir: str, n_preexisting: int, approved: set[str] | None = None) -> "DeterministicLayers | None":
        p = os.path.join(bundle_dir, cls.FILE)
        if not os.path.exists(p):
            return None
        return cls(json.load(open(p)), n_preexisting, approved)

    def set_approved(self, approved) -> None:
        if self.novelty is not None:
            self.novelty.approved = set(approved or ())

    def set_allowlist(self, addresses=(), suppressed=()) -> None:
        """Console allow list: trusted network addresses (layer 2) and specific detections (rule, key) not to raise."""
        if self.tags is not None:
            self.tags.set_allowed_addresses(addresses)
        self.suppressed = {(str(r), str(k)) for r, k in (suppressed or ())}

    def reset(self):
        if self.novelty is not None:
            self.novelty.reset()
        if self.tags is not None:
            self.tags.reset()

    def process(self, w: Window, reg: Registry, ids: np.ndarray) -> list[Hit]:
        hits = []
        if self.novelty is not None:
            hits += self.novelty.process(w, reg, ids)
        if self.tags is not None:
            hits += self.tags.process(w, reg)
        sup = getattr(self, "suppressed", None)
        if sup:
            hits = [h for h in hits if (h.rule, h.key) not in sup]
        return hits


def fit_layers(store, days: list[str], reg: Registry, n_preexisting: int, cfg: LayerConfig = LayerConfig(), log=print) -> dict:
    """Fit layers 1 and 2 on benign days (in order): known executables, trusted remote addresses, per-key alarm
    thresholds. Returns the layers.json document.

    The alarm thresholds must be learned under the novelty a deployment will see, not under the baseline's own
    hindsight (every baseline address is trusted by construction otherwise, and no benign alarm is ever observed).
    The calibration replay is therefore leave-one-day-out: an address is trusted on a day only if it also occurs
    on another baseline day, and a file counts as pre-existing only if it was seen on an earlier day."""
    known = NoveltyLayer.fit((store.windows(d) for d in days), reg)
    ip_days: dict[str, set[int]] = defaultdict(set)
    first_day: dict[int, int] = {}
    for k, d in enumerate(days):
        seen = set()
        for w in store.windows(d):
            seen.update(np.unique(np.concatenate([w.src, w.dst])).tolist())
        for n in seen:
            first_day.setdefault(n, k)
            e = reg.entities[n]
            if e.ntype == "netflow":
                ip = remote_ip(e.label)
                if not is_local(ip):
                    ip_days[ip].add(k)
    ips = set(ip_days)
    recurring = {ip for ip, ds in ip_days.items() if len(ds) >= 2}
    eng = TagEngine(cfg.tags, recurring, None, n_preexisting, fit=True)
    eng.first_day = first_day
    for k, d in enumerate(days):
        eng.cur_day = k
        for w in store.windows(d):
            eng.process(w, reg)
    thr = eng.thresholds()
    log(f"layers: {len(known)} known executables, {len(ips)} baseline remote addresses ({len(recurring)} recurring), "
        f"benign alarm keys " + (", ".join(f"{r}={len(v)}" for r, v in sorted(thr.items())) or "none"))
    return {"version": 1, "config": {"novelty": cfg.novelty, "rules": cfg.rules, "tags": asdict(cfg.tags), "evidence_rules": list(cfg.evidence_rules)},
            "fit_days": list(days), "known_executables": sorted(known), "trusted_ips": sorted(ips), "thresholds": thr,
            "benign_alarm_events": dict(eng.benign_count)}
