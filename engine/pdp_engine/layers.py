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
    "novel_executable_repeat": "another run of a new program that already alerted today (evidence)",
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
# Windows credential stores (full_paths, matched on canonical_path): SAM / SECURITY hives, the domain database, DPAPI
# master keys, the credential manager and vault, browser password stores, password-manager databases.
SENSITIVE_WIN = re.compile(r"(^/windows/system32/config/(sam|security)$|/ntds\.dit$|/appdata/(roaming|local)/microsoft/"
                           r"(credentials|protect|vault)/|/login data$|/logins\.json$|/key[34]\.db$|\.kdbx$)")
UNKNOWN_PROGRAM = {"None", "", "null"}
LOCAL_ADDR = {"", "NA", "None", "null", "localhost", "0.0.0.0", "::", "::1", "*"}


# ------------------------------------------------------------------------------------------------- label helpers
_WIN_PATH = re.compile(r"^(?:/device/harddiskvolume\d+|/\?\?/[a-z]:|//\?/[a-z]:|[a-z]:)/", re.I)
_HAS_EXT = re.compile(r"\.[A-Za-z0-9]{1,4}$")


def executable(label: str, full_paths: bool = False) -> str:
    """The program of a process label 'subject <exe> <cmdline>': the exe path, or the first command-line token when
    the collector recorded no path (DARPA CADETS records only the process name).

    full_paths (0.4): the label separates path and command line by a space, so a Windows path with spaces
    ('C:/Program Files (x86)/Google/Update/GoogleUpdate.exe') was cut at the first space and every program under
    Program Files became the program '.../Program'. A Windows-style path whose last component has no extension is
    continued with the following words until it ends in a file name with an extension (at most 8 words). Other
    paths (Linux programs rarely have an extension) are unchanged."""
    parts = label.split(" ", 2)
    p = parts[1] if len(parts) > 1 else "None"
    if p in ("None", "", "null"):
        rest = parts[2].split() if len(parts) > 2 else []
        p = rest[0] if rest else "None"
    elif full_paths and len(parts) > 2 and _WIN_PATH.match(p) and not _HAS_EXT.search(p.rsplit("/", 1)[-1]):
        words = parts[2].split(" ")
        for k, tok in enumerate(words[:8]):
            if not tok or tok[0] in "\"'-":
                break
            cand = p + " " + " ".join(words[: k + 1])
            if _HAS_EXT.search(cand.rsplit("/", 1)[-1]):
                return cand
    return p


# Program identity for layer 1 (normalize_programs). The same program is recorded under different spellings: Windows
# paths in NT-namespace or drive form and in any letter case, inside per-install random directories (GUIDs, long hex
# ids) or per-version directories, or with no path at all when the collector missed the image (only a name). Novelty
# compares programs by this key, so a program counts as new only when it really is a new program.
_NT_PREFIX = re.compile(r"^(?:/device/harddiskvolume\d+|/\?\?/[a-z]:|//\?/[a-z]:|/[a-z]:|[a-z]:)(?=/)")
_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?")
_HEXID = re.compile(r"(?<![0-9a-z])[0-9a-f]{16,}(?![0-9a-z])")
_VERSION_DIR = re.compile(r"^v?\d+(?:[._]\d+)+$")
_EXE_SUFFIX = re.compile(r"\.(exe|com)$")


def program_key(exe: str) -> str:
    """Canonical program identity: '/Device/HarddiskVolume1/Windows/System32/PING.EXE' and 'C:\\Windows\\system32\\ping.exe'
    -> '/windows/system32/ping.exe'; GUID / long hex directory names -> '{id}', version directories -> '{v}'."""
    p = exe.replace("\\", "/").casefold()
    p = p.replace("%systemroot%", "/windows").replace("%windir%", "/windows")
    p = _NT_PREFIX.sub("", p)
    if "/" not in p:
        return p
    p = _HEXID.sub("{id}", _GUID.sub("{id}", p))
    parts = p.split("/")
    return "/".join([("{v}" if _VERSION_DIR.match(s) else s) for s in parts[:-1]] + parts[-1:])


def program_name(key: str) -> str:
    """Bare program name of a key, for matching a process recorded without a path ('taskkill' ~ '.../taskkill.exe')."""
    return _EXE_SUFFIX.sub("", key.rsplit("/", 1)[-1])


def file_path(label: str) -> str:
    return label[5:] if label.startswith("file ") else label


def remote_ip(label: str) -> str:
    parts = label.split(" ")
    return parts[1] if len(parts) > 1 else "None"


def is_local(ip: str, multicast: bool = False) -> bool:
    """Not a remote host: loopback, unspecified, link-local, non-addresses; with multicast=True (0.4) also multicast
    and limited broadcast - group traffic of the local network (IPv6 neighbour discovery, mDNS, LLMNR, SSDP), which
    0.3 treated as an untrusted remote source and so tainted every process that receives it."""
    if ip in LOCAL_ADDR:
        return True
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a.is_unspecified or a.is_link_local or (
            multicast and (a.is_multicast or (a.version == 4 and int(a) == 0xFFFFFFFF)))
    except ValueError:
        return True          # not an address (unix socket names, 'NA') -> not a remote host


def remote_port(label: str) -> str:
    parts = label.split(" ")
    return parts[2] if len(parts) > 2 else "None"


_PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def is_private(ip: str) -> bool:
    """RFC 1918 / IPv6 unique-local only (Python's is_private also covers documentation and other reserved ranges)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in _PRIVATE_NETS)


def canonical_path(path: str) -> str:
    """Windows paths in one spelling ('/Device/HarddiskVolume1/Users/X/f', 'C:\\Users\\x\\f' -> '/users/x/f');
    other paths unchanged."""
    q = path.replace("\\", "/")
    if _WIN_PATH.match(q) or q[:12].casefold().startswith("%systemroot%"):
        q = q.casefold().replace("%systemroot%", "/windows")
        return _NT_PREFIX.sub("", q)
    return path


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
    def __init__(self, known: set[str], approved: set[str] | None = None, normalize: bool = False, instances: int = 0,
                 full_paths: bool = False):
        """normalize: compare programs by program_key (else by the raw path). instances > 0: only the first
        `instances` processes of a new program per day alert; later ones are 'novel_executable_repeat' evidence (one
        new tool run in a loop is one finding, not hundreds)."""
        self.known = set(known)
        self.normalize = bool(normalize)
        self.instances = int(instances or 0)
        self.full_paths = bool(full_paths)
        self.approved = set(approved or ())
        self._checked: set[int] = set()
        self._count: dict[tuple[str, int], int] = defaultdict(int)
        if self.normalize:
            self.known_keys = {program_key(k) for k in self.known if k not in UNKNOWN_PROGRAM}
            self.known_names = {program_name(k) for k in self.known_keys}

    @property
    def approved(self) -> set[str]:
        return self._approved

    @approved.setter
    def approved(self, v) -> None:
        self._approved = set(v or ())
        self._approved_keys = {program_key(k) for k in self._approved}

    def reset(self):
        self._checked = set()
        self._count = defaultdict(int)

    def remap(self, old2new) -> None:
        self._checked = {old2new[n] for n in self._checked if old2new[n] >= 0}

    def is_known(self, exe: str) -> bool:
        if exe in self.known or exe in self._approved or exe in UNKNOWN_PROGRAM:
            return True   # no program recorded (collector missed the exec) is missing data, not a new program
        if not self.normalize:
            return False
        k = program_key(exe)
        if k in self.known_keys or k in self._approved_keys:
            return True
        return "/" not in k and program_name(k) in self.known_names   # recorded without a path: match by name

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
            exe = executable(e.label, self.full_paths)
            if self.is_known(exe):
                continue
            if not first_t:
                for s, d, t in zip(w.src.tolist(), w.dst.tolist(), w.t.tolist()):
                    first_t.setdefault(s, t); first_t.setdefault(d, t)
            ts = int(first_t.get(n, w.start_ns))
            rule = "novel_executable"
            if self.instances:
                ck = (program_key(exe) if self.normalize else exe, ts // 86_400_000_000_000)
                self._count[ck] += 1
                if self._count[ck] > self.instances:
                    rule = "novel_executable_repeat"
            out.append(Hit("novelty", rule, exe, 0.0, (n,), ts, f"runs {exe}, which never ran during the baseline"
                           + ("" if rule == "novel_executable" else f" (repeat run #{self._count[ck]} today)")))
        return out

    @staticmethod
    def fit(windows_by_day, reg: Registry, full_paths: bool = False) -> set[str]:
        ents = reg.entities
        known = set()
        seen = set()
        for ws in windows_by_day:
            for w in ws:
                for n in np.unique(np.concatenate([w.src, w.dst])).tolist():
                    if n not in seen:
                        seen.add(n)
                        if ents[n].ntype == "subject":
                            known.add(executable(ents[n].label, full_paths))
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
                 n_preexisting: int, fit: bool = False, private_services: set[str] | None = None, full_paths: bool = False,
                 image_exec: bool = False, local_multicast: bool = False):
        """full_paths: Windows path handling (programs with spaces, canonical directories, Windows credential stores).
        image_exec: a process whose program file was written with untrusted content in the stream counts as executing
        it, for collectors that record no EXECUTE event (Windows). local_multicast: multicast / broadcast addresses
        are local (see is_local)."""
        self.p = params
        self.local_multicast = bool(local_multicast)
        self.full_paths = bool(full_paths)
        self.image_exec = bool(image_exec)
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
        # "<program>|<port>" a program sent to on private addresses during the baseline: a new private address on the
        # same port (containers get new addresses on every redeploy, new docker networks) is that service again
        self.private_services = set(private_services or ())
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
        self._untrusted_files: dict[str, int] = {}      # image_exec: canonical path -> file node with untrusted content
        self._fired: set[tuple[str, int]] = set()
        self._lbl: dict[int, str] = {}

    # ---- helpers
    def _label(self, reg: Registry, n: int) -> str:
        s = self._lbl.get(n)
        if s is None:
            e = reg.entities[n]
            s = executable(e.label, self.full_paths) if e.ntype == "subject" else (file_path(e.label) if e.ntype == "file" else remote_ip(e.label))
            self._lbl[n] = s
        return s

    def _tag(self, reg: Registry, n: int) -> _Tag:
        t = self.tags.get(n)
        if t is None:
            e = reg.entities[n]
            if e.ntype == "netflow":
                ip = remote_ip(e.label)
                t = _Tag(1.0 if (is_local(ip, self.local_multicast) or ip in self.trusted or self._allowed(ip) or self._private_trusted(ip)) else 0.0, 0.0, n)
                self.__dict__.setdefault("_net_nodes", set()).add(n)
            elif e.ntype == "file":
                fp_ = file_path(e.label)
                sens = SENSITIVE.search(fp_) or (self.full_paths and SENSITIVE_WIN.search(canonical_path(fp_)))
                t = _Tag(1.0, 1.0 if sens else 0.0, n)
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

    # ---- registry compaction
    def keep_nodes(self, now: int) -> set[int]:
        """Nodes whose state still matters: lowered integrity (until it has decayed back) and where it came from."""
        out = set()
        for n, t in self.tags.items():
            if t.code < 1.0 or self._data(t, now) < 0.999:
                out.add(n)
                if t.origin is not None and t.origin >= 0:
                    out.add(t.origin)
        out.update(self._untrusted_files.values())
        return out

    def remap(self, old2new) -> None:
        """Renumber per-node state after a registry compaction (old2new[i] = new id or -1)."""
        m = old2new
        tags = {}
        for n, t in self.tags.items():
            k = m[n]
            if k >= 0:
                if t.origin is not None and t.origin >= 0:
                    t.origin = m[t.origin] if m[t.origin] >= 0 else k
                tags[k] = t
        self.tags = tags
        self.parent_exe = {m[n]: v for n, v in self.parent_exe.items() if m[n] >= 0}
        self._lbl = {m[n]: v for n, v in self._lbl.items() if m[n] >= 0}
        self._fired = {(r, m[n]) for r, n in self._fired if m[n] >= 0}
        self._untrusted_files = {k: m[n] for k, n in self._untrusted_files.items() if m[n] >= 0}
        if "_net_nodes" in self.__dict__:
            self._net_nodes = {m[n] for n in self._net_nodes if m[n] >= 0}

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
                if self.image_exec and not c.exec and self._untrusted_files:
                    fid = self._untrusted_files.get(canonical_path(self._label(reg, d)))
                    if fid is not None:
                        f = self._tag(reg, fid)
                        prog = self._label(reg, d)
                        if f.data < U:
                            self._check(out, "untrusted_exec", prog, f.data, (d, fid), now,
                                        f"starts {prog}, whose content came from untrusted {self._why(reg, f)}")
                        c.code, c.exec = min(c.code, f.data), True
                        if f.data < 1.0:
                            c.origin = f.origin
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
                if v < U and path.startswith("/") and (reg.gid(d) < self.n_pre if self.first_day is None else self.first_day.get(d, self.cur_day) < self.cur_day):
                    self._check(out, "tainted_modify", f"{self._label(reg, s)} @ {dir_key(canonical_path(path) if self.full_paths else path)}", v, (s, d), now,
                                f"{self._label(reg, s)} with untrusted input from {self._why(reg, q)} modifies {path}")
                if v < f.data:
                    f.data, f.origin = v, (q.origin if v < 1.0 else f.origin)
                if self.image_exec and f.data < U and path not in ("None", ""):
                    self._untrusted_files[canonical_path(path)] = d
                c = q.conf - p.conf_attenuation
                if c > f.conf:
                    f.conf = c
            elif e in SEND:                                 # process -> netflow
                q, n = self._tag(reg, s), self._tag(reg, d)
                if n.data < U and self.private_services and reg.entities[d].ntype == "netflow":
                    lab = reg.entities[d].label
                    if is_private(remote_ip(lab)) and f"{self._label(reg, s)}|{remote_port(lab)}" in self.private_services:
                        continue                            # a known service of this program on a re-assigned address
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
ALWAYS_EVIDENCE = ("novel_executable_repeat",)      # by definition: the program's first runs already alerted


@dataclass
class LayerConfig:
    novelty: bool = True
    rules: bool = True
    tags: TagParams = field(default_factory=TagParams)
    evidence_rules: tuple = EVIDENCE_RULES
    # 0.4 (docs/DETECTION_LAYERS.md, "0.4"). Defaults for new fits; a layers.json fitted by 0.3 lacks the keys and
    # keeps the 0.3 behaviour until it is re-fitted (tools.add_layers), since keys and thresholds depend on them.
    normalize_programs: bool = True    # layer 1 compares programs by program_key
    novel_instances: int = 1           # > 0: per new program and day, only the first N processes alert
    full_paths: bool = True            # Windows path handling (programs with spaces, folders, credential stores)
    image_exec: bool = True            # a process started from an untrusted written file = untrusted exec
    local_multicast: bool = True       # multicast / broadcast addresses are local, not untrusted sources


class DeterministicLayers:
    """Layers 1 + 2 as one stateful object used by the runtime (one call per window, in stream order)."""

    FILE = "layers.json"

    def __init__(self, spec: dict, n_preexisting: int, approved: set[str] | None = None):
        self.spec = spec
        cfg = spec.get("config", {})
        self.novelty = (NoveltyLayer(set(spec["known_executables"]), approved, normalize=cfg.get("normalize_programs", False),
                                     instances=cfg.get("novel_instances", 0), full_paths=cfg.get("full_paths", False))
                        if cfg.get("novelty", True) else None)
        self.tags = (TagEngine(TagParams(**cfg.get("tags", {})), set(spec.get("trusted_ips", [])), spec.get("thresholds", {}),
                               n_preexisting, private_services=set(spec.get("private_services", [])),
                               full_paths=cfg.get("full_paths", False), image_exec=cfg.get("image_exec", False),
                               local_multicast=cfg.get("local_multicast", False))
                     if cfg.get("rules", True) else None)

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

    def keep_nodes(self, now: int) -> set[int]:
        return self.tags.keep_nodes(now) if self.tags is not None else set()

    def remap(self, old2new) -> None:
        if self.novelty is not None:
            self.novelty.remap(old2new)
        if self.tags is not None:
            self.tags.remap(old2new)

    def process(self, w: Window, reg: Registry, ids: np.ndarray) -> list[Hit]:
        hits = []
        if self.novelty is not None:
            hits += self.novelty.process(w, reg, ids)
        if self.tags is not None:
            hits += self.tags.process(w, reg)
        sup = getattr(self, "suppressed", None)
        if sup:   # a suppressed new program covers its repeat runs too
            hits = [h for h in hits if (h.rule.replace("novel_executable_repeat", "novel_executable"), h.key) not in sup]
        return hits


def fit_layers(store, days: list[str], reg: Registry, n_preexisting: int, cfg: LayerConfig = LayerConfig(), log=print) -> dict:
    """Fit layers 1 and 2 on benign days (in order): known executables, trusted remote addresses, per-key alarm
    thresholds. Returns the layers.json document.

    The alarm thresholds must be learned under the novelty a deployment will see, not under the baseline's own
    hindsight (every baseline address is trusted by construction otherwise, and no benign alarm is ever observed).
    The calibration replay is therefore leave-one-day-out: an address is trusted on a day only if it also occurs
    on another baseline day, and a file counts as pre-existing only if it was seen on an earlier day."""
    known = NoveltyLayer.fit((store.windows(d) for d in days), reg, cfg.full_paths)
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
                if not is_local(ip, cfg.local_multicast):
                    ip_days[ip].add(k)
    ips = set(ip_days)
    recurring = {ip for ip, ds in ip_days.items() if len(ds) >= 2}
    # program|port pairs sent to on private addresses (recurring on two baseline days, like trusted addresses)
    svc_days: dict[str, set[int]] = defaultdict(set)
    send_ops = np.array(sorted(SEND), dtype=np.int64)
    for k, d in enumerate(days):
        for w in store.windows(d):
            m = np.isin(w.etype, send_ops)
            for s_, d_ in zip(w.src[m].tolist(), w.dst[m].tolist()):
                e = reg.entities[d_]
                if e.ntype == "netflow" and is_private(remote_ip(e.label)) and reg.entities[s_].ntype == "subject":
                    svc_days[f"{executable(reg.entities[s_].label, cfg.full_paths)}|{remote_port(e.label)}"].add(k)
    private_services = sorted(k for k, ds in svc_days.items() if len(ds) >= 2 or len(days) == 1)
    eng = TagEngine(cfg.tags, recurring, None, n_preexisting, fit=True, private_services=set(private_services), full_paths=cfg.full_paths,
                    image_exec=cfg.image_exec, local_multicast=cfg.local_multicast)
    eng.first_day = first_day
    for k, d in enumerate(days):
        eng.cur_day = k
        for w in store.windows(d):
            eng.process(w, reg)
    thr = eng.thresholds()
    log(f"layers: {len(known)} known executables, {len(ips)} baseline remote addresses ({len(recurring)} recurring), "
        f"benign alarm keys " + (", ".join(f"{r}={len(v)}" for r, v in sorted(thr.items())) or "none"))
    return {"version": 1, "config": {"novelty": cfg.novelty, "rules": cfg.rules, "tags": asdict(cfg.tags), "evidence_rules": list(cfg.evidence_rules),
                                     "normalize_programs": cfg.normalize_programs, "novel_instances": cfg.novel_instances,
                                     "full_paths": cfg.full_paths, "image_exec": cfg.image_exec,
                                     "local_multicast": cfg.local_multicast},
            "fit_days": list(days), "known_executables": sorted(known), "trusted_ips": sorted(ips), "thresholds": thr,
            "private_services": private_services,
            "benign_alarm_events": dict(eng.benign_count)}
