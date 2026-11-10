"""0.12 Sigma layer (artifacts/lab_v12): SigmaHQ detection rules evaluated on the provenance stream, as part of the
deterministic layers - the fallback that flags known attacker techniques whatever the learned detectors score.

Rules are compiled from the SigmaHQ YAML by pdp_server.tools.sigma_compile into sigma_rules.json (Detection Rule
License 1.1: every rule keeps its title, id and author). Provenance events become Sigma events:

  process_creation   CLONE parent -> child (or a process first seen without one)  Image, CommandLine, ParentImage,
                                                                                    ParentCommandLine
  image_load         a process READs a .dll / .so / .sys / .ocx / .cpl / .drv file  Image, ImageLoaded
  file_event         a process WRITEs a file                                        Image, TargetFilename
  network_connection a process CONNECTs / sends to a remote address                 Image, DestinationIp,
                                                                                    DestinationPort, Initiated

Matching follows the Sigma specification: case-insensitive, wildcards * and ?, modifiers contains / startswith /
endswith / all / windash / re / cidr, null = field absent. A field the telemetry does not record is absent.
Windows paths are given in Windows form (c:\\windows\\system32\\x.exe; NT device paths converted).

No duplicates: each (process, counterpart, event kind) is evaluated once; each (rule, program) alerts once per UTC
day; the runtime merges all reasons of a node into one alert. A (rule, program) pair that already matched during the
endpoint's baseline becomes evidence (rule `sigma_known`, alerts only when the learned score corroborates it)."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections import defaultdict

import numpy as np

from .layers import Hit, executable, program_key, remote_ip, remote_port, is_local
from .schema import EDGE_TYPE_ID, Registry
from .windows import Window

RULES_FILE = os.path.join(os.path.dirname(__file__), "sigma_rules.json")
SIGMA_RULE, SIGMA_KNOWN_RULE = "sigma", "sigma_known"
LEVELS = ("informational", "low", "medium", "high", "critical")
DAY_NS = 86_400 * 1_000_000_000
_LOADED_EXT = (".dll", ".so", ".sys", ".ocx", ".cpl", ".drv")
_SO_RE = re.compile(r"\.so(\.\d+)*$")
_NT = re.compile(r"^(?:/device/harddiskvolume\d+|\\device\\harddiskvolume\d+)", re.I)
_DRIVE = re.compile(r"^(?:/\?\?/|\\\?\?\\|//\?/|\\\\\?\\|/)?([a-z]):", re.I)
_WIN_EXT = re.compile(r"\.(exe|com|bat|cmd|dll|scr|ps1|vbs|js|msi|cpl|hta|sys)$", re.I)
_NONE = ("None", "", "null", None)
_DASHES = ("-", "/", "\u2013", "\u2014", "\u2015")


# ------------------------------------------------------------------------------------------------ values
def is_windows_path(p: str) -> bool:
    q = p.replace("\\", "/").lower()
    return bool(_NT.match(q) or re.match(r"^(?:/\?\?/|//\?/)?[a-z]:/", q) or q.startswith("%systemroot%")
                or "\\" in p or (("/" not in q) and _WIN_EXT.search(q)))


def win_path(p: str) -> str:
    """'/Device/HarddiskVolume1/Windows/System32/x.exe', 'C:/Windows/x.exe', '\\??\\C:\\x' -> 'c:\\windows\\...'."""
    q = p.replace("/", "\\")
    q = re.sub(r"^\\device\\harddiskvolume\d+", "c:", q, flags=re.I)
    q = re.sub(r"^(?:\\\?\?\\|\\\\\?\\)", "", q)
    q = re.sub(r"^%systemroot%", r"c:\\windows", q, flags=re.I)
    if "\\" not in q:
        q = "\\" + q                    # a bare name: endswith('\\x.exe') must still match
    return q


def linux_path(p: str) -> str:
    return p if "/" in p else "/" + p


def _wild(v: str, how: str) -> re.Pattern:
    """Sigma value with wildcards -> regex (escaped \\* and \\? are literal)."""
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v) and v[i + 1] in "*?\\":
            out.append(re.escape(v[i + 1])); i += 2; continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c)); i += 1
    body = "".join(out)
    body = {"eq": f"^{body}$", "contains": body, "startswith": f"^{body}", "endswith": f"{body}$"}[how]
    return re.compile(body, re.I | re.S)


def _has_wild(v: str) -> bool:
    """An unescaped * or ? (Sigma: \\* and \\? are literal, \\\\ is one backslash)."""
    i = 0
    while i < len(v):
        if v[i] == "\\" and i + 1 < len(v) and v[i + 1] in "*?\\":
            i += 2; continue
        if v[i] in "*?":
            return True
        i += 1
    return False


def _unescape(v: str) -> str:
    return re.sub(r"\\([*?\\])", r"\1", v)


def _windash(v: str) -> list[str]:
    if not re.search(r"(^|\s)[-/\u2013\u2014\u2015]", v):
        return [v]
    return list(dict.fromkeys(re.sub(r"(^|\s)[-/\u2013\u2014\u2015]", lambda m: m.group(1) + d, v) for d in _DASHES))


class _Field:
    """One `field|modifiers: values` entry -> a predicate on the event."""
    __slots__ = ("field", "preds", "all", "null")

    def __init__(self, field: str, mods: list[str], values: list):
        self.field, self.all = field, "all" in mods
        self.null = any(v is None for v in values)
        vals = [v for v in values if v is not None]
        if "windash" in mods:
            vals = [x for v in vals for x in _windash(v)]
        how = "contains" if "contains" in mods else "startswith" if "startswith" in mods else "endswith" if "endswith" in mods else "eq"
        self.preds = []
        for v in vals:
            if "re" in mods:
                rx = re.compile(v)
                self.preds.append(lambda s, rx=rx: bool(rx.search(s)))
            elif "cidr" in mods:
                net = ipaddress.ip_network(v, strict=False)
                self.preds.append(lambda s, net=net: _in_net(s, net))
            elif _has_wild(v):
                rx = _wild(v, how)
                self.preds.append(lambda s, rx=rx: bool(rx.search(s)))
            else:
                lv = _unescape(v).lower()
                if how == "eq":
                    self.preds.append(lambda s, lv=lv: s.lower() == lv)
                elif how == "contains":
                    self.preds.append(lambda s, lv=lv: lv in s.lower())
                elif how == "startswith":
                    self.preds.append(lambda s, lv=lv: s.lower().startswith(lv))
                else:
                    self.preds.append(lambda s, lv=lv: s.lower().endswith(lv))

    def __call__(self, ev: dict) -> bool:
        s = ev.get(self.field)
        if s is None:
            return self.null
        if not self.preds:
            return False
        return all(p(s) for p in self.preds) if self.all else any(p(s) for p in self.preds)


def _in_net(s: str, net) -> bool:
    try:
        a = ipaddress.ip_address(s.strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return a.version == net.version and a in net


class SigmaRule:
    __slots__ = ("id", "title", "level", "product", "category", "parent", "sels", "cond", "tags")

    def __init__(self, r: dict):
        self.id, self.title, self.level = r["id"], r["title"], r["level"]
        self.product, self.category, self.parent = r["product"], r["category"], r.get("parent", False)
        self.tags = [t for t in r.get("tags", []) if t.startswith("attack.t")]
        self.sels = {}
        for name, s in r["sel"].items():
            if "keywords" in s:
                kws = [k.lower() for k in s["keywords"]]
                self.sels[name] = ("kw", kws)
            else:
                self.sels[name] = ("maps", [[_Field(f, m, v) for f, m, v in mp] for mp in s["maps"]])
        self.cond = r["cond"]

    def _sel(self, name: str, ev: dict) -> bool:
        kind, body = self.sels[name]
        if kind == "kw":
            text = " ".join(v for v in ev.values() if isinstance(v, str)).lower()
            return any(k in text for k in body)
        return any(all(f(ev) for f in mp) for mp in body)

    def _eval(self, ast, ev) -> bool:
        op = ast[0]
        if op == "sel":
            return self._sel(ast[1], ev)
        if op == "not":
            return not self._eval(ast[1], ev)
        if op == "and":
            return all(self._eval(x, ev) for x in ast[1:])
        return any(self._eval(x, ev) for x in ast[1:])

    def match(self, ev: dict) -> bool:
        return self._eval(self.cond, ev)


def load_rules(levels=("high", "critical"), path: str = RULES_FILE) -> dict:
    """{(product, category): [SigmaRule]} for the given levels."""
    data = json.load(open(path))
    out = defaultdict(list)
    for r in data["rules"]:
        if r["level"] in levels:
            out[(r["product"], r["category"])].append(SigmaRule(r))
    return dict(out)


# ------------------------------------------------------------------------------------------------ the layer
def _proc_fields(label: str) -> tuple[str | None, str | None]:
    """(image, command line) of a 'subject <exe> <cmdline>' label; None when not recorded."""
    exe = executable(label, full_paths=True, backslash_paths=True)
    if exe in _NONE:
        return None, None
    body = label[8:] if label.startswith("subject ") else label
    parts = body.split(" ", 1)
    if parts[0] in _NONE:               # no path: the command line is everything after it
        cmd = parts[1] if len(parts) > 1 else None
    else:
        cmd = body[len(exe):].strip() or None
    if cmd in _NONE:
        cmd = None
    return exe, cmd


class SigmaLayer:
    def __init__(self, levels=("high", "critical"), known: set[str] | None = None, rules: dict | None = None,
                 bare_names: str = "absent"):
        """bare_names: a process recorded with a program name but no folder (OpTC: 'taskhostw.exe'). "absent" (lab_v12
        iteration 2): Image / ParentImage are absent - the folder is unknown, and rules that check where a system
        program runs from must not see a made-up location; "prefix" (iteration 1): Image = '\\taskhostw.exe'."""
        self.rules = rules if rules is not None else load_rules(levels)
        self.levels = tuple(levels)
        self.bare_names = bare_names
        self.known = set(known or ())          # "<rule id>:<program key>" matched during the baseline
        self.reset()

    def reset(self):
        self._proc_done: set[int] = set()
        self._pairs: set[tuple] = set()
        self._fired: set[tuple] = set()       # (rule id, program key, day)
        self._img: dict[int, tuple] = {}

    def remap(self, old2new) -> None:
        self._proc_done = {int(old2new[n]) for n in self._proc_done if old2new[n] >= 0}
        self._pairs = {(k, int(old2new[a]), int(old2new[b])) for k, a, b in self._pairs if old2new[a] >= 0 and old2new[b] >= 0}
        self._img = {}

    # -- event fields
    def _proc(self, reg: Registry, n: int):
        r = self._img.get(n)
        if r is None:
            e = reg.entities[n]
            img, cmd = _proc_fields(e.label)
            if img is None:
                r = (None, None, None, None, None)
            else:
                win = is_windows_path(img)
                shown = win_path(img) if win else linux_path(img)
                bare = "/" not in img.replace("\\", "/")
                field = None if (bare and self.bare_names == "absent") else shown
                r = ("windows" if win else "linux", field, cmd, program_key(img, True), shown)
            self._img[n] = r
        return r

    def _check(self, out, product, category, ev, nodes, ts, pkey, child_only, shown=None):
        for rule in self.rules.get((product, category), ()):
            try:
                if not rule.match(ev):
                    continue
            except Exception:  # noqa - a malformed rule never stops detection
                continue
            key = f"{rule.id}:{pkey}"
            day = ts // DAY_NS
            if (rule.id, pkey, day) in self._fired:
                continue
            self._fired.add((rule.id, pkey, day))
            ns = nodes if (rule.parent and not child_only) else nodes[:1]
            what = ev.get("CommandLine") or ev.get("TargetFilename") or ev.get("ImageLoaded") or ev.get("DestinationIp") or ""
            detail = (f"{shown or ev.get('Image')}: Sigma rule '{rule.title}' ({rule.level}"
                      + (f", {', '.join(t[7:].upper() for t in rule.tags[:3])}" if rule.tags else "") + ")"
                      + (f" - {what[:160]}" if what else ""))
            rname = SIGMA_KNOWN_RULE if key in self.known else SIGMA_RULE
            out.append(Hit("rules", rname, key, float(LEVELS.index(rule.level)), tuple(int(x) for x in ns), int(ts), detail))

    def process(self, w: Window, reg: Registry, ids: np.ndarray | None = None) -> list[Hit]:
        out: list[Hit] = []
        ents = reg.entities
        clone, rd, wr, conn = (EDGE_TYPE_ID[x] for x in ("CLONE", "READ", "WRITE", "CONNECT"))
        sends = {EDGE_TYPE_ID[x] for x in ("SENDTO", "SENDMSG")}
        parent_of: dict[int, tuple[int, int]] = {}
        first_t: dict[int, int] = {}
        src, dst, et, tt = w.src.tolist(), w.dst.tolist(), w.etype.tolist(), w.t.tolist()
        for s, d, e, t in zip(src, dst, et, tt):
            first_t.setdefault(s, t); first_t.setdefault(d, t)
            if e == clone and ents[s].ntype == "subject" and ents[d].ntype == "subject":
                parent_of.setdefault(d, (s, t))
        # process creation: every process once, with its parent when the window shows it
        for n in sorted(set(first_t)):
            if n in self._proc_done or ents[n].ntype != "subject":
                continue
            self._proc_done.add(n)
            prod, img, cmd, pkey, shown = self._proc(reg, n)
            if prod is None or (img is None and not cmd):
                continue
            ev = {"Image": img} if img is not None else {}
            if cmd:
                ev["CommandLine"] = cmd
            p = parent_of.get(n)
            nodes = (n,)
            if p is not None:
                pprod, pimg, pcmd, _, _ = self._proc(reg, p[0])
                if pprod is not None:
                    if pimg is not None:
                        ev["ParentImage"] = pimg
                    if pcmd:
                        ev["ParentCommandLine"] = pcmd
                    nodes = (n, p[0])
            self._check(out, prod, "process_creation", ev, nodes, (p[1] if p else first_t[n]), pkey, False, shown)
        # library loads, file writes, connections: each (process, object) once
        for s, d, e, t in zip(src, dst, et, tt):
            if e == rd:
                proc, obj, kind = d, s, "image_load"
            elif e == wr:
                proc, obj, kind = s, d, "file_event"
            elif e == conn or e in sends:
                proc, obj, kind = s, d, "network_connection"
            else:
                continue
            if ents[proc].ntype != "subject":
                continue
            k = (kind, proc, obj)
            if k in self._pairs:
                continue
            o = ents[obj]
            if kind == "network_connection":
                if o.ntype != "netflow":
                    continue
                ip = remote_ip(o.label)
                if is_local(ip):
                    continue
            elif o.ntype != "file":
                continue
            self._pairs.add(k)
            prod, img, cmd, pkey, shown = self._proc(reg, proc)
            if prod is None:
                continue
            ev = {"Image": img} if img is not None else {}
            if kind == "network_connection":
                ev.update(DestinationIp=ip, DestinationPort=remote_port(o.label), Initiated="true")
            else:
                path = o.label[5:] if o.label.startswith("file ") else o.label
                if path in _NONE:
                    continue
                low = path.lower()
                if kind == "image_load" and not (low.endswith(_LOADED_EXT) or _SO_RE.search(low)):
                    continue
                path = win_path(path) if prod == "windows" else path
                ev["ImageLoaded" if kind == "image_load" else "TargetFilename"] = path
            self._check(out, prod, kind, ev, (proc,), t, pkey, True, shown)
        return out

    @staticmethod
    def fit(windows_by_day, reg: Registry, levels=("high", "critical"), rules: dict | None = None,
            bare_names: str = "absent") -> set[str]:
        """The (rule, program) keys that match during the baseline: they become evidence at detection time."""
        lay = SigmaLayer(levels, rules=rules, bare_names=bare_names)
        keys = set()
        for ws in windows_by_day:
            for w in ws:
                keys |= {h.key for h in lay.process(w, reg)}
        return keys
