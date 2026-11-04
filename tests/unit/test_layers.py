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

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
