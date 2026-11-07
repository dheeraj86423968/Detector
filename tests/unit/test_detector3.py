"""Detector-3 (0.7, pdp_engine.behaviour): behavioural likelihood per endpoint, novelty paid once per process
instance, save/load, learned-seeded propagation, and the trainer/runtime path (tiny CPU training).
Synthetic, harmless data."""
import os
import random
import shutil
import sys
import tempfile

import numpy as np

from pdp_engine.behaviour import BehaviourModel, entity_keys, gen, propagate, top_threshold
from pdp_engine.data import WindowStore, ingest_day
from pdp_engine.schema import EDGE_TYPE_ID, Entity, Event, Registry
from pdp_engine.windows import Window

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


def window(reg, events, t0=0):
    """events: [(src Entity, op, dst Entity)] in data-flow order -> Window over reg."""
    src, dst, ts, et = [], [], [], []
    for k, (a, op, b) in enumerate(events):
        src.append(reg.add(a)); dst.append(reg.add(b)); ts.append(t0 + k); et.append(EDGE_TYPE_ID[op])
    return Window(t0, t0 + len(events), np.array(src, np.int64), np.array(dst, np.int64), np.array(ts, np.int64),
                  np.array(et, np.int64), [f"e{t0}-{k}" for k in range(len(events))])


P = Entity.process
F = Entity.file
N = Entity.socket

# ---------------------------------------------------------------- generalisation of volatile names
check(gen("/home/a/.cache/x/3F2A9C8B7D6E5F40") == gen("/home/a/.cache/x/0011223344556677"), "hex ids generalised")
check(gen("/tmp/tmpab3kq9z") == gen("/tmp/tmpzz81kqq"), "random temp names generalised")
check(entity_keys("netflow", "netflow 93.184.216.34 443")[2] == "n:93.184.216.34|443", "netflow key keeps a well-known port")
check(entity_keys("netflow", "netflow 10.0.0.5 51234")[4] == "N:private|hi", "ephemeral port bucket and address class")
check(entity_keys("subject", "subject None nginx")[0] == "s:nginx", "process without an image path keyed by its command name")

# ---------------------------------------------------------------- baseline: a web server, an installer, a shell
reg = Registry()
base = []
NAMES = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima",
         "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango"]
for day in range(3):
    for k in range(40):
        ng = P(f"ng{day}{k}", "/usr/sbin/nginx", "nginx: worker")
        base.append(window(reg, [(F("f:conf", "/etc/nginx/nginx.conf"), "READ", ng),
                                 (N("n:c", "10.0.0.7", 51000 + k), "RECVFROM", ng),
                                 (ng, "SENDTO", N("n:c", "10.0.0.7", 51000 + k)),
                                 (ng, "WRITE", F("f:log", "/var/log/nginx/access.log"))], t0=(day * 100 + k) * 1000))
        nm = NAMES[k % 20] + NAMES[(k + day * 7) % 20]            # distinct package names (no digits: not generalised)
        inst = P(f"dp{day}{k}", "/usr/bin/dpkg", "dpkg -i pkg.deb")
        base.append(window(reg, [(inst, "WRITE", F(f"f:new{day}{k}{j}", f"/usr/share/{nm}/file{j}.dat")) for j in range(5)]
                           + [(inst, "CLONE", P(f"dpc{day}{k}", f"/var/lib/dpkg/info/{nm}.postinst", "postinst"))],
                           t0=(day * 100 + k) * 1000 + 500))
m = BehaviourModel()
K = m.keys(reg)
for w in base:
    m.fit_window(w, K)
m.finish()


def node_score(events, node):
    w = window(reg, events, t0=10**9 + len(reg))
    own, _ = m.node_scores(w, K, len(reg))
    return float(own[reg.get(node.uuid)])


ng = P("ng-t1", "/usr/sbin/nginx", "nginx: worker")
s_known = node_score([(F("f:conf", "/etc/nginx/nginx.conf"), "READ", ng)], ng)
ng2 = P("ng-t2", "/usr/sbin/nginx", "nginx: worker")
child = P("sh-t2", "/tmp/.x/payload", "/tmp/.x/payload")
s_web_spawn = node_score([(ng2, "CLONE", child)], child)
dp = P("dp-t3", "/usr/bin/dpkg", "dpkg -i other.deb")
child2 = P("dpc-t3", "/var/lib/dpkg/info/other.postinst", "postinst")
s_pkg_spawn = node_score([(dp, "CLONE", child2)], child2)
check(s_known < 1.0, f"known program doing a known thing scores ~0 ({s_known:.2f})")
check(s_web_spawn > 10.0, f"a web server starting a new program from /tmp is very unusual ({s_web_spawn:.1f})")
check(s_web_spawn > s_pkg_spawn + 5.0, f"a new program started by the package manager is ordinary by comparison ({s_pkg_spawn:.1f} vs {s_web_spawn:.1f})")

# novelty paid once per process instance: the 50th new file the same installer run writes into one directory is cheap
dp4 = P("dp-t4", "/usr/bin/dpkg", "dpkg -i big.deb")
ev = [(dp4, "WRITE", F(f"f:big{j}", f"/opt/bigpkg/lib/mod{j}.so")) for j in range(50)]
w = window(reg, ev, t0=2 * 10**9)
p, x, e, s = m.edge_scores(w, K)
check(s[0] > 5.0 and s[-1] <= np.log1p(49) + 1e-9, f"first new file in a new directory pays full novelty ({s[0]:.1f}), the 50th at most log(50) ({s[-1]:.2f})")

# save / load round trip gives identical scores
tmp = tempfile.mkdtemp()
m.save(tmp)
m2 = BehaviourModel.load(tmp)
K2 = m2.keys(reg)
_, _, _, s2 = m2.edge_scores(w, K2)
check(np.allclose(s, s2), "save/load: identical edge scores")
try:
    m2.fit_window(w, K2)
    check(False, "a loaded model is frozen")
except RuntimeError:
    check(True, "a loaded model is frozen")

# exclusion: an excluded node's activity is not learned (compared with the same baseline learned without exclusion)
def excl_score(use_exclusion):
    regx = Registry()
    mx = BehaviourModel()
    Kx = mx.keys(regx)
    bad = P("bad", "/usr/sbin/nginx", "nginx: worker")
    wx = window(regx, [(bad, "CLONE", P("evil", "/tmp/evil", "/tmp/evil"))] * 3)
    ex = np.zeros(len(regx), bool); ex[regx.get("bad")] = True
    mx.fit_window(wx, Kx, ex if use_exclusion else None)
    for j in range(20):
        mx.fit_window(window(regx, [(F("f:conf", "/etc/nginx/nginx.conf"), "READ", P(f"ok{j}", "/usr/sbin/nginx", "nginx")),
                                    (P(f"sh{j}", "/usr/bin/bash", "bash"), "CLONE", P(f"ls{j}", "/usr/bin/ls", "ls"))], t0=j * 10), Kx)
    mx.finish()
    w2 = window(regx, [(P("ng9", "/usr/sbin/nginx", "nginx"), "CLONE", P("evil2", "/tmp/evil", "/tmp/evil"))], t0=999)
    own, _ = mx.node_scores(w2, Kx, len(regx))
    return float(own[regx.get("evil2")])
se, sn = excl_score(True), excl_score(False)
check(se > sn + 3.0, f"activity of excluded (unreleased-alert) nodes is not learned ({se:.1f} excluded vs {sn:.1f} learned)")

# ---------------------------------------------------------------- propagation
lv = np.zeros(4)
wp = Window(0, 3, np.array([0, 1, 2]), np.array([1, 2, 3]), np.array([0, 1, 2]), np.array([EDGE_TYPE_ID["WRITE"]] * 3), ["a", "b", "c"])
own = np.array([10.0, 0, 0, 0])
propagate(lv, own, wp, np.array([1.0, 1.0, 0.1]), delta=0.9, gate=0.4, clip=3.0, seed=0.3, passes=3)
check(abs(lv[1] - 2.7) < 1e-9 and abs(lv[2] - 2.43) < 1e-9, f"suspicion fades per hop and is clipped ({lv[1]:.2f}, {lv[2]:.2f})")
check(lv[3] == 0.0, "a common edge (below the gate) carries nothing")
lv = np.zeros(2)
propagate(lv, np.array([0.2, 0.0]), Window(0, 1, np.array([0]), np.array([1]), np.array([0]), np.array([EDGE_TYPE_ID["WRITE"]]), ["a"]),
          np.array([5.0]), delta=0.9, gate=0.4, clip=3.0, seed=0.3, passes=2)
check(lv[1] == 0.0, "nodes below the seed level pass nothing on")
lv = np.zeros(2)
propagate(lv, np.array([5.0, 0.0]), Window(0, 1, np.array([0]), np.array([1]), np.array([0]), np.array([EDGE_TYPE_ID["OPEN"]]), ["a"]),
          np.array([5.0]), delta=0.9, gate=0.4, clip=3.0, seed=0.3, passes=2)
check(lv[1] == 0.0, "OPEN edges carry nothing")
check(top_threshold(np.array([5.0, 4, 3, 2, 1]), 0) == 5.0 and top_threshold(np.array([5.0, 4, 3, 2, 1]), 2) == 3.0,
      "budget threshold: the (budget+1)-th largest validation score")

# ---------------------------------------------------------------- trainer + runtime (tiny CPU model)
from pdp_engine.runtime import Runtime
from pdp_engine.trainer import TrainConfig, Trainer, upgrade_bundle_07

rng = random.Random(3)
MIN, T0 = 60 * 10**9, 1_790_000_000 * 10**9
progs = ["/usr/bin/bash", "/usr/bin/python3", "/usr/sbin/sshd", "/usr/bin/curl"]
seq = [0]


def activity(t0, minutes, tag, attack=False):
    out = []

    def e(ts, a, op, b):
        seq[0] += 1
        out.append(([a, b], Event(ts, a.uuid, op, b.uuid, f"e{seq[0]:010d}")))
    for mi in range(minutes):
        for k in range(12):
            ts = t0 + mi * MIN + k * 10**9
            exe = rng.choice(progs)
            p = P(f"p:{tag}:{mi}:{k}", exe, f"{exe} {k % 3}")
            e(ts, F(f"file:{exe}", exe), "EXECUTE", p)
            e(ts, F(f"file:/etc/conf{k % 6}", f"/etc/conf{k % 6}"), "READ", p)
            if k % 4 == 0:
                e(ts, p, "CONNECT", N("net:10.0.0.5:443", "10.0.0.5", 443))
        if attack and mi == minutes // 2:
            ts = t0 + mi * MIN + 30 * 10**9
            c = P(f"p:{tag}:dl", "/usr/sbin/sshd", "sshd: root")
            tool = F("file:/dev/shm/.k", "/dev/shm/.k")
            e(ts, c, "WRITE", tool)
            r = P(f"p:{tag}:run", "/dev/shm/.k", "/dev/shm/.k")
            e(ts + 10**9, tool, "EXECUTE", r)
            e(ts + 2 * 10**9, c, "CLONE", r)
            e(ts + 3 * 10**9, r, "CONNECT", N("net:198.51.100.7:4444", "198.51.100.7", 4444))
            e(ts + 4 * 10**9, r, "WRITE", F("file:/etc/cron.d/k", "/etc/cron.d/k"))
    return out


tmp2 = tempfile.mkdtemp()
st = WindowStore(os.path.join(tmp2, "base"))
regt = Registry()
lookup = {}
days = []
for d in range(3):
    ev = activity(T0 + d * 86400 * 10**9, 40, f"d{d}")
    for ents, _ in ev:
        for x in ents:
            lookup[x.uuid] = x
    day = f"2026-01-0{d + 1}"
    st.add_day(day, ingest_day(regt, [e for _, e in ev], lookup, window_ns=10 * MIN))
    days.append(day)
st.save_registry(regt)
cfg = TrainConfig(device="cpu", emb_dim=16, w2v_epochs=2, velox_out_dim=16, velox_epochs=2, velox_runs=1, orthrus_seeds=(0,),
                  orthrus_hid_dim=16, orthrus_out_dim=16, orthrus_epochs=2, calibration_budget=2)
out = os.path.join(tmp2, "bundle")
Trainer(st, days[:2], days[2], cfg, out).run({"endpoint": "t"})
import json
man = json.load(open(os.path.join(out, "manifest.json")))
cal = man["calibration"]
check("detector-3" in man["detectors"] and "detector-3" in man["requires"] and "propagation" in man["requires"],
      "0.7 bundle: detector-3 + propagation required of the runtime")
check(cal.get("final", {}).get("pending") is None and cal["final"]["threshold"] > 0, f"final threshold calibrated after propagation ({cal['final']['threshold']:.3f})")
check(man["layers"]["novelty"] is True and man["learned_policy"]["learned_alerts"] is True
      and man["learned_policy"].get("corroboration") == "threshold",
      "0.7 defaults: layer 1 kept as a safety net, learned alerts on, corroboration at the learned threshold")
rtc = Runtime(out, st.load_registry(), device="cpu")
check(abs(rtc.corroboration - 1.0) < 1e-3 and abs(rtc.policy.corroboration - 1.0) < 1e-3, "the runtime corroborates only above the learned threshold")
check(os.path.exists(os.path.join(out, "detector-3.npz")) and "detector-3.npz" in man["sha256"], "detector-3 tables are in the signed digests")

# score an attack day with the runtime
regs = st.load_registry()
ev = activity(T0 + 5 * 86400 * 10**9, 40, "t", attack=True)
for ents, _ in ev:
    for x in ents:
        lookup[x.uuid] = x
st2 = WindowStore(os.path.join(tmp2, "test"))
st2.add_day("2026-01-06", ingest_day(regs, [e for _, e in ev], lookup, window_ns=10 * MIN))
rt = Runtime(out, regs, device="cpu")
alerted, r3max = {}, 0.0
for w in st2.windows("2026-01-06"):
    r = rt.score(w)
    r3max = max(r3max, float(r.r3.max()) if len(r.r3) else 0.0)
    for n in r.alerts.tolist():
        alerted.setdefault(regs.entities[n].uuid, r.layer_of(n))
check("p:t:run" in alerted, f"the dropped program run by the SSH daemon alerts ({alerted.get('p:t:run')})")
check(len(alerted) <= 25, f"few alerts on an otherwise ordinary day ({len(alerted)})")
check(r3max > 1.0, f"detector-3 scores the attack above its threshold (max ratio {r3max:.1f})")

# upgrade path: a 0.6-style bundle (no detector-3) upgraded without retraining
cfg6 = TrainConfig(**{**cfg.__dict__, "detector3": False, "layer_novelty": True, "novelty_as_evidence": False, "learned_alerts": False})
b6 = os.path.join(tmp2, "b6")
Trainer(st, days[:2], days[2], cfg6, b6).run({"endpoint": "t"})
check("detector-3" not in json.load(open(os.path.join(b6, "manifest.json")))["detectors"], "0.6-style bundle has no detector-3")
b7 = os.path.join(tmp2, "b7")
upgrade_bundle_07(b6, b7, st, cfg)
m7 = json.load(open(os.path.join(b7, "manifest.json")))
check("detector-3" in m7["detectors"] and m7["calibration"]["final"].get("pending") is None, "upgrade_bundle_07 adds detector-3 and calibrates")
rt7 = Runtime(b7, st.load_registry(), device="cpu")
check(rt7.bm is not None and rt7.prop is not None, "the runtime loads the upgraded bundle")

# 0.7b option: per-activity detector-3 thresholds
bg = os.path.join(tmp2, "bg")
Trainer(st, days[:2], days[2], TrainConfig(**{**cfg.__dict__, "d3_grouped": True}), bg).run({"endpoint": "t"})
cg = json.load(open(os.path.join(bg, "calibration.json")))["detector-3"]
check(len(cg.get("groups", [])) == 4 and min(cg["groups"]) >= 5.0, f"per-activity thresholds calibrated ({[round(x, 1) for x in cg.get('groups', [])]})")
regg = st.load_registry()
for ents, _ in ev:
    for x in ents:
        regg.add(x)
rtg = Runtime(bg, regg, device="cpu")
alg = set()
st3 = WindowStore(os.path.join(tmp2, "test3"))
st3.add_day("2026-01-06", ingest_day(regg, [e for _, e in ev], lookup, window_ns=10 * MIN))
for w in st3.windows("2026-01-06"):
    alg |= {regg.entities[n].uuid for n in rtg.score(w).alerts.tolist()}
check(rtg.thr3g is not None and "p:t:run" in alg, f"per-activity thresholds: the dropped program still alerts ({len(alg)} alerts)")

shutil.rmtree(tmp, ignore_errors=True)
shutil.rmtree(tmp2, ignore_errors=True)
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
