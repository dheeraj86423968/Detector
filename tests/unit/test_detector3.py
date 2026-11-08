"""Detector-3 (0.7, pdp_engine.behaviour): behavioural likelihood per endpoint, novelty paid once per process
instance, save/load, learned-seeded propagation, 0.8 breadth evidence (Breadth, breadth_node_scores), and the
trainer/runtime path (tiny CPU training; calibration, upgrades, compaction, manifest requires).
Synthetic, harmless data."""
import os
import random
import shutil
import sys
import tempfile

import numpy as np

from pdp_engine.behaviour import (BREADTH_GROUPS, BehaviourModel, Breadth, breadth_node_scores, edge_events, entity_keys,
                                  gen, propagate, top_threshold)
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

# ---------------------------------------------------------------- 0.8 breadth evidence (behaviour.Breadth)
check(BREADTH_GROUPS == ("process", "network", "file-write", "file-read"), "breadth groups")
H = 100
b = Breadth(cap=10.0, floor=4.0, horizon_ns=H)
check(b.val.shape == (4, 0) and b.ts.shape == (4, 0), "empty state")
b.grow(3)
check(b.val.shape == (4, 3) and not b.val.any() and b.ts.dtype == np.int64, "grow: zero state for new positions")
pr, ev = b.update(np.zeros(0, np.int64), np.zeros(0, np.int64), np.zeros(0), 1000)
check(len(pr) == 0 and len(ev) == 0, "update without events: nothing touched")
# process 0: process group 8 (-> 4), network 7 and 9 in one window (max 9 -> 5); process 1: one extreme read (50 -> cap)
pr, ev = b.update(np.array([0, 0, 0, 1]), np.array([0, 1, 1, 3]), np.array([8.0, 7.0, 9.0, 50.0]), 1000)
check(pr.tolist() == [0, 1] and np.allclose(ev, [9.0, 6.0]),
      f"sum over groups of (min(max, cap) - floor); one extreme event counts at most cap - floor ({pr.tolist()}, {ev.tolist()})")
check(b.val[1, 0] == 9.0 and b.ts[1, 0] == 1000 and b.val[3, 1] == 50.0, "state: the raw maximum per group and when it was set")
pr, ev = b.update(np.array([2, 2]), np.array([2, 3]), np.array([3.9, 4.0]), 1000)
check(pr.tolist() == [2] and ev.tolist() == [0.0], "scores at or below the floor count nothing")
pr, ev = b.update(np.array([0]), np.array([1]), np.array([6.0]), 1050)
check(np.allclose(ev, [9.0]) and b.val[1, 0] == 9.0 and b.ts[1, 0] == 1000, "a smaller score within the horizon keeps the maximum (and its time)")
pr, ev = b.update(np.array([0]), np.array([1]), np.array([9.5]), 1060)
check(np.allclose(ev, [9.5]) and b.ts[1, 0] == 1060, "a larger score replaces the maximum")
pr, ev = b.update(np.array([0]), np.array([2]), np.array([10.0]), 1100)
check(np.allclose(ev, [4.0 + 5.5 + 6.0]), "exactly at the horizon a group still counts (process group set at 1000, now 1100)")
pr, ev = b.update(np.array([0]), np.array([3]), np.array([30.0]), 1101)
check(np.allclose(ev, [5.5 + 6.0 + 6.0]), "past the horizon an untouched group no longer counts")
pr, ev = b.update(np.array([0, 1]), np.array([1, 3]), np.array([5.0, 5.0]), 1300)
check(np.allclose(ev, [1.0, 1.0]) and b.val[1, 0] == 5.0 and b.val[3, 1] == 5.0,
      f"an expired maximum is replaced by a smaller new score; the other groups expired ({ev.tolist()})")
b.grow(2)
check(b.val.shape == (4, 3), "grow never shrinks")
b.grow(5)
check(b.val.shape == (4, 5) and b.val[1, 0] == 5.0 and not b.val[:, 3:].any() and not b.ts[:, 3:].any(), "grow keeps the state")
v0, t0_ = b.val.copy(), b.ts.copy()
keep = np.array([True, False, True, False, True])
b.remap(keep)
check(b.val.shape == (4, 3) and np.array_equal(b.val, v0[:, keep]) and np.array_equal(b.ts, t0_[:, keep]),
      "remap: the kept positions' state, in order")
b.grow(3)
v1 = b.val.copy()
b.remap(np.array([False, True, True, True, False, True]))     # registry grew past the state since its last window
check(b.val.shape == (4, 2) and np.array_equal(b.val, v1[:, 1:3]), "remap with a longer keep mask: positions beyond the state stay new")
b.grow(4)
check(b.val.shape == (4, 4) and not b.val[:, 2:].any(), "... and are zero after growing to the compacted registry")
b.reset()
check(b.val.shape == (4, 0) and b.ts.shape == (4, 0), "reset: empty state")

# breadth_node_scores with controlled event scores (a stand-in model: score per window edge)
class FixedScores:
    def __init__(self, by_edge):
        self.by_edge = np.asarray(by_edge, dtype=np.float64)

    def edge_scores(self, w, K):
        p, x, _, e = edge_events(w, K)
        return p, x, e, self.by_edge[e]


bp = P("bp-wide", "/usr/bin/python3", "python3 x.py")
bc = P("bp-child", "/usr/bin/id", "id")
bq = P("bp-one", "/usr/bin/find", "find /")
evs = [(bp, "CLONE", bc), (bp, "CONNECT", N("n:bp", "198.51.100.9", 8443)), (bp, "WRITE", F("f:bp-w", "/var/tmp/bp.out")),
       (F("f:bp-r", "/etc/bp.conf"), "READ", bp), (F("f:bq-r", "/srv/odd/file"), "READ", bq)]
wb = window(reg, evs, t0=3 * 10**9)
st8 = Breadth(10.0, 4.0, 4 * 3600 * 10**9)
own, es = breadth_node_scores(FixedScores([8.0, 8.0, 8.0, 8.0, 60.0]), wb, K, len(reg), st8)
g = reg.get
check(abs(own[g("bp-wide")] - 16.0) < 1e-9, f"moderate events (8 nats) in four kinds of activity add up: 4 x (8 - 4) = {own[g('bp-wide')]:.1f}")
check(abs(own[g("bp-one")] - 6.0) < 1e-9, f"one extreme event (60 nats) scores at most cap - floor ({own[g('bp-one')]:.1f})")
check(abs(own[g("bp-child")] - 4.0) < 1e-9, "a started process gets its own view of the start (process group)")
check(own[g("n:bp")] == 8.0 and own[g("f:bp-w")] == 8.0 and own[g("f:bq-r")] == 10.0,
      "objects: their largest event score, capped (no floor)")
check(es.tolist() == [8.0, 8.0, 8.0, 8.0, 60.0], "edges keep their raw (uncapped) scores")
check(st8.val.shape[1] == len(reg), "the state grew with the registry")
own2, _ = breadth_node_scores(FixedScores([5.0]), window(reg, [(bq, "CONNECT", N("n:bq", "198.51.100.10", 8443))], t0=4 * 10**9),
                              K, len(reg), st8)
check(abs(own2[g("bp-one")] - 7.0) < 1e-9 and own2[g("bp-wide")] == 0.0,
      "carried across windows: the earlier extreme read and the new connection add up; untouched processes score 0 in this window")
own3, es3 = breadth_node_scores(FixedScores([]), Window(0, 1, np.zeros(0, np.int64), np.zeros(0, np.int64), np.zeros(0, np.int64),
                                                        np.zeros(0, np.int64), []), K, len(reg), st8)
check(not own3.any() and len(es3) == 0, "an empty window scores nothing")
# with the real model: one strange start scores at most cap - floor for the starting process, the raw score stays on the edge
ng5, ch5 = P("ng-t5", "/usr/sbin/nginx", "nginx: worker"), P("sh-t5", "/tmp/.x/payload", "/tmp/.x/payload")
w5 = window(reg, [(ng5, "CLONE", ch5)], t0=5 * 10**9)
own5, es5 = breadth_node_scores(m, w5, K, len(reg), Breadth(10.0, 4.0, 4 * 3600 * 10**9))
check(es5[0] > 10.0 and own5[reg.get("ng-t5")] <= 6.0 + 1e-9,
      f"real model: a web server starting a program from /tmp ({es5[0]:.1f} nats) gives the server {own5[reg.get('ng-t5')]:.1f} <= cap - floor")

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
                  orthrus_hid_dim=16, orthrus_out_dim=16, orthrus_epochs=2, calibration_budget=2,
                  d3_breadth=True, layer_novelty=False, learned_daily_budget=20)   # the 0.8 configuration (not the default)
_d = TrainConfig()
check(_d.layer_novelty is True and _d.d3_breadth is False and _d.detector3 is True,
      "defaults after the 0.8 held-out run: layer 1 on, detector-3 breadth off (available per endpoint)")
check(_d.learned_daily_budget == 0 and _d.repeat_corroborations == 1 and _d.near_alert_score == "own",
      "0.9 defaults: no learned-only alerts, one corroborated repeat run per program and day, near-alert on the own score")
out = os.path.join(tmp2, "bundle")
Trainer(st, days[:2], days[2], cfg, out).run({"endpoint": "t"})
import json
man = json.load(open(os.path.join(out, "manifest.json")))
cal = man["calibration"]
check("detector-3" in man["detectors"] and "detector-3" in man["requires"] and "propagation" in man["requires"],
      "0.7 bundle: detector-3 + propagation required of the runtime")
check(cal.get("final", {}).get("pending") is None and cal["final"]["threshold"] > 0, f"final threshold calibrated after propagation ({cal['final']['threshold']:.3f})")
check(man["layers"]["novelty"] is False and man["learned_policy"]["learned_alerts"] is True
      and man["learned_policy"].get("corroboration") == "threshold",
      "0.8 configuration: layer 1 off, learned alerts on, corroboration at the learned threshold")
cb = cal["detector-3"].get("breadth") or {}
check("detector-3-breadth" in man["requires"] and cb.get("cap") == 10.0 and cb.get("floor") == 4.0 and cb.get("horizon_s") == 14400.0,
      f"0.8 bundle: breadth calibrated with cap, floor, horizon and required of the runtime ({cb})")
check(cb.get("threshold", 0) >= 6.0 - 1e-9, f"breadth threshold never below cap - floor ({cb.get('threshold')})")
json_cal = json.load(open(os.path.join(out, "calibration.json")))
check(json_cal["detector-3"].get("breadth") == cb, "calibration.json carries the same breadth calibration as the manifest")
rtc = Runtime(out, st.load_registry(), device="cpu")
check(abs(rtc.corroboration - 1.0) < 1e-3 and abs(rtc.policy.corroboration - 1.0) < 1e-3, "the runtime corroborates only above the learned threshold")
check(rtc.breadth is not None and rtc.thr3b == cb["threshold"] and (rtc.breadth.cap, rtc.breadth.floor, rtc.breadth.horizon_ns)
      == (10.0, 4.0, 14400 * 10**9), "the runtime loads the breadth calibration")
# trainer and runtime compute the same breadth evidence: the validation day replayed through the runtime gives the
# trainer's threshold (the runtime's r3 is the evidence over that threshold)
rtc.reset(at="validation")
bb_rt = np.zeros(len(rtc.reg))
seen_rt = np.zeros(len(rtc.reg), bool)
for w in st.windows(days[2]):
    r = rtc.score(w)
    np.maximum.at(bb_rt, r.node_ids, r.r3 * rtc.thr3b)
    seen_rt[r.node_ids] = True
tb_rt = max(top_threshold(bb_rt[seen_rt], cfg.calibration_budget), 6.0)
check(abs(tb_rt - cb["threshold"]) < 1e-6, f"runtime replay of the validation day reproduces the trainer's breadth threshold ({tb_rt:.4f} vs {cb['threshold']:.4f})")
# the same with a validation day that has unusual activity (an attack in it): the trainer's breadth evidence per node
# (its in-memory model) = the runtime's (the saved model, through Runtime.score)
import pdp_engine.trainer as T_
stc = WindowStore(os.path.join(tmp2, "basec"))
regc, daysc = Registry(), []
for d in range(3):
    evc = activity(T0 + d * 86400 * 10**9, 40, f"c{d}", attack=(d == 2))
    for ents, _ in evc:
        for x in ents:
            lookup[x.uuid] = x
    stc.add_day(f"2026-02-0{d + 1}", ingest_day(regc, [e for _, e in evc], lookup, window_ns=10 * MIN))
    daysc.append(f"2026-02-0{d + 1}")
stc.save_registry(regc)
_bns, bb_tr = T_.breadth_node_scores, {}


def _record(model, w, K, n, state):        # the trainer's breadth evidence per node (max over the validation day)
    own, es = _bns(model, w, K, n, state)
    bb_tr["v"] = np.maximum(bb_tr.get("v", np.zeros(n)), own)
    return own, es


T_.breadth_node_scores = _record
try:
    outc = os.path.join(tmp2, "bundlec")
    Trainer(stc, daysc[:2], daysc[2], cfg, outc).run({"endpoint": "t"})
finally:
    T_.breadth_node_scores = _bns
rcc = Runtime(outc, stc.load_registry(), device="cpu")
rcc.reset(at="validation")
bbc = np.zeros(len(rcc.reg))
for w in stc.windows(daysc[2]):
    r = rcc.score(w)
    np.maximum.at(bbc, r.node_ids, r.r3 * rcc.thr3b)
bv = bb_tr.get("v", np.zeros(0))
check(len(bv) == len(bbc) and np.allclose(bv, bbc) and bv.max() > 6.0,
      f"trainer and runtime: the same breadth evidence for every node of the validation day ({(bv > 0).sum()} nodes > 0, max {bv.max():.2f}, "
      f"max diff {np.abs(bv - bbc).max() if len(bv) == len(bbc) else -1:.1e})")
rtc.reset(at="validation")
check(rtc.breadth.val.shape[1] == 0, "reset() clears the breadth state")
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
check(man["learned_policy"].get("policy") == "0.9" and rt.daily_budget == 20, "a 0.9 bundle keeps the budget it was trained with")
_m = json.load(open(os.path.join(out, "manifest.json")))
_old = dict(_m, learned_policy={k: v for k, v in _m["learned_policy"].items() if k != "policy"})
json.dump(_old, open(os.path.join(out, "manifest.json"), "w"))
check(Runtime(out, regs, device="cpu").daily_budget == 0 and Runtime(out, regs, device="cpu", daily_budget=7).daily_budget == 7,
      "a bundle trained before 0.9 (budget 20 recorded) gets the 0.9 default 0; an endpoint setting still overrides")
json.dump(_m, open(os.path.join(out, "manifest.json"), "w"))
check(len(alerted) <= 25, f"few alerts on an otherwise ordinary day ({len(alerted)})")
check(r3max > 1.0, f"detector-3 scores the attack above its threshold (max ratio {r3max:.1f})")

# r3 in the 0.8 runtime = breadth_node_scores over the breadth threshold (processes and objects), with the state
# carried across windows
regx = st.load_registry()
for ents, _ in ev:
    for x in ents:
        regx.add(x)
rtx = Runtime(out, regx, device="cpu", keep_reset_state=False)
Kx = rtx.bm.keys(regx)
stx = Breadth(10.0, 4.0, 14400 * 10**9)
stx_d = WindowStore(os.path.join(tmp2, "testx"))
stx_d.add_day("2026-01-06", ingest_day(regx, [e for _, e in ev], lookup, window_ns=10 * MIN))
dmax, nwin = 0.0, 0
for w in stx_d.windows("2026-01-06"):
    r = rtx.score(w)
    own_x, _ = breadth_node_scores(rtx.bm, w, Kx, len(regx), stx)
    dmax = max(dmax, float(np.abs(r.r3 - own_x[r.node_ids] / rtx.thr3b).max()) if len(r.r3) else 0.0)
    nwin += 1
check(nwin >= 2 and dmax < 1e-9, f"runtime r3 = breadth evidence / breadth threshold, state carried over {nwin} windows (max diff {dmax:.1e})")
# compaction keeps the breadth state aligned with the registry
n_before = len(regx)
keepx = rtx.compaction_keep(now_ns=T0 + 7 * 86400 * 10**9, max_age_ns=10**18)
keepx[np.arange(n_before) % 3 == 1] = False          # drop every third entity (more than compaction_keep would)
vb, tb_ = rtx.breadth.val[:, :n_before].copy(), rtx.breadth.ts[:, :n_before].copy()
o2n = rtx.compact(keepx)
check(rtx.breadth.val.shape[1] == len(regx) == int(keepx.sum()) and np.array_equal(rtx.breadth.val, vb[:, keepx])
      and np.array_equal(rtx.breadth.ts, tb_[:, keepx]), f"compaction: breadth state remapped with the registry ({n_before} -> {len(regx)})")
check(all(rtx.breadth.val[:, o2n[i]].tolist() == vb[:, i].tolist() for i in range(n_before) if o2n[i] >= 0 and vb[:, i].any()),
      "compaction: every kept process keeps its own breadth state")
try:
    for w in stx_d.windows("2026-01-06"):
        pass
    wnew = window(regx, [(P("p:after", "/usr/bin/bash", "bash"), "CONNECT", N("net:203.0.113.5:9999", "203.0.113.5", 9999))],
                  t0=T0 + 7 * 86400 * 10**9)
    rtx.score(wnew)
    check(rtx.breadth.val.shape[1] == len(regx), "after compaction the state grows with the registry again")
except Exception as e:  # noqa
    check(False, f"scoring after compaction: {type(e).__name__}: {e}")

# manifest requires: a runtime without the feature (a 0.7 agent) refuses breadth bundles
from pdp_engine import bundle as B_
check(B_.requirements("none", "weighted", detector3=True, propagation=True, breadth=True)[-1] == "detector-3-breadth"
      and "detector-3-breadth" not in B_.requirements("none", "weighted", detector3=True, propagation=True), "requirements(breadth=)")
B_.check_requires(man)
check("detector-3-breadth" in B_.SUPPORTED_FEATURES, "this runtime supports detector-3-breadth")
saved = set(B_.SUPPORTED_FEATURES)
B_.SUPPORTED_FEATURES.discard("detector-3-breadth")
try:
    B_.check_requires(man)
    check(False, "a 0.7 runtime refuses a breadth bundle")
except ValueError as e:
    check("detector-3-breadth" in str(e), "a 0.7 runtime refuses a breadth bundle (check_requires)")
finally:
    B_.SUPPORTED_FEATURES.clear(); B_.SUPPORTED_FEATURES.update(saved)

# a 0.7-style bundle (d3_breadth off) runs the 0.7 path unchanged
b7s = os.path.join(tmp2, "b7s")
cfg7 = TrainConfig(**{**cfg.__dict__, "d3_breadth": False})
Trainer(st, days[:2], days[2], cfg7, b7s).run({"endpoint": "t"})
m7s = json.load(open(os.path.join(b7s, "manifest.json")))
check("breadth" not in m7s["calibration"]["detector-3"] and "detector-3-breadth" not in m7s["requires"] and "detector-3" in m7s["requires"],
      "d3_breadth off: no breadth calibration, not required (0.7 agents load it)")
reg7 = st.load_registry()
for ents, _ in ev:
    for x in ents:
        reg7.add(x)
rt7s = Runtime(b7s, reg7, device="cpu")
check(rt7s.breadth is None and rt7s.thr3b is None, "the runtime has no breadth state for a bundle without it")
K7 = rt7s.bm.keys(reg7)
st7 = WindowStore(os.path.join(tmp2, "test7"))
st7.add_day("2026-01-06", ingest_day(reg7, [e for _, e in ev], lookup, window_ns=10 * MIN))
d7 = 0.0
for w in st7.windows("2026-01-06"):
    r = rt7s.score(w)
    o7, _ = rt7s.bm.node_scores(w, K7, len(reg7))
    want = o7 / np.where(K7.isproc[:len(reg7)], rt7s.thr3[0], rt7s.thr3[1])
    d7 = max(d7, float(np.abs(r.r3 - want[r.node_ids]).max()) if len(r.r3) else 0.0)
check(d7 < 1e-9, f"0.7 path: r3 = per-node maximum over the proc / obj thresholds (max diff {d7:.1e})")
rt7s.reset()
c7 = Runtime(b7s, st.load_registry(), device="cpu", keep_reset_state=False)
c7.compact(np.ones(len(c7.reg), bool))
check(c7.breadth is None, "reset() / compact() without breadth state")

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
check("detector-3-breadth" in m7["requires"] and m7["calibration"]["detector-3"].get("breadth") and rt7.breadth is not None,
      "upgrade_bundle_07 with the 0.8 configuration adds breadth (and requires it)")
check(m7["layers"]["novelty"] is False, "upgrade: layers re-fitted with the 0.8 configuration (layer 1 off)")
# 0.7 -> 0.8: upgrading a bundle that already has detector-3 (the d3_breadth-off one above)
b8 = os.path.join(tmp2, "b8")
upgrade_bundle_07(b7s, b8, st, cfg)
m8 = json.load(open(os.path.join(b8, "manifest.json")))
check(m8["requires"].count("detector-3") == 1 and m8["requires"].count("propagation") == 1 and "detector-3-breadth" in m8["requires"],
      f"0.7 -> 0.8 upgrade: requires {m8['requires']}")
check(abs(m8["calibration"]["fusion"]["budget_threshold"] - m7s["calibration"]["fusion"]["budget_threshold"]) < 1e-6,
      f"0.7 -> 0.8 upgrade: the fusion budget threshold comes from detectors 1-2 only, not the source's 0.7 final score "
      f"({m8['calibration']['fusion']['budget_threshold']:.4f} vs {m7s['calibration']['fusion']['budget_threshold']:.4f})")
check(m8["detectors"]["detector-3"]["budget"] == cfg.calibration_budget and m8["calibration"]["final"].get("pending") is None,
      "0.7 -> 0.8 upgrade: detector-3 re-fitted and the final threshold calibrated")
b8n = os.path.join(tmp2, "b8n")
upgrade_bundle_07(b8, b8n, st, TrainConfig(**{**cfg.__dict__, "d3_breadth": False, "propagation": False}))
m8n = json.load(open(os.path.join(b8n, "manifest.json")))
check("detector-3-breadth" not in m8n["requires"] and "propagation" not in m8n["requires"] and "propagation" not in m8n["calibration"]
      and "detector-3" in m8n["requires"], f"upgrade with breadth / propagation off drops their requires and calibration ({m8n['requires']})")

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

# 0.8 learning integrity: the entity an unreleased alert was raised on stays out of detector-3's counts on retrain,
# whatever layer raised it (with layer 1 off, a new program is often caught by the learned layer alone)
from pdp_server.learning import exclude_nodes
rege = Registry()
for u, t, l in (("p1", "subject", "subject /usr/bin/firefox firefox"), ("p2", "subject", "subject /usr/bin/firefox firefox"),
                ("f1", "file", "file /tmp/x"), ("n1", "netflow", "netflow 203.0.113.9 443")):
    rege.add(Entity(u, t, l))
check(exclude_nodes(rege, {"nodes": ["p2", "missing"]}) == [rege.get("p2")],
      "alerted process instance excluded alone (other instances of the program and unknown uuids are not)")
got = exclude_nodes(rege, {"programs": [], "addresses": ["203.0.113.9"], "nodes": ["f1"]})
check(sorted(got) == sorted([rege.get("f1"), rege.get("n1")]), f"alerted entities and excluded addresses together ({got})")

shutil.rmtree(tmp, ignore_errors=True)
shutil.rmtree(tmp2, ignore_errors=True)
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
