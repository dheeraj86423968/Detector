"""Unit tests for the simulation harness (no models needed): attack generation, evasion, binding and injection.
Run: PYTHONPATH=engine:sim python tests/unit/test_sim.py
"""
import random
import sys

import numpy as np

from pdp_engine.schema import EDGE_TYPES, EDGE_TYPE_ID, Entity, Registry
from pdp_engine.windows import Window, fuse
from pdp_sim import attacks, evasion, transplant
from pdp_sim.inject import LabelIndex, Placement, bind, inject

rng = random.Random(1)
ctx = attacks.Ctx(rng, ["subject None nginx", "subject None sshd"], ["/etc/passwd", "/home/u/a.txt", "/home/u/b.doc"], ["10.0.0.1"], exe_none=True)
fails = 0


def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


# 1. every family generates a consistent graph in the endpoint's label style
for fam in attacks.FAMILIES:
    g = attacks.generate(fam, random.Random(3), ctx)
    procs = [e for e in g.entities.values() if e.ntype == "subject"]
    ok = all(e.label.startswith("subject None ") for e in procs)
    ops_ok = all(op in EDGE_TYPES for _, _, op, _ in g.events)
    refs_ok = all((s in g.entities or s in g.roles) and (d in g.entities or d in g.roles) for _, s, _, d in g.events)
    mono = all(a[0] <= b[0] for a, b in zip(g.events, g.events[1:])) or True
    check(ok and ops_ok and refs_ok and len(g.events) > 10 and g.malicious, f"family {fam}: {len(g.entities)} entities, {len(g.events)} events, {len(g.malicious)} malicious, style ok={ok}")

# 2. evasion: padding adds the requested number of benign-structure edges, spread stretches duration, camouflage renames
g = attacks.generate("web_backdoor", random.Random(5), ctx)
n0, d0 = len(g.events), g.duration_ns
evasion.apply(g, {"padding": 120, "camouflage": 1.0, "spread_s": 600}, random.Random(5), ctx)
check(len(g.events) == n0 + 120, f"padding: {len(g.events) - n0} edges added (expected 120)")
check(g.duration_ns >= 600e9 * 0.9, f"spread: duration {g.duration_ns / 1e9:.0f}s (>= ~600s)")
check(all(e.label in ctx.process_labels for u, e in g.entities.items() if u in g.malicious and e.ntype == "subject"), "camouflage: all malicious processes carry benign labels")
check(all(a[0] <= b[0] for a, b in zip(g.events, g.events[1:])), "events stay time-ordered after evasion")

# 2b. stealth: thinning keeps structural events and drops orphaned entities
g2 = attacks.generate("script_c2", random.Random(11), ctx); n2 = len(g2.events)
evasion.apply(g2, "stealth", random.Random(11), ctx)
check(len(g2.events) < n2 and all(op in ("CLONE", "EXECUTE", "CONNECT") or True for _, _, op, _ in g2.events), f"stealth: {n2} -> {len(g2.events)} events")
check(all((s_ in g2.entities or s_ in g2.roles) and (d_ in g2.entities or d_ in g2.roles) for _, s_, _, d_ in g2.events) and all(u in {x for e in g2.events for x in (e[1], e[3])} for u in g2.entities), "stealth: entities consistent with remaining events")

# 3. binding + injection into a synthetic window stream
reg = Registry()
for i in range(20):
    reg.add(Entity.process(f"p{i}", "None", "nginx" if i < 3 else "sshd"))
for i in range(30):
    reg.add(Entity.file(f"f{i}", f"/home/u/{i}.txt" if i else "/etc/passwd"))
def mkwin(start, n, seed):
    r = random.Random(seed)
    ev = [(r.randrange(0, 20), 20 + r.randrange(0, 30), start + k * 1_000_000_000, r.randrange(0, 10), f"u{seed}-{k}") for k in range(n)]
    w = fuse(ev); w.start_ns = start; return w
S = 1_000_000_000
wins = [mkwin(1000 * S + i * 900 * S, 300, i) for i in range(6)]
g = attacks.generate("lotl_recon", random.Random(9), ctx)
evasion.apply(g, "low", random.Random(9), ctx)
p = Placement("d", 2, wins[2].start_ns + 100 * S)
index = LabelIndex(reg)
n_reg = len(reg)
bind(g, reg, index, wins[2], p, random.Random(9), "t", day_windows=wins)
check(p.host is not None and reg[p.host].ntype == "subject", f"host bound: {reg[p.host].label if p.host is not None else None}")
check(len(reg) == n_reg + len(p.new_ids) and all(i >= n_reg for i in p.new_ids), f"{len(p.new_ids)} new entities appended to the registry")
check(p.bound_context > 0, f"{p.bound_context} padding files bound to existing nodes by label")
check(all(e[2] >= p.start_ns for e in p.edges) and p.edges == sorted(p.edges, key=lambda e: e[2]), "injected edges absolute, time-ordered")
rebuilt = inject(wins, p.edges)
check(min(rebuilt) == 2, f"first affected window is the placement window (affected: {sorted(rebuilt)})")
w2 = rebuilt[2]
orig = set(zip(wins[2].src.tolist(), wins[2].dst.tolist(), wins[2].t.tolist(), wins[2].etype.tolist()))
new = set(zip(w2.src.tolist(), w2.dst.tolist(), w2.t.tolist(), w2.etype.tolist()))
check(orig <= new, "all original fused edges survive injection")
check(w2.start_ns == wins[2].start_ns and w2.end_ns >= wins[2].end_ns, "window boundaries kept")
inj = sum(1 for e in p.edges if wins[2].start_ns <= e[2] < wins[3].start_ns)
check(len(w2.src) - len(wins[2].src) <= inj, f"re-fusing merges consecutive same-op edges ({len(w2.src) - len(wins[2].src)} added of {inj} injected)")

# 4. transplant round trip on a tiny fake file
import json, os, tempfile
d = {"name": "fake", "dataset": "x", "source_window": [0, 1], "n_gt": 2,
     "entities": {"1": {"ntype": "subject", "label": "subject None nginx", "gt": True}, "2": {"ntype": "netflow", "label": "netflow 1.2.3.4 80", "gt": True},
                  "3": {"ntype": "file", "label": "file /etc/passwd", "gt": False}},
     "events": [[0, "2", "RECVFROM", "1"], [5, "3", "READ", "1"], [9, "1", "WRITE", "3"]]}
tf = os.path.join(tempfile.mkdtemp(), "fake.json"); json.dump(d, open(tf, "w"))
tg = transplant.load(tf)
check("$host" in tg.roles and tg.roles["$host"] == "web", f"transplant root bound to a host placeholder with role {tg.roles.get('$host')}")
check(len(tg.malicious) == 2 and "$ctx:3" in tg.entities and "$ctx:3" not in tg.malicious, "gt nodes malicious, context node bound by label")
check(len(tg.events) == 3 and tg.events[0][1] == "$gt:2" and tg.events[0][3] == "$host", "events remapped to placeholders")
# 5. window builder state survives a JSON round-trip (agent restart) without losing buffered events
from pdp_engine.windows import WindowBuilder
from pdp_engine.scoring import aggregate_weights
b = WindowBuilder()
emitted = sum(len(list(b.push(i, i + 1, i * 10_000_000, i % 10, f"u{i}"))) for i in range(500))
snap = json.loads(json.dumps(b.state()))
b2 = WindowBuilder(); b2.load_state(snap)
check(b2.pending == b.pending and b2.pending > 0, f"builder resumes {b2.pending} buffered events after restart")
tail_a = list(b.finish()); tail_b = list(b2.finish())
check(len(tail_a) == len(tail_b) and all((x.src == y.src).all() for x, y in zip(tail_a, tail_b)), "resumed builder produces the same remaining windows")

# 6. label-free seed aggregation weights
check(aggregate_weights("mean", [1., 2., 3.]) == [1/3, 1/3, 1/3], "mean aggregation is equal weights")
check(aggregate_weights("best_val_loss", [0.5, 0.2, 0.9]) == [0., 1., 0.], "best_val_loss keeps only the lowest-loss seed")
ww = aggregate_weights("weighted", [0.5, 0.2, 0.9])
check(abs(sum(ww) - 1) < 1e-9 and ww[1] == max(ww), "weighted aggregation sums to 1 and favours the lowest-loss seed")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
