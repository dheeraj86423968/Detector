"""Living-off-the-land counterfactual (artifacts/lotl_paper/PROTOCOL.md): relabel the attacker's new programs in the
test period as the host's most frequent baseline program of the same kind. A pure relabelling of process entities:
no event, edge, timestamp, file entity or network entity changes, and every node keeps its uuid (so the ground truth
stays attached to the same nodes).

build(S, reg, bdir, N, test_nodes) -> (relabel {node id: new label}, report dict). The caller applies the relabelling
to the registry BEFORE the Runtime is built, so detector-1/2 node features (word2vec of the label), detector-3 keys
(behaviour.entity_keys of the label), layer 1 (executable(label)) and layer 2 (program names in rule keys, per-key
thresholds, interpreter / script detection) all see the new identity."""
import json, re
from collections import Counter
from pdp_engine.layers import DeterministicLayers, INTERPRETER, UNKNOWN_PROGRAM, executable, program_name
from pdp_engine.schema import Entity

WIN_SHELLS = {"cmd", "command"}     # Windows command shells (layers.INTERPRETER lists script interpreters only)
SCRIPT_EXT = re.compile(r"\.(sh|bash|py|pyw|pl|rb|php|ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd)$", re.I)


def kind_of(key: str) -> str:
    """'shell' for a shell, interpreter or script host (layers.INTERPRETER, the names layer 2 treats as interpreters,
    plus cmd / command) or a program that is itself a script file; else 'process'."""
    base = key.replace("\\", "/").replace('"', "").replace("'", "").rstrip("/").rsplit("/", 1)[-1]
    name = re.sub(r"\.exe$", "", base.casefold())
    return "shell" if (INTERPRETER.match(name) or name in WIN_SHELLS or SCRIPT_EXT.search(base)) else "process"


def build(S, reg, bdir, N, test_nodes):
    lay = DeterministicLayers.load(bdir, N)
    nov = lay.novelty
    fp, bs = nov.full_paths, getattr(nov, "backslash_paths", False)
    known_raw = set(json.load(open(f"{bdir}/layers.json"))["known_executables"])
    ents = reg.entities

    def exe_of(lab):                    # what layer 1 reads (the bundle's own parse settings)
        return executable(lab, fp, bs)

    def exe_full(lab):                  # the program as recorded (Windows paths with spaces kept whole, either slash)
        return executable(lab, True, True)

    # baseline frequency: process entities of the bundle's registry (ids < N: the baseline period) whose program,
    # as layer 1 reads it, is in the bundle's known_executables (layer 1's baseline = training days); counted by the
    # program as recorded (full path), so a 'c:\\program files\\...' program is itself, not layer 1's cut 'c:\\program'
    cnt, spell = Counter(), {}
    for i in range(min(N, len(ents))):
        e = ents[i]
        if e.ntype != "subject":
            continue
        x = exe_of(e.label)
        if x in UNKNOWN_PROGRAM or x not in known_raw:
            continue
        xf = exe_full(e.label)
        k = nov.key(xf)
        cnt[k] += 1
        spell.setdefault(k, Counter())[xf] += 1

    def ranked(kind):
        ks = [k for k in cnt if kind is None or kind_of(k) == kind]
        return sorted(ks, key=lambda k: (-cnt[k], k))

    # target programs: unseen in the baseline (layer 1's own test, fleet prevalence ignored) and run by a GT node
    tkeys = {}
    for u in S.allgt:
        i = reg.get(u)
        if i is None or i not in test_nodes or ents[i].ntype != "subject":
            continue
        x = exe_of(ents[i].label)
        if nov.is_known(x):
            continue
        tkeys.setdefault(nov.key(x), []).append(i)
    tnames = {program_name(k) for k in tkeys}
    tnames_nopath = {program_name(k) for k in tkeys if "/" not in k}

    def target_of(x):
        k = nov.key(x)
        if k in tkeys:
            return k
        n = program_name(k)
        if ("/" not in k and n in tnames) or n in tnames_nopath:
            return next(t for t in sorted(tkeys) if program_name(t) == n)
        return None

    # replacement per target: most frequent baseline program of the same kind (ties: smallest key); its most
    # frequent raw spelling (ties: smallest); a candidate whose relabelled label layer 1 would not read back as a
    # known program is skipped (spelling check)
    def make_label(lab, okey, new):
        oname = program_name(okey)
        parts = lab.split(" ", 2)
        if len(parts) > 1 and parts[1] not in UNKNOWN_PROGRAM:
            x = exe_full(lab)
            head = "subject " + x
            tail = lab[len(head):].lstrip(" ") if lab.startswith(head) else (parts[2] if len(parts) > 2 else "")
            pre = "subject " + new
        else:                                   # no image path recorded: the program is the first command token
            rest = parts[2].split(" ", 1) if len(parts) > 2 else [""]
            tail = rest[1] if len(rest) > 1 else ""
            pre = "subject None " + new
        nbase = new.replace("\\", "/").rsplit("/", 1)[-1]
        toks = []
        for t in tail.split(" ") if tail else []:
            core = t.strip("\"'")
            if core and core not in UNKNOWN_PROGRAM and program_name(nov.key(core)) == oname:
                rep = new if ("/" in core or "\\" in core) else nbase
                if not re.search(r"\.exe$", core, re.I):
                    rep = re.sub(r"\.exe$", "", rep, flags=re.I)
                t = t.replace(core, rep)
            toks.append(t)
        return pre + ((" " + " ".join(toks)) if toks else "")

    repl, report = {}, {"targets": []}
    for k in sorted(tkeys):
        kd = kind_of(k)
        cands = ranked("shell") if kd == "shell" else []
        cands = cands + [c for c in ranked(None) if c not in cands]
        chosen = None
        sample = ents[tkeys[k][0]].label
        for c in cands:
            sp = sorted(spell[c].items(), key=lambda z: (-z[1], z[0]))[0][0]
            if '"' in sp or "'" in sp:      # a malformed recording (quoted path cut at a space), not a program
                continue
            nl = make_label(sample, k, sp)
            if nov.is_known(exe_of(nl)) and nov.key(exe_full(nl)) == c:
                chosen = (c, sp)
                break
        repl[k] = chosen
        report["targets"].append({"key": k, "kind": kd, "gt_nodes": len(tkeys[k]), "replacement_key": chosen[0] if chosen else None,
                                  "replacement": chosen[1] if chosen else None,
                                  "fallback_to_process": bool(chosen and kd == "shell" and kind_of(chosen[0]) != "shell"),
                                  "baseline_runs": cnt.get(chosen[0], 0) if chosen else 0})

    relabel, per = {}, Counter()
    for i in sorted(test_nodes):
        e = ents[i]
        if e.ntype != "subject":
            continue
        x = exe_of(e.label)
        if nov.is_known(x):
            continue
        k = target_of(x)
        if k is None or repl.get(k) is None:
            continue
        relabel[i] = make_label(e.label, k, repl[k][1])
        per[k] += 1
    for t in report["targets"]:
        t["renamed_nodes"] = per.get(t["key"], 0)
    # check: no renamed node is new to layer 1 any more
    bad = [i for i, l in relabel.items() if not nov.is_known(exe_of(l))]
    report.update(renamed_nodes=len(relabel), renamed_gt=sum(1 for i in relabel if ents[i].uuid in S.allgt),
                  still_unknown=len(bad), baseline_programs=len(cnt), baseline_processes=int(sum(cnt.values())),
                  top_shell=(ranked("shell")[:1] or [None])[0], top_process=(ranked(None)[:1] or [None])[0],
                  examples=[{"before": ents[i].label[:160], "after": relabel[i][:160], "gt": ents[i].uuid in S.allgt}
                            for i in list(relabel)[:3]])
    return relabel, report


def apply(reg, relabel):
    """Replace the labels in place (same uuid, type, display): the registry's ids and uuids are unchanged."""
    for i, lab in relabel.items():
        e = reg.entities[i]
        reg.entities[i] = Entity(e.uuid, e.ntype, lab, e.display)
