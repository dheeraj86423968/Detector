"""Real agent replay of the 16 lab sets (cross-check of the lab_v10 console import): one `replay10-*` benchmark endpoint
per set, through the whole product path - enrolment, baseline replay and upload, server ingest, GPU training, signed
bundle, local scoring by the agent, alerts to the server.

  python3 artifacts/lab_v10/replay/replay10.py run [SET ...]      (all 16 by default; runs on the host, uses docker)
  python3 artifacts/lab_v10/replay/replay10.py status

Input per set:
  * db-replay (raw stream, exactly what the lab's windows were built from): the seven DARPA TC E3 / OpTC research
    databases, and ATLASv2 h1/h2 from atlasv2_edr with each host's node partition (EDR translation);
  * store-replay (the lab's stored, fused edges; raw data no longer exists): CARBANAKv2 h1-h5, TRACE E3, THEIA E5.
Days, baseline length and per-set training settings are the lab's (sets10.json; the original benchmark endpoints'
`train` settings for THEIA E3 and OpTC). Fleets as in the lab (eval13_fleets), under replay10-* labels so the lab10
endpoints are not part of them.

Two phases, so fleet prevalence sees what it saw in the lab (every member's baseline known before any test day is
scored): phase 1 replays each set's baseline days only and stops once the bundle is loaded; phase 2, after every
member of the fleet has its bundle, restarts the agent with all days (the agent resumes after its baseline days).
The image is pdp/server:$REPLAY_IMAGE (default v101rc: 0.10 + the store-replay source); production is not changed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SETS = json.load(open(os.path.join(HERE, "..", "import", "sets10.json")))
IMAGE = "pdp/server:" + os.environ.get("REPLAY_IMAGE", "v101rc")
WORK = os.environ.get("REPLAY_WORK", os.path.join(HERE, "work"))
PAR1 = int(os.environ.get("REPLAY_PAR1", "2"))     # agents replaying baselines at once
PAR2 = int(os.environ.get("REPLAY_PAR2", "1"))     # agents scoring test days at once (GPU)

DB = {"CADETS_E3": "cadets_e3", "THEIA_E3": "theia_e3", "CLEARSCOPE_E3": "clearscope_e3",
      "FIVEDIRECTIONS_E3": "fivedirections_e3", "OPTC_H201": "optc_201", "OPTC_H501": "optc_501", "OPTC_H051": "optc_051"}
# the original benchmark endpoints' training settings (darpa-theia-e3, darpa-optc-*), which the lab bundles came from
TRAIN = {"THEIA_E3": {"velox_lr": 0.001, "velox_out_dim": 320, "orthrus_hid_dim": 128, "orthrus_out_dim": 128},
         "OPTC_H051": {"velox_lr": 0.001, "velox_out_dim": 320, "orthrus_hid_dim": 128, "orthrus_out_dim": 128},
         "OPTC_H201": {"velox_lr": 0.001, "velox_out_dim": 128, "orthrus_hid_dim": 128, "orthrus_out_dim": 128},
         "OPTC_H501": {"velox_lr": 0.001, "velox_out_dim": 320, "orthrus_hid_dim": 256, "orthrus_out_dim": 256}}
STORE = {"CARBANAKV2_EDR-h1": "CARBANAKV2_EDR/h1", "CARBANAKV2_EDR-h2": "CARBANAKV2_EDR/h2", "CARBANAKV2_EDR-h3": "CARBANAKV2_EDR/h3",
         "CARBANAKV2_EDR-h4": "CARBANAKV2_EDR/h4", "CARBANAKV2_EDR-h5": "CARBANAKV2_EDR/h5", "TRACE_E3-trace": "TRACE_E3/trace",
         "THEIA_E5-theia": "THEIA_E5/theia"}
ATLAS = ("ATLASV2_EDR-h1", "ATLASV2_EDR-h2")
FLEET = {"CARBANAKV2": "replay10-carbanakv2", "OPTC": "replay10-optc", "ATLASV2": "replay10-atlasv2", "E3": "replay10-darpa-e3",
         "THEIA_E5": None}
VOL_DATA = "pdp_pdp_data"          # held-out stores and partitions: <volume>/heldout, mounted read-only at /replay


def log(m):
    print(time.strftime("%H:%M:%S"), m, flush=True)


def sh(*a, check=True, capture=True):
    r = subprocess.run(a, capture_output=capture, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(a[:6])}...: {r.stderr.strip()[-800:]}")
    return r.stdout.strip() if capture else ""


def psql(q):
    return sh("docker", "exec", "pdp-platform-db-1", "psql", "-U", "pdp", "-d", "platform", "-Atc", q)


def api():
    return next(n for n in sh("docker", "ps", "--format", "{{.Names}}").split() if n.startswith("pdp-api-"))


def name(s):
    return "replay10-" + s.lower().replace("_", "-")


def days_of(s, phase):
    v = SETS[s]
    base = list(v["train_days"]) + [v["val_day"]]
    return base if phase == 1 else base + [d for d in v["test_days"] if d not in base]


def source(s, phase):
    if s in DB:
        return {"kind": "db-replay", "database": DB[s], "host": "postgres", "days": days_of(s, phase)}
    if s in ATLAS:
        key = json.load(open(f"/var/lib/docker/volumes/{VOL_DATA}/_data/heldout/ATLASV2_EDR/{s[-2:]}/manifest.json"))["host_partition_key"]
        return {"kind": "db-replay", "database": "atlasv2_edr", "host": "postgres", "edr": True, "days": days_of(s, phase),
                "host_nodes": {"file": "/replay/ATLASV2_EDR/host_partition.npz", "key": key}}
    h = STORE[s]
    return {"kind": "store-replay", "stores": [f"/replay/{h}/baseline", f"/replay/{h}/eval-test"], "days": days_of(s, phase)}


def agent_cfg(s, phase):
    p = os.path.join(WORK, f"{name(s)}-p{phase}.json")
    json.dump({"server_url": "https://gateway", "agent_url": "https://gateway:8443", "data_dir": "/var/lib/pdp",
               "pki_dir": "/var/lib/pdp/pki", "day_tz": "US/Eastern", "status_interval": 10, "device": "cuda",
               "feat_device": "cuda", "source": source(s, phase)}, open(p, "w"), indent=1)
    os.chmod(p, 0o644)
    return p


def docker_run(s, phase, args, detach):
    cfg = agent_cfg(s, phase)
    base = ["docker", "run", "--network", "pdp_edge", "--gpus", "all", "--oom-score-adj", "800", "-m", os.environ.get("PDP_BENCH_MEM", "12g"),
            "-e", "PDP_AGENT_CONFIG=/etc/pdp/agent.json", "-v", f"{name(s)}:/var/lib/pdp", "-v", f"{cfg}:/etc/pdp/agent.json:ro",
            "--mount", f"type=volume,src={VOL_DATA},dst=/replay,readonly,volume-subpath=heldout"]
    if detach:
        sh("docker", "rm", "-f", name(s), check=False)
        sh("docker", "create", "--name", name(s), *base[2:], IMAGE, *args)
        sh("docker", "network", "connect", "shared_network", name(s))
        sh("docker", "start", name(s))
    else:
        return sh(*base[:2], "--rm", *base[2:], IMAGE, *args)


def endpoint(s):
    r = psql(f"SELECT id, phase, coalesce(current_bundle::text,''), config FROM endpoints WHERE name='{name(s)}' AND phase <> 'retired'")
    if not r:
        return None
    eid, ph, b, cfg = r.split("|", 3)
    return {"id": eid, "phase": ph, "bundle": b or None, "config": json.loads(cfg)}


def enrol(s):
    if endpoint(s):
        return
    v = SETS[s]
    cfg = {"tz": "US/Eastern", "baseline_days": len(v["train_days"])}
    if s in TRAIN:
        cfg["train"] = TRAIN[s]
    tok = json.loads(sh("docker", "exec", api(), "python", "-m", "pdp_server.tools.token", "--name", name(s), "--kind", "benchmark",
                        "--dataset", s, "--config", json.dumps(cfg)))
    docker_run(s, 1, ["agent", "enroll", tok["token"], "--ca-sha256", tok["ca_sha256"]], detach=False)
    fl = FLEET[v["fleet"]]
    if fl:      # the production token tool (0.10.0) does not take `fleet` yet (fixed in 0.10.1): set on the endpoint
        psql(f"UPDATE endpoints SET config = config || '{json.dumps({'fleet': fl})}'::jsonb WHERE name='{name(s)}'")
    log(f"{s}: enrolled as {name(s)} ({endpoint(s)['id']}), fleet {fl}")


def agent_state(s):
    code = ("import json; from pdp_agent.state import State; s = State('/var/lib/pdp/state.sqlite'); "
            "print(json.dumps({'done': s.get('replay_days_done') or [], 'bundle': s.get('bundle_id'), "
            "'unscored': s.unscored_count(), 'unreported': len(s.get('unreported') or [])}))")
    try:
        return json.loads(sh("docker", "exec", "-u", "pdp", name(s), "python", "-c", code))
    except (RuntimeError, ValueError):
        return None


def running(s):
    return sh("docker", "inspect", "-f", "{{.State.Running}}", name(s), check=False) == "true"


def save_log(s, phase):
    with open(os.path.join(WORK, f"{name(s)}-p{phase}.log"), "a") as f:
        subprocess.run(["docker", "logs", name(s)], stdout=f, stderr=subprocess.STDOUT)


def stop(s, phase):
    save_log(s, phase)
    sh("docker", "stop", "-t", "60", name(s), check=False)
    sh("docker", "rm", "-f", name(s), check=False)


def phase1_done(s):
    st = agent_state(s)
    return bool(st and st["bundle"] and set(days_of(s, 1)) <= set(st["done"]))


def phase2_done(s, prev):
    """All days replayed and nothing left to score or report (the still open last window aside: unchanged for 2 polls)."""
    st = agent_state(s)
    if not st or not set(days_of(s, 2)) <= set(st["done"]) or st["unreported"]:
        return False, st
    return prev is not None and prev.get("unscored") == st["unscored"] and set(prev.get("done", [])) == set(st["done"]), st


def run(sets):
    os.makedirs(WORK, exist_ok=True)
    marks = os.path.join(WORK, "done.json")
    done = json.load(open(marks)) if os.path.exists(marks) else {"p1": [], "p2": []}

    def mark(k, s):
        done[k].append(s)
        json.dump(done, open(marks, "w"), indent=1)

    for s in sets:
        enrol(s)
    # phase 1: baselines (PAR1 at a time)
    todo = [s for s in sets if s not in done["p1"]]
    active = []
    while todo or active:
        while todo and len(active) < PAR1:
            s = todo.pop(0)
            docker_run(s, 1, ["agent", "run"], detach=True)
            active.append(s); log(f"{s}: phase 1 (baseline {days_of(s, 1)}) started")
        time.sleep(60)
        for s in list(active):
            if phase1_done(s):
                stop(s, 1); active.remove(s); mark("p1", s)
                log(f"{s}: phase 1 done, bundle {endpoint(s)['bundle']}")
            elif not running(s):
                save_log(s, 1)
                raise SystemExit(f"{s}: agent stopped during phase 1 (log in {WORK})")
    # phase 2: every fleet member has its bundle (all sets of this run went through phase 1)
    todo = [s for s in sets if s not in done["p2"]]
    active, prev = [], {}
    while todo or active:
        while todo and len(active) < PAR2:
            s = todo.pop(0)
            docker_run(s, 2, ["agent", "run"], detach=True)
            active.append(s); prev[s] = None; log(f"{s}: phase 2 (test days {SETS[s]['test_days']}) started")
        time.sleep(120)
        for s in list(active):
            ok, st = phase2_done(s, prev[s])
            prev[s] = st
            if ok:
                stop(s, 2); active.remove(s); mark("p2", s)
                n = psql(f"SELECT count(*) FROM alerts a JOIN endpoints e ON e.id = a.endpoint_id WHERE e.name='{name(s)}'")
                log(f"{s}: phase 2 done, {n} alerts, {st['unscored']} events of the last open window not scored")
            elif not running(s):
                save_log(s, 2)
                raise SystemExit(f"{s}: agent stopped during phase 2 (log in {WORK})")
    log("all done")


def status():
    for s in SETS:
        ep = endpoint(s)
        st = agent_state(s) if running(s) else None
        n = psql(f"SELECT count(*) FROM alerts a JOIN endpoints e ON e.id = a.endpoint_id WHERE e.name='{name(s)}'") if ep else "-"
        print(f"{s:20s} {(ep or {}).get('phase', '-'):10s} bundle={'yes' if ep and ep['bundle'] else 'no ':3s} running={running(s)!s:5s} "
              f"alerts={n:>5s} {json.dumps(st) if st else ''}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "run":
        run(sys.argv[2:] or list(SETS))
    elif cmd == "status":
        status()
    else:
        print(__doc__); sys.exit(2)
