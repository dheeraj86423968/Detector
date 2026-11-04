"""Background worker: Postgres-backed job queue (SKIP LOCKED). Job kinds:
  ingest  {date}      build the fused windows of one completed baseline day into the endpoint's window store
  train   {}          train detector-1 + detector-2 (k seeds), calibrate, sign and publish a bundle
  sim     {campaign_id} run an adversarial simulation campaign against the endpoint's bundle (sim/pdp_sim)
  command {...}       delivered to the agent via /status (left queued until the agent acknowledges)

Run: python -m pdp_server.worker [--kinds ingest,train] [--device cuda|cpu]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
import traceback

sys.path.insert(0, os.environ.get("PDP_ENGINE_PATH", "/opt/pdp/engine"))
sys.path.insert(0, os.environ.get("PDP_SIM_PATH", "/opt/pdp/sim"))
from pdp_engine.bundle import sha256  # noqa: E402
from pdp_engine.data import WindowStore, ingest_day  # noqa: E402
from pdp_engine.schema import Entity, Event, Registry  # noqa: E402
from pdp_engine.trainer import TrainConfig, Trainer  # noqa: E402

from . import db, pki  # noqa: E402

DATA_DIR = os.environ.get("PDP_DATA_DIR", "/data")
ATTACK_DIR = os.environ.get("PDP_ATTACK_DIR", "/opt/pdp/sim/attacks")


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", msg, flush=True)


def store_for(endpoint_id: str) -> WindowStore:
    return WindowStore(os.path.join(DATA_DIR, "endpoints", endpoint_id, "baseline"))


def load_registry(endpoint_id: str, store: WindowStore) -> Registry:
    if os.path.exists(os.path.join(store.root, "registry.json")):
        return store.load_registry()
    return Registry()


def telemetry_entities(endpoint_id: str) -> dict[str, Entity]:
    s = db.tschema(endpoint_id)
    with db.conn(db.TELEMETRY_DSN) as c:
        rows = db.q(c, f"SELECT uuid, ntype, label, display FROM {s}.entities ORDER BY dense_id")
    return {r["uuid"]: Entity(r["uuid"], r["ntype"], r["label"], r["display"] or {}) for r in rows}


def extend_registry(endpoint_id: str, reg: Registry) -> int:
    """Append the uploaded entities to the endpoint registry in the agent's dense-id order (contiguously from the
    current size). Node ids then equal the agent's own registry indices, which the detector-2 neighbour state in the
    bundle is keyed by — independently of event order, ties or the order days are ingested in."""
    s = db.tschema(endpoint_id)
    added = 0
    with db.conn(db.TELEMETRY_DSN) as c:
        rows = db.q(c, f"SELECT uuid, ntype, label, display, dense_id FROM {s}.entities WHERE dense_id >= %s ORDER BY dense_id", (len(reg),))
    for r in rows:
        if r["uuid"] in reg.ids:
            continue
        if r["dense_id"] != len(reg):    # not yet contiguous (an upload still in flight): stop, the next ingest continues
            log(f"registry {endpoint_id}: gap at dense id {len(reg)} (next uploaded is {r['dense_id']}); continuing later")
            break
        reg.add(Entity(r["uuid"], r["ntype"], r["label"], r["display"] or {}))
        added += 1
    return added


def day_bounds(date: str, tz: str = "UTC") -> tuple[int, int]:
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    d0 = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=ZoneInfo(tz))
    return int(d0.timestamp() * 1e9), int((d0 + timedelta(days=1)).timestamp() * 1e9)


def telemetry_events(endpoint_id: str, date: str, tz: str = "UTC"):
    """Events of one calendar day (in the endpoint's timezone) in time order."""
    t0, t1 = day_bounds(date, tz)
    s = db.tschema(endpoint_id)
    c = db.pool(db.TELEMETRY_DSN).getconn()
    try:
        cur = c.cursor(name=f"ingest_{date}")
        cur.itersize = 200_000
        cur.execute(f"SELECT ts_ns, src, op, dst, event_uuid FROM {s}.events WHERE ts_ns >= %s AND ts_ns < %s ORDER BY ts_ns, event_uuid", (t0, t1))
        for ts, src, op, dst, eu in cur:
            yield Event(int(ts), src, op, dst, eu)
        cur.close()
    finally:
        db.pool(db.TELEMETRY_DSN).putconn(c)


def ep_config(eid: str) -> dict:
    with db.conn() as c:
        return db.q(c, "SELECT config FROM endpoints WHERE id=%s", (eid,), one=True)["config"]


def window_ns(cfg: dict) -> int:
    return int(float(cfg.get("window_minutes", 15)) * 60 * 1_000_000_000)


def job_ingest(job: dict):
    eid, date = str(job["endpoint_id"]), job["params"]["date"]
    store = store_for(eid)
    reg = load_registry(eid, store)
    added = extend_registry(eid, reg)
    cfg = ep_config(eid)
    tz = cfg.get("tz", "UTC")
    stats = {}
    n = store.add_day(date, ingest_day(reg, telemetry_events(eid, date, tz), None, window_ns=window_ns(cfg), stats=stats))
    store.save_registry(reg)
    if stats.get("dropped"):
        log(f"ingest {eid} {date}: {stats['dropped']} events referenced entities not (yet) in the registry and were skipped")
    with db.conn(db.TELEMETRY_DSN) as c:
        n_events = db.q(c, f"SELECT count(*) AS n FROM {db.tschema(eid)}.events WHERE ts_ns >= %s AND ts_ns < %s", day_bounds(date, tz), one=True)["n"]
        if not ep_config(eid).get("retain_baseline_events", False):   # retention: raw events live only until they are windowed
            with c.cursor() as cur:
                cur.execute(f"DELETE FROM {db.tschema(eid)}.events WHERE ts_ns >= %s AND ts_ns < %s", day_bounds(date, tz))
    with db.conn() as c:
        db.q(c, "UPDATE baseline_days SET events=%s, windows=%s WHERE endpoint_id=%s AND date=%s", (n_events, n, eid, date))
        db.q(c, "UPDATE jobs SET progress=%s WHERE id=%s", (json.dumps({"windows": n, "events": n_events, "entities_added": added, "dropped": stats.get("dropped", 0)}), str(job["id"])))
        ep = db.q(c, "SELECT config, phase FROM endpoints WHERE id=%s", (eid,), one=True)
        done = db.q(c, "SELECT count(*) AS n FROM baseline_days WHERE endpoint_id=%s AND complete AND windows > 0", (eid,), one=True)["n"]
        db.q(c, "UPDATE endpoints SET baseline_days_done=%s WHERE id=%s", (done, eid))
        need = int(ep["config"].get("baseline_days", 7)) + 1  # train days + validation day
        # training starts only once all baseline days are ingested (days can complete faster than they ingest)
        if ep["phase"] == "baseline" and done >= need:
            db.q(c, "INSERT INTO jobs (id, endpoint_id, kind) VALUES (%s,%s,'train')", (pki.new_id(), eid))
            db.q(c, "UPDATE endpoints SET phase='training' WHERE id=%s", (eid,))
    log(f"ingest {eid} {date}: {n} windows ({done}/{need} days)")


# ---------------------------------------------------------------------------------------------- early models
# Detection does not wait for the full baseline: while an endpoint learns, a model is trained on whatever activity it
# has recorded so far - after 1 hour, after 6 hours, then once a day - and replaced by the final model when the
# baseline (7 days + 1 validation day) is complete. Agents from 0.3.3 detect with these early models while they keep
# uploading their baseline; older agents ignore them and start detecting with the final model, as before.
EARLY_MILESTONES_H = [1, 6] + [24 * d for d in range(1, 60)]
EARLY_MIN_WINDOWS = 4          # one hour of 15-minute windows: 3 to train on, 1 to calibrate on
# Which layers may alert from an early model (tools/maturity_eval.py, DARPA CADETS E3, all 3 attacks detected at
# every level): with 1 hour of baseline the data-flow rules gave 30 alerts (29 on the attack) while new-program and
# learned alerts were 10,742 and 170,389 - so models trained on less than a day alert from the rules only. From one
# day on all layers alert: 140 false alerts at 1 day, 66 at 3 days, 66 with the full week.
EARLY_RULES_ONLY_BELOW_H = 24
_last_milestone_check = 0.0


def baseline_hours(eid: str) -> float:
    """Recorded activity so far, in hours: ingested baseline days (their windows) plus the open day's raw events."""
    store = store_for(eid)
    n = sum(len(os.listdir(os.path.join(store.root, "windows", d))) for d in store.days())
    with db.conn(db.TELEMETRY_DSN) as c:
        t = db.q(c, f"SELECT min(ts_ns) AS lo, max(ts_ns) AS hi FROM {db.tschema(eid)}.events", one=True)
    open_h = (int(t["hi"]) - int(t["lo"])) / 3.6e12 if t and t["lo"] is not None else 0.0
    return n / 4.0 + open_h


def due_milestones(maturity: dict, hours: float) -> list[int]:
    """Milestones passed since the current model's. Compared with the milestone the model was trained for: its own
    baseline_hours can be a little below the milestone (windows are cut at 15 minutes), and comparing that queued
    the same milestone again every minute."""
    have = float(maturity.get("milestone_h") or maturity.get("baseline_hours") or 0)
    return [m for m in EARLY_MILESTONES_H if have < m <= hours]


def schedule_early_models():
    """Queue an early training job for each learning endpoint that has passed its next milestone."""
    global _last_milestone_check
    if time.time() - _last_milestone_check < 60:
        return
    _last_milestone_check = time.time()
    with db.conn() as c:
        eps = db.q(c, "SELECT e.id, e.config, b.manifest FROM endpoints e LEFT JOIN bundles b ON b.id=e.current_bundle "
                      "WHERE e.phase='baseline' AND e.kind='live' AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.endpoint_id=e.id "
                      "AND j.kind='train' AND j.state IN ('queued','running'))")
    for ep in eps:
        if (ep["config"] or {}).get("early_models") is False:
            continue
        eid = str(ep["id"])
        try:
            hours = baseline_hours(eid)
        except Exception as e:  # noqa - a missing telemetry schema etc. must not stop the worker
            log(f"early model check {eid}: {e}")
            continue
        due = due_milestones((ep["manifest"] or {}).get("maturity") or {}, hours)
        if due:
            with db.conn() as c:
                db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, params) VALUES (%s,%s,'train',%s)",
                     (pki.new_id(), eid, json.dumps({"early": True, "milestone_h": due[-1]})))
            log(f"early model for {eid}: {hours:.1f} h recorded, milestone {due[-1]} h queued")


def prune_early_bundles(eid: str):
    """Model files of superseded early models are deleted (a few hundred MB each); their database rows stay as the
    record of what was trained when. Final models are kept."""
    import shutil
    with db.conn() as c:
        rows = db.q(c, "SELECT b.id, b.path FROM bundles b JOIN endpoints e ON e.id=b.endpoint_id WHERE b.endpoint_id=%s "
                       "AND b.id <> coalesce(e.current_bundle, '00000000-0000-0000-0000-000000000000'::uuid) "
                       "AND (b.manifest->'maturity'->>'early')::boolean IS TRUE", (eid,))
    for r in rows:
        for ext in (".tar.gz", ".agent.tar.gz"):
            if os.path.exists(r["path"].rstrip("/") + ext):
                os.unlink(r["path"].rstrip("/") + ext)
        if os.path.isdir(r["path"]):
            shutil.rmtree(r["path"], ignore_errors=True)
            log(f"removed superseded early model {r['id']}")


def job_train_early(job: dict, device: str):
    """An early model from the activity recorded so far. Raw events are kept (the final model still needs them);
    the endpoint stays in its baseline phase."""
    import shutil
    from pdp_engine.data import WindowStore, ingest_day
    eid = str(job["endpoint_id"])
    base = store_for(eid)
    reg = load_registry(eid, base)
    extend_registry(eid, reg)
    bid = pki.new_id()
    work = os.path.join(DATA_DIR, "endpoints", eid, "early", bid)
    tmp = WindowStore(os.path.join(work, "open"))
    cfg = ep_config(eid)
    tz = cfg.get("tz", "UTC")
    done_days = sorted(base.days())        # ingested days are read as windows; raw events only after the last of them
    since = day_bounds(done_days[-1], tz)[1] if done_days else 0
    with db.conn(db.TELEMETRY_DSN) as c:
        t = db.q(c, f"SELECT min(ts_ns) AS lo, max(ts_ns) AS hi FROM {db.tschema(eid)}.events WHERE ts_ns >= %s", (since,), one=True)
    def open_events():   # the not yet ingested day(s), in time order
        if not t or t["lo"] is None:
            return
        cc = db.pool(db.TELEMETRY_DSN).getconn()
        try:
            cur = cc.cursor(name=f"early_{bid[:8]}")
            cur.itersize = 200_000
            cur.execute(f"SELECT ts_ns, src, op, dst, event_uuid FROM {db.tschema(eid)}.events WHERE ts_ns >= %s ORDER BY ts_ns, event_uuid", (since,))
            for ts, src, op, dst, eu in cur:
                yield Event(int(ts), src, op, dst, eu)
            cur.close()
        finally:
            db.pool(db.TELEMETRY_DSN).putconn(cc)
    stats = {}
    tmp.add_day("open", ingest_day(reg, open_events(), None, window_ns=window_ns(cfg), stats=stats))
    paths = [os.path.join(base.root, "windows", d, f) for d in done_days for f in sorted(os.listdir(os.path.join(base.root, "windows", d)))]
    paths += [os.path.join(tmp.root, "windows", "open", f) for f in sorted(os.listdir(os.path.join(tmp.root, "windows", "open")))]
    if len(paths) < EARLY_MIN_WINDOWS:
        shutil.rmtree(work, ignore_errors=True)
        log(f"early model {eid}: only {len(paths)} windows recorded; waiting for more activity")
        return
    n_val = max(1, int(round(len(paths) * 0.25)))         # the last quarter calibrates, the rest trains
    store = WindowStore(os.path.join(work, "store"))
    store.save_registry(reg)
    for label, ps in (("train", paths[:-n_val]), ("val", paths[-n_val:])):
        os.makedirs(os.path.join(store.root, "windows", label), exist_ok=True)
        for k, p in enumerate(ps):
            os.symlink(p, os.path.join(store.root, "windows", label, f"{k:05d}.npz"))
    last = list(store.windows("val"))[-1]
    hours = round(len(paths) / (3.6e12 / window_ns(cfg)), 1)
    overrides = dict(cfg.get("train", {}))
    overrides.pop("fusion_calibration", None)
    for k in ("orthrus_seeds", "fusion_weights"):
        if k in overrides:
            overrides[k] = tuple(overrides[k])
    out = os.path.join(DATA_DIR, "bundles", eid, bid)
    t0 = time.time()
    log(f"train {eid}: early model on {len(paths)} windows ({hours} h), {n_val} for calibration")
    if hours < EARLY_RULES_ONLY_BELOW_H:
        # rules-only model: the learned detectors only rank here, so they are trained minimally (minutes, not an hour,
        # on a busy host) - detection starts soon after the first hour
        overrides["alert_layers"] = ("rules",)
        overrides.setdefault("orthrus_seeds", (0,))
        overrides.setdefault("velox_runs", 1)
        overrides.setdefault("orthrus_epochs", 3)
        overrides.setdefault("velox_epochs", 3)
        overrides.setdefault("w2v_epochs", 10)
    Trainer(store, ["train"], "val", TrainConfig(device=device, **overrides), out).run(
        {"endpoint": eid, "bundle_id": bid, "window_ns": window_ns(cfg), "trained_on": device,
         "maturity": {"early": True, "baseline_hours": hours, "windows": len(paths), "trained_until_ns": int(last.end_ns),
                      "alert_layers": list(overrides.get("alert_layers") or ["novelty", "rules", "corroborated", "learned"]),
                      "milestone_h": (job.get("params") or {}).get("milestone_h")}})
    pki.sign_bundle(out)
    from .bundles import archive
    archive(out); archive(out, slim=True)
    digest = sha256(os.path.join(out, "manifest.json"))
    manifest = json.load(open(os.path.join(out, "manifest.json")))
    with db.conn() as c:
        db.q(c, "UPDATE jobs SET progress=%s WHERE id=%s", (json.dumps({"early": True, "windows": len(paths), "hours": hours,
                                                                         "seconds": round(time.time() - t0, 1)}), str(job["id"])))
        db.q(c, "INSERT INTO bundles (id, endpoint_id, job_id, path, sha256, manifest) VALUES (%s,%s,%s,%s,%s,%s)",
             (bid, eid, str(job["id"]), out, digest, json.dumps(manifest)))
        # a final model published meanwhile wins; otherwise the early model becomes current (phase unchanged)
        db.q(c, "UPDATE endpoints SET current_bundle=%s WHERE id=%s AND phase='baseline'", (bid, eid))
    shutil.rmtree(work, ignore_errors=True)
    prune_early_bundles(eid)
    log(f"train {eid}: early bundle {bid} published ({hours} h of activity)")


def job_train(job: dict, device: str):
    if (job.get("params") or {}).get("early"):
        return job_train_early(job, device)
    eid = str(job["endpoint_id"])
    store = store_for(eid)
    with db.conn() as c:
        ep = db.q(c, "SELECT config FROM endpoints WHERE id=%s", (eid,), one=True)
        rows = db.q(c, "SELECT date FROM baseline_days WHERE endpoint_id=%s AND complete ORDER BY completed_at NULLS LAST, date", (eid,))
    need = int(ep["config"].get("baseline_days", 7)) + 1
    days = sorted(str(r["date"]) for r in rows[:need])      # the first N+1 days completed, in calendar order
    days = [d for d in days if d in store.days()]
    if len(days) < 2:
        raise RuntimeError("need at least two ingested baseline days (train + validation)")
    train_days, val_day = days[:-1], days[-1]
    log(f"train {eid}: train days {train_days}, validation {val_day}")
    overrides = dict(ep["config"].get("train", {}))
    fusion_mode = overrides.pop("fusion_calibration", "fixed")   # "fixed" (2:1 / train.fusion_weights) | "simulation"
    if "orthrus_seeds" in overrides:
        overrides["orthrus_seeds"] = tuple(overrides["orthrus_seeds"])
    if "fusion_weights" in overrides:
        overrides["fusion_weights"] = tuple(overrides["fusion_weights"])
    cfg = TrainConfig(device=device, **overrides)
    bid = pki.new_id()
    out = os.path.join(DATA_DIR, "bundles", eid, bid)
    t0 = time.time()
    tz = ep["config"].get("tz", "UTC")
    Trainer(store, train_days, val_day, cfg, out).run({"endpoint": eid, "bundle_id": bid, "window_ns": window_ns(ep["config"]),
                                                      "trained_on": device,
                                                      "maturity": {"early": False, "baseline_days": len(train_days) + 1,
                                                                   "baseline_hours": 24.0 * (len(train_days) + 1),
                                                                   "trained_until_ns": day_bounds(val_day, tz)[1]}})
    with db.conn() as c:
        db.q(c, "UPDATE jobs SET progress=%s WHERE id=%s", (json.dumps({"train_days": train_days, "val_day": val_day, "seconds": round(time.time() - t0, 1)}), str(job["id"])))
    if fusion_mode == "simulation":
        # per-bundle fusion weights chosen on synthetic attacks injected into the benign validation day (no test data;
        # pdp_server.tools.calibrate_fusion, docs/BENCHMARK_E3.md)
        from pdp_server.tools.calibrate_fusion import apply_to_bundle, calibrate
        res = calibrate(store, out, device=device)
        apply_to_bundle(out, res)
        log(f"train {eid}: fusion calibrated by simulation -> weights {res['chosen']['weights']} (synthetic detection {res['chosen']['detection_rate']:.2f})")
    pki.sign_bundle(out)
    from .bundles import archive
    archive(out); archive(out, slim=True)
    digest = sha256(os.path.join(out, "manifest.json"))
    manifest = json.load(open(os.path.join(out, "manifest.json")))
    with db.conn() as c:
        db.q(c, "INSERT INTO bundles (id, endpoint_id, job_id, path, sha256, manifest) VALUES (%s,%s,%s,%s,%s,%s)", (bid, eid, str(job["id"]), out, digest, json.dumps(manifest)))
        db.q(c, "UPDATE endpoints SET current_bundle=%s, phase='protected' WHERE id=%s", (bid, eid))
    log(f"train {eid}: bundle {bid} published")
    prune_early_bundles(eid)
    if ep["config"].get("retain_baseline_events", False):
        return
    with db.conn(db.TELEMETRY_DSN) as c:   # retention: raw baseline events are not needed once the bundle exists
        with c.cursor() as cur:
            cur.execute(f"DELETE FROM {db.tschema(eid)}.events")
    log(f"train {eid}: raw baseline events dropped from the telemetry store (retention)")


class CombinedStore:
    """Baseline window store plus a per-bundle evaluation store (held-out days ingested for simulation)."""

    def __init__(self, base: WindowStore, extra: WindowStore | None):
        self.base, self.extra, self.root = base, extra, base.root

    def days(self):
        d = set(self.base.days())
        if self.extra:
            d |= set(self.extra.days())
        return sorted(d)

    def windows(self, date):
        if self.extra and date in self.extra.days():
            return self.extra.windows(date)
        return self.base.windows(date)

    def load_registry(self):
        if self.extra and os.path.exists(os.path.join(self.extra.root, "registry.json")):
            return self.extra.load_registry()
        return self.base.load_registry()


def eval_day_source(ep: dict, date: str):
    """Events of a held-out day for a benchmark endpoint: replayed from the research database named in its config."""
    cfg = ep["config"]
    if ep["kind"] != "benchmark" or not cfg.get("dataset"):
        raise RuntimeError(f"day {date} is not in the window store and the endpoint is not a benchmark endpoint with a dataset")
    from pdp_engine.sources.pg_replay import PostgresReplay
    src = PostgresReplay(cfg["dataset"], host=cfg.get("dataset_host", "postgres"))
    return src.entity_index(), src.events(date)


def job_sim(job: dict, device: str):
    from pdp_sim.campaign import Campaign, Spec
    cid = job["params"]["campaign_id"]
    with db.conn() as c:
        camp = db.q(c, "SELECT * FROM sim_campaigns WHERE id=%s", (cid,), one=True)
        ep = db.q(c, "SELECT * FROM endpoints WHERE id=%s", (camp["endpoint_id"],), one=True)
        bid = str(camp["bundle_id"] or ep["current_bundle"] or "")
        bundle = db.q(c, "SELECT path FROM bundles WHERE id=%s", (bid,), one=True) if bid else None
        db.q(c, "UPDATE sim_campaigns SET state='running', bundle_id=%s WHERE id=%s", (bid or None, cid))
    if not bundle:
        raise RuntimeError("endpoint has no bundle to simulate against")
    eid = str(ep["id"])
    spec = Spec.from_dict(dict(camp["spec"], transplant_dir=ATTACK_DIR))
    base = store_for(eid)
    ev_root = os.path.join(DATA_DIR, "endpoints", eid, "eval", bid)
    extra = WindowStore(ev_root)
    if not os.path.exists(os.path.join(ev_root, "registry.json")):
        shutil.copy(os.path.join(base.root, "registry.json"), os.path.join(ev_root, "registry.json"))
    store = CombinedStore(base, extra)
    for d in spec.days:
        if d == "validation" or d in store.days():
            continue
        reg = extra.load_registry()
        lookup, events = eval_day_source(ep, d)
        n = extra.add_day(d, ingest_day(reg, events, lookup))
        extra.save_registry(reg)
        log(f"sim {cid}: ingested held-out day {d}: {n} windows")
    def on_result(row):
        with db.conn() as c:
            db.q(c, "INSERT INTO sim_runs (campaign_id, run_index, attack, result) VALUES (%s,%s,%s,%s)", (cid, row["run_index"], json.dumps(row["attack"], default=str), json.dumps(row["result"], default=str)))
    camp_obj = Campaign(spec, store, bundle["path"], device=device, log=lambda m: log(f"sim {cid}: {m}"))
    out = camp_obj.run(on_result=on_result)
    with db.conn() as c:
        db.q(c, "UPDATE sim_campaigns SET state='done', finished_at=now(), spec = spec || %s WHERE id=%s",
             (json.dumps({"summary": out["summary"], "clean": out["clean"], "plan_passes": len(out["plan"]), "spec_hash": out["summary"]["spec_hash"]}, default=str), cid))
    s = out["summary"]
    log(f"sim {cid}: done, detection {s['detection_rate']:.2f} CI {s['detection_rate_ci']} fp/day {s['fp_per_day']:.1f}")


def _release_gpu():
    """Give cached GPU memory back between jobs (benchmark agents and other workers share the card)."""
    try:
        import gc, torch
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except Exception:  # noqa
        pass


class Heartbeat:
    """Touch jobs.heartbeat every 30 s while a job runs, so a crashed worker's job can be told from a long one."""

    def __init__(self):
        import threading
        self._ev, self._job, self._t = threading.Event(), None, None
        self._threading = threading

    def start(self, job_id):
        self._job = str(job_id); self._ev.clear()
        self._t = self._threading.Thread(target=self._run, daemon=True); self._t.start()

    def _run(self):
        while not self._ev.wait(30):
            try:
                with db.conn() as c:
                    db.q(c, "UPDATE jobs SET heartbeat=now() WHERE id=%s", (self._job,))
            except Exception:  # noqa
                pass

    def stop(self):
        self._ev.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kinds", default="ingest,train")
    ap.add_argument("--device", default=os.environ.get("PDP_TRAIN_DEVICE", "cpu"))
    a = ap.parse_args()
    kinds = tuple(a.kinds.split(","))
    log(f"worker up: kinds={kinds} device={a.device}")
    if a.device.startswith("cuda"):
        import torch
        if not torch.cuda.is_available():
            log("WARNING: --device cuda but no GPU is visible to this container; falling back to cpu")
            a.device = "cpu"
        else:
            log(f"GPU: {torch.cuda.get_device_name(0)}, {torch.cuda.get_device_properties(0).total_memory / 2**30:.0f} GiB")
    with db.conn() as c:   # jobs left 'running' by a worker that died are re-queued (this worker owns those kinds)
        n = db.q(c, "UPDATE jobs SET state='queued', started_at=NULL WHERE state='running' AND kind = ANY(%s) AND heartbeat < now() - interval '10 minutes' RETURNING id", (list(kinds),))
        if n:
            log(f"re-queued {len(n)} stale running jobs")
    hb = Heartbeat()
    while True:
        job = None
        with db.conn() as c:
            job = db.q(c, "UPDATE jobs SET state='running', started_at=now(), heartbeat=now() WHERE id = "
                          "(SELECT id FROM jobs WHERE state='queued' AND kind = ANY(%s) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *",
                       (list(kinds),), one=True)
        if not job:
            if "train" in kinds:
                schedule_early_models()
            time.sleep(5)
            continue
        hb.start(job["id"])
        try:
            if job["kind"] == "ingest":
                job_ingest(job)
            elif job["kind"] == "train":
                job_train(job, a.device)
            elif job["kind"] == "sim":
                job_sim(job, a.device)
            with db.conn() as c:
                db.q(c, "UPDATE jobs SET state='done', finished_at=now() WHERE id=%s", (job["id"],))
            _release_gpu()
        except Exception as e:  # noqa
            _release_gpu()
            log(f"job {job['id']} failed: {e}\n{traceback.format_exc()}")
            with db.conn() as c:
                db.q(c, "UPDATE jobs SET state='failed', finished_at=now(), error=%s WHERE id=%s", (str(e)[:2000], job["id"]))
                if job["kind"] == "train":
                    db.q(c, "UPDATE endpoints SET phase='degraded' WHERE id=%s AND phase='training'", (job["endpoint_id"],))
                if job["kind"] == "sim":
                    db.q(c, "UPDATE sim_campaigns SET state='failed', finished_at=now() WHERE id=%s", (job["params"].get("campaign_id"),))
        finally:
            hb.stop()


if __name__ == "__main__":
    main()
