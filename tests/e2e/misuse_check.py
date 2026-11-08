"""Control-plane misuse resistance (0.6) against a real platform database: the console routes are called directly
with sessions of two organisations (no gateway needed). Creates its own organisations, users, endpoints, a model
bundle and alerts, and deletes them afterwards.

  docker run --rm --network <platform db network> -v $PWD:/src:ro -w /src -e PYTHONPATH=/src/server:/src/engine \
      -e PDP_ENGINE_PATH=/src/engine -e PDP_PLATFORM_DSN=... -e PDP_TELEMETRY_DSN=... --entrypoint python \
      pdp/server:dev tests/e2e/misuse_check.py

Checks: settings validation and reasons (audit diff + security event), approved_executables refused, allow-list
program rules and status_by, reopening on deletion, export role / limit / paging / audit, simulation bundle ownership
and quotas, rate limits, hunt scope, response-action reasons, organisation retention, notification of security
events, posture refresh, job_sim's bundle check and audit retention."""
import json
import os
import sys
import tempfile
import uuid

os.environ.setdefault("PDP_SESSION_SECRET", os.path.join(tempfile.mkdtemp(), "session.secret"))
os.environ.setdefault("PDP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("PDP_RATE_HUNT", "2/1")
from fastapi import HTTPException  # noqa: E402

from pdp_server import db  # noqa: E402

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg, flush=True)
    fails += 0 if ok else 1


def status_of(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except HTTPException as e:
        return e.status_code, str(e.detail)
    return 200, None


if os.environ.get("PDP_MISUSE_INIT_SCHEMA") == "1":     # an empty database: apply the schema first
    db.init_platform(os.path.join(os.path.dirname(db.__file__), "schema.sql"))
from pdp_server import allowlist, api, hunt, notify, orgs, posture, respond, worker  # noqa: E402
from pdp_server.allowlist import NewEntry  # noqa: E402

with db.conn() as c:
    o1 = str(db.q(c, "INSERT INTO orgs (name, response_actions) VALUES ('Misuse A', true) RETURNING id", one=True)["id"])
    o2 = str(db.q(c, "INSERT INTO orgs (name) VALUES ('Misuse B') RETURNING id", one=True)["id"])
    tag = uuid.uuid4().hex[:8]
    uid = {}
    for name, role, org, eps in (("adm", "admin", o1, None), ("ana", "analyst", o1, None), ("view", "viewer", o1, None),
                                 ("scoped", "analyst", o1, "e1"), ("b", "admin", o2, None)):
        uid[name] = db.q(c, "INSERT INTO users (username, password_hash, role, org_id) VALUES (%s,'!',%s,%s) RETURNING id",
                         (f"mis-{name}-{tag}", role, org), one=True)["id"]
    e1, e2, e3 = (str(uuid.uuid4()) for _ in range(3))
    for e, org in ((e1, o1), (e2, o1), (e3, o2)):
        db.q(c, "INSERT INTO endpoints (id, name, org_id, phase, kind, config, enrolled_at, agent_version, last_seen) "
                "VALUES (%s,%s,%s,'protected','live','{\"baseline_days\": 7}', now() - interval '20 days', '0.3.20', now())",
             (e, f"mis-{e[:4]}", org))
    bdir = os.path.join(os.environ["PDP_DATA_DIR"], "bundles", e1, "b1")
    os.makedirs(bdir, exist_ok=True)
    json.dump({"known_executables": ["/usr/bin/bash", "/usr/sbin/sshd"]}, open(os.path.join(bdir, "layers.json"), "w"))
    b1, b3 = str(uuid.uuid4()), str(uuid.uuid4())
    man = {"layers": {"novelty": True, "rules": True}, "learned_policy": {"daily_budget": 20}, "maturity": {"early": False}}
    db.q(c, "INSERT INTO bundles (id, endpoint_id, path, sha256, manifest) VALUES (%s,%s,%s,'x',%s)", (b1, e1, bdir, json.dumps(man)))
    db.q(c, "INSERT INTO bundles (id, endpoint_id, path, sha256, manifest) VALUES (%s,%s,'/nonexistent','x',%s)", (b3, e3, json.dumps(man)))
    db.q(c, "UPDATE endpoints SET current_bundle=%s WHERE id=%s", (b1, e1))
    db.q(c, "UPDATE endpoints SET current_bundle=%s WHERE id=%s", (b3, e3))
    for k in range(5):
        db.q(c, "INSERT INTO alerts (endpoint_id, window_start_ns, node_uuid, ntype, label, layer, rule, reasons) VALUES "
                "(%s,%s,%s,'subject',%s,'novelty','novel_executable',%s)",
             (e1, 10**18 + k, f"n{k}", "subject /dev/shm/x/python3 python3", json.dumps([{"rule": "novel_executable", "key": "/dev/shm/x/python3", "layer": "novelty"}])))
    ch = db.q(c, "INSERT INTO notify_channels (org_id, name, kind, target, events, created_at) VALUES (%s,'SOC','webhook','https://hooks.example.com/x','[\"incident\"]', now() - interval '1 minute') RETURNING *",
              (o1,), one=True)


def sess(name, org, scope):
    role = {"adm": "admin", "ana": "analyst", "view": "viewer", "scoped": "analyst", "b": "admin"}[name]
    return {"u": uid[name], "r": role, "org": org, "scope": set(scope), "op": False, "a": "local"}


A = sess("adm", o1, {e1, e2}); AN = sess("ana", o1, {e1, e2}); V = sess("view", o1, {e1, e2}); S = sess("scoped", o1, {e1})
B = sess("b", o2, {e3})

try:
    # ---- settings
    cp = api.ConfigPatch
    check(status_of(api.patch_config, e1, cp(config={"train": {"device": "cuda"}}), s=A)[0] == 400, "train.device refused")
    st, msg = status_of(api.patch_config, e1, cp(config={"approved_executables": ["python3"]}), s=A)
    check(st == 400 and "allow list" in msg, "approved_executables refused with a pointer to the allow list")
    st, msg = status_of(api.patch_config, e1, cp(config={"train": {"layer_rules": False}}), s=A)
    check(st == 400 and msg.startswith("Reason required"), "weakening without a reason: 400")
    # 0.7 floor: the learned layer or the data-flow rules must be able to alert
    check(status_of(api.patch_config, e1, cp(config={"train": {"layer_rules": False, "learned_alerts": False}}, reason="x"), s=A)[0] == 400,
          "data-flow rules and learned alerts both off: refused even with a reason")
    check(status_of(api.patch_config, e1, cp(config={"train": {"layer_rules": False}}, reason="noisy build host"), s=A)[0] == 200,
          "weakening with a reason: accepted")
    with db.conn() as c:
        au = db.q(c, "SELECT * FROM audit_log WHERE org_id=%s AND action='endpoint settings changed' ORDER BY id DESC LIMIT 1", (o1,), one=True)
        se = db.q(c, "SELECT * FROM security_events WHERE org_id=%s AND kind='detection_weakened' ORDER BY id DESC LIMIT 1", (o1,), one=True)
    check(au and au["detail"]["reason"] == "noisy build host" and au["detail"]["changes"]["train.layer_rules"]["after"] is False,
          "audit row: reason and before/after diff")
    check(se and "layer 2" in se["title"] and se["username"].startswith("mis-adm") and str(se["endpoint_id"]) == e1, "security event recorded")
    check(status_of(api.patch_config, e1, cp(config={"train": {"layer_rules": True}, "learned_daily_budget": 30}), s=A)[0] == 200,
          "strengthening needs no reason")
    # 0.8: layer 1 (new programs) is an optional extra rule, off by default: turning it on or off needs no reason;
    # turning detector-3's breadth evidence off (or making it less sensitive) does
    check(status_of(api.patch_config, e1, cp(config={"train": {"layer_rules": True, "layer_novelty": True}}), s=A)[0] == 200,
          "0.8: turning layer 1 on needs no reason")
    check(status_of(api.patch_config, e1, cp(config={"train": {"layer_rules": True, "layer_novelty": False}}), s=A)[0] == 200,
          "0.8: turning layer 1 off needs no reason")
    st, msg = status_of(api.patch_config, e1, cp(config={"train": {"layer_rules": True, "d3_breadth": False}}), s=A)
    check(st == 400 and msg.startswith("Reason required") and "breadth" in msg, "0.8: turning detector-3 breadth evidence off needs a reason")
    st, msg = status_of(api.patch_config, e1, cp(config={"train": {"layer_rules": True, "d3_breadth_floor": 8.0}}), s=A)
    check(st == 400 and "breadth floor raised" in msg, "0.8: raising the breadth floor needs a reason")
    st, msg = status_of(api.patch_config, e1, cp(config={"train": {"d3_breadth_floor": 12.0}}, reason="x"), s=A)
    check(st == 400 and "below train.d3_breadth_cap" in msg, "0.8: a breadth floor at or above the cap is refused")

    # ---- allow list
    ne = lambda **kw: NewEntry(**{"kind": "program", "endpoints": [e1], **kw})  # noqa: E731
    check(status_of(allowlist.add_entry, ne(value="/usr/local/bin/links"), s=A)[1].startswith("Reason required"), "allow-list entry without a note: 400")
    st, msg = status_of(allowlist.add_entry, ne(value="python3", note="ops"), s=A)
    check(st == 400 and "full path" in msg, "bare name refused (the endpoint records paths)")
    st, msg = status_of(allowlist.add_entry, ne(value="/usr/bin/python3", note="ops"), s=A)
    check(st == 400 and msg.startswith("Confirmation required"), "interpreter without force: 400")
    check(status_of(allowlist.add_entry, ne(value="/usr/bin/*", note="ops"), s=A)[0] == 400, "wildcard refused")
    r = allowlist.add_entry(ne(value="/dev/shm/x/python3", note="lab tool", force=True), s=A)
    check(r["alerts_allowed"] == 5, f"forced interpreter entry resolves the 5 matching alerts ({r['alerts_allowed']})")
    with db.conn() as c:
        al = db.q(c, "SELECT status, status_by, status_at, allowed_by FROM alerts WHERE endpoint_id=%s", (e1,))
        ent = db.q(c, "SELECT forced, note, created_by FROM allowlist WHERE id=%s", (r["id"],), one=True)
    check(all(a["status"] == "false_positive" and a["status_by"] == uid["adm"] and a["status_at"] for a in al), "auto-resolution: status_by = the entry's creator")
    check(ent["forced"] is True and ent["note"] == "lab tool", "force recorded with the note")
    view = allowlist.list_allowlist(s=A)["entries"]
    check(any(x["id"] == r["id"] and "interpreter" in x["risks"] and x["force"] for x in view), "allow-list view shows the risk and force")
    # an analyst marks one alert again by hand, the entry is removed: the others reopen, the analyst's verdict stays
    with db.conn() as c:
        one = db.q(c, "SELECT id FROM alerts WHERE endpoint_id=%s ORDER BY id LIMIT 1", (e1,), one=True)["id"]
    api.update_alert(one, api.AlertUpdate(status="false_positive"), s=AN)
    d = allowlist.delete_entry(r["id"], s=A)
    with db.conn() as c:
        al = {a["id"]: a for a in db.q(c, "SELECT id, status, allowed_by, status_by FROM alerts WHERE endpoint_id=%s", (e1,))}
    check(d["alerts_reopened"] == 4 and al[one]["status"] == "false_positive" and al[one]["status_by"] == uid["ana"],
          f"deleting the entry reopened the 4 auto-resolved alerts, kept the analyst's verdict ({d})")
    check(all(a["allowed_by"] is None for a in al.values()) and sum(a["status"] == "open" for a in al.values()) == 4, "links cleared")
    st, _ = status_of(api.approve_executables, e1, api.ApprovalReq(executables=["/opt/app/run"]), s=A)
    check(st == 400, "legacy approved-executables route: needs a reason too")
    check(status_of(api.approve_executables, e1, api.ApprovalReq(executables=["/opt/app/run"], note="vendor agent"), s=A)[0] == 200,
          "legacy approved-executables route with a note: accepted")
    cfg = api.endpoint_detail(e1, s=A)["endpoint"]["config"]
    check(cfg["approved_executables"] == ["/opt/app/run"], f"effective config from the allow list only ({cfg['approved_executables']})")
    with db.conn() as c:     # a value still stored in the endpoint configuration is migrated, not applied
        db.q(c, "UPDATE endpoints SET config = config || '{\"approved_executables\": [\"bash\"]}' WHERE id=%s", (e2,))
        allowlist.migrate(c)
        mig = db.q(c, "SELECT note, created_by FROM allowlist WHERE org_id=%s AND value='bash'", (o1,), one=True)
        left = db.q(c, "SELECT config ? 'approved_executables' AS x FROM endpoints WHERE id=%s", (e2,), one=True)["x"]
    check(mig and mig["note"] == "migrated from endpoint config" and not left, "stored approved_executables migrated into the allow list")
    view = allowlist.list_allowlist(s=A)["entries"]
    check(any(x["value"] == "bash" and "name_only" in x["risks"] for x in view), "migrated bare name visible with its risk")

    # ---- export
    from pdp_server.access import triager
    import inspect
    check(inspect.signature(api.export_alerts).parameters["s"].default.dependency is triager and status_of(triager, V)[0] == 403,
          "export needs the triager role: a viewer gets 403")
    st, msg = status_of(api.export_alerts, None, s=AN, limit=1_000_000)
    check(st == 400 and "since_id" in msg, "export above 100000 rows: 400 with paging hint")
    from types import SimpleNamespace
    resp = api.export_alerts(SimpleNamespace(headers={"x-real-ip": "198.51.100.7"}, client=None), s=AN, format="ndjson", limit=2, since_id=0)
    rows = [json.loads(x) for x in resp.body.decode().splitlines()]
    check(len(rows) == 2 and resp.headers.get("X-PDP-More") == "1" and resp.headers.get("X-PDP-Next-Since-Id") == str(rows[-1]["id"]),
          "export pages by since_id with X-PDP-Next-Since-Id")
    with db.conn() as c:
        ex = db.q(c, "SELECT detail FROM audit_log WHERE org_id=%s AND action='alerts exported' ORDER BY id DESC LIMIT 1", (o1,), one=True)
    check(ex and ex["detail"]["rows"] == 2, "export audited with its row count")

    # ---- simulation
    nc = api.NewCampaign
    st, msg = status_of(api.create_campaign, nc(name="x", endpoint_id=e1, bundle_id=b3), s=A)
    check(st == 400 and "own models" in msg, "another organisation's bundle refused")
    st, _ = status_of(api.create_campaign, nc(name="x", endpoint_id=e1, bundle_id="not-a-uuid"), s=A)
    check(st == 400, "malformed bundle id: 400")
    with db.conn() as c:
        db.q(c, "INSERT INTO sim_campaigns (id, name, endpoint_id, spec, seed) VALUES (%s,'big',%s,%s,1)",
             (str(uuid.uuid4()), e1, json.dumps({"runs": posture.SIM_RUNS_PER_DAY - 10})))
    st, msg = status_of(api.create_campaign, nc(name="x", endpoint_id=e1, spec={"runs": 40}), s=A)
    check(st == 429 and "per 24 hours" in msg, "organisation's daily simulation runs capped")
    check(status_of(api.create_campaign, nc(name="x", endpoint_id=e1, spec={"runs": 5}), s=A)[0] == 200, "within the cap: accepted")
    with db.conn() as c:     # job_sim never loads another endpoint's bundle
        db.q(c, "UPDATE sim_campaigns SET bundle_id=%s WHERE endpoint_id=%s", (b3, e1))
        cid = db.q(c, "SELECT id FROM sim_campaigns WHERE endpoint_id=%s LIMIT 1", (e1,), one=True)["id"]
    try:
        worker.job_sim({"params": {"campaign_id": str(cid)}}, "cpu")
        check(False, "job_sim with a foreign bundle must fail")
    except RuntimeError as e:
        check("no bundle" in str(e), f"job_sim refuses a foreign bundle ({e})")

    # ---- rate limits (hunt: 2 at once, 1 per hour in this run)
    hr = hunt.HuntReq
    codes = [status_of(hunt.start_hunt, hr(q="ssh"), s=AN)[0] for _ in range(3)]
    check(codes == [200, 200, 429], f"hunts rate-limited per user ({codes})")
    check(status_of(hunt.start_hunt, hr(q="ssh"), s=A)[0] == 200, "another user has their own bucket")
    with db.conn() as c:
        hq = db.q(c, "SELECT detail FROM audit_log WHERE org_id=%s AND action='hunt started' ORDER BY id DESC LIMIT 1", (o1,), one=True)
        hid = db.q(c, "SELECT id FROM hunts WHERE org_id=%s ORDER BY created_at DESC LIMIT 1", (o1,), one=True)["id"]
        for e in (e1, e2):
            db.q(c, "INSERT INTO hunt_results (hunt_id, endpoint_id, rows) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                 (hid, e, json.dumps([{"kind": "exec", "program": f"/bin/{e[:4]}"}])))
    check(hq and hq["detail"]["query"] == "ssh", "hunt audited with its query text")
    g = hunt.get_hunt(str(hid), s=S)
    check([x["id"] for x in g["endpoints"]] == [e1], "a scoped user sees only their endpoints' hunt answers")
    lh = [h for h in hunt.list_hunts(s=S)["hunts"] if str(h["id"]) == str(hid)]
    check(lh and lh[0]["asked"] == 1 and lh[0]["matches"] == 1, f"hunt list counts only the user's scope ({lh})")
    check(status_of(hunt.get_hunt, str(hid), s=B)[0] == 404, "another organisation: 404")

    # ---- response actions
    rq = respond.Respond
    st, msg = status_of(respond.respond, e1, rq(action="isolate"), s=A)
    check(st == 400 and msg.startswith("Reason required"), "isolate without a reason: 400")
    check(status_of(respond.respond, e1, rq(action="isolate", reason="ransomware on host"), s=A)[0] == 200, "isolate with a reason")
    with db.conn() as c:
        ra = db.q(c, "SELECT * FROM security_events WHERE org_id=%s AND kind='response_action' ORDER BY id DESC LIMIT 1", (o1,), one=True)
    check(ra and ra["detail"]["reason"] == "ransomware on host", "response action: security event with the reason")

    # ---- organisation
    st, msg = status_of(orgs.patch_org, orgs.OrgPatch(retention_days=30), s=A)
    check(st == 400 and "retention" in msg, "lowering retention needs a reason")
    check(status_of(orgs.patch_org, orgs.OrgPatch(retention_days=30, reason="contract"), s=A)[0] == 200, "with a reason: accepted")

    # ---- notifications: the channel receives the security events
    with db.conn() as c:
        msgs = notify.pending_messages(c, ch, [], [])
        other = notify.pending_messages(c, {**ch, "org_id": o2}, [], [])
    kinds = {m["event"] for k, m in msgs if k.startswith("sec:")}
    check({"detection_weakened", "response_action"} <= kinds, f"incident channel gets the security events ({kinds})")
    check(not [k for k, m in other if k.startswith("sec:")], "another organisation's channel gets none of them")
    patched = notify.patch_channel(ch["id"], notify.ChannelPatch(enabled=False), s=A)
    with db.conn() as c:
        sil = db.q(c, "SELECT title FROM security_events WHERE org_id=%s ORDER BY id DESC LIMIT 1", (o1,), one=True)
    check(not patched["channel"]["enabled"] and sil["title"].startswith("Notifications reduced"), "disabling a channel is a security event")

    # ---- posture
    with db.conn() as c:
        db.q(c, "UPDATE endpoints SET config = config || '{\"periodic_retrain\": false}', current_bundle=NULL WHERE id=%s", (e2,))
    n = posture.refresh_all(force=True)
    with db.conn() as c:
        pe = db.q(c, "SELECT title FROM security_events WHERE endpoint_id=%s AND detail->>'type'='detection_posture'", (e2,))
    check(n >= 1 and any("no detection model" in p["title"] for p in pe), f"posture worsening recorded ({[p['title'] for p in pe]})")
    posture.refresh_all(force=True)
    with db.conn() as c:
        again = db.q(c, "SELECT count(*) AS n FROM security_events WHERE endpoint_id=%s AND detail->>'type'='detection_posture'", (e2,), one=True)["n"]
    check(again == len(pe), "unchanged posture: no new events")
    det = api.endpoint_detail(e2, s=A)
    check(det["posture"]["level"] == "error", "endpoint API returns the posture")

    # ---- audit retention: kept >= 365 days even with retention 30
    with db.conn() as c:
        db.q(c, "INSERT INTO audit_log (org_id, action, at) VALUES (%s, 'old', now() - interval '40 days')", (o1,))
    worker._last_retention = 0
    worker.apply_retention()
    with db.conn() as c:
        kept = db.q(c, "SELECT count(*) AS n FROM audit_log WHERE org_id=%s AND action='old'", (o1,), one=True)["n"]
    check(kept == 1, "audit log entries survive a 30-day retention")
finally:
    with db.conn() as c:
        db.q(c, "DELETE FROM sim_campaigns WHERE endpoint_id IN (%s,%s,%s)", (e1, e2, e3))
        db.q(c, "DELETE FROM hunts WHERE org_id IN (%s,%s)", (o1, o2))
        db.q(c, "DELETE FROM allowlist WHERE org_id IN (%s,%s)", (o1, o2))
        db.q(c, "DELETE FROM endpoints WHERE id IN (%s,%s,%s)", (e1, e2, e3))
        db.q(c, "DELETE FROM users WHERE org_id IN (%s,%s)", (o1, o2))
        db.q(c, "DELETE FROM orgs WHERE id IN (%s,%s)", (o1, o2))
        db.q(c, "DELETE FROM kv WHERE k LIKE 'posture:%%' AND NOT EXISTS (SELECT 1 FROM endpoints WHERE id::text = substr(k, 9))")
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
