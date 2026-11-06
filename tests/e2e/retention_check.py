"""Retention against a real database (staging): an organisation keeping 30 days loses its 40-day-old alerts; recent
ones and other organisations' data stay; the audit log is kept for at least 365 days whatever the retention (0.6: a
lower retention must not erase the record of who changed what)."""
import sys
import uuid

from pdp_server import db, worker

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


with db.conn() as c:
    o1 = db.q(c, "INSERT INTO orgs (name, retention_days) VALUES ('Ret 30', 30) RETURNING id", one=True)["id"]
    o2 = db.q(c, "INSERT INTO orgs (name, retention_days) VALUES ('Ret 365', 365) RETURNING id", one=True)["id"]
    e1, e2 = str(uuid.uuid4()), str(uuid.uuid4())
    for e, o in ((e1, o1), (e2, o2)):
        db.q(c, "INSERT INTO endpoints (id, name, org_id) VALUES (%s,%s,%s)", (e, "ret", o))
        for age in (40, 5):
            db.q(c, "INSERT INTO alerts (endpoint_id, window_start_ns, node_uuid, ntype, label, fused, r1, r2, created_at) "
                    "VALUES (%s, 0, 'n', 'file', 'file x', 0, 0, 0, now() - %s * interval '1 day')", (e, age))
        db.q(c, "INSERT INTO audit_log (org_id, action, at) VALUES (%s, 'old', now() - interval '40 days')", (o,))
        db.q(c, "INSERT INTO audit_log (org_id, action, at) VALUES (%s, 'older than a year', now() - interval '400 days')", (o,))
        # window summaries: one received 40 days ago, one just received with an event time from 2019 (a replayed
        # dataset or a wrong endpoint clock): only the first is old
        db.q(c, "INSERT INTO windows (endpoint_id, start_ns, end_ns, received_at) VALUES (%s, 1, 2, now() - interval '40 days')", (e,))
        db.q(c, "INSERT INTO windows (endpoint_id, start_ns, end_ns) VALUES (%s, 1569211200000000000, 1569212100000000000)", (e,))
try:
    worker._last_retention = 0
    worker.apply_retention()
    with db.conn() as c:
        a1 = db.q(c, "SELECT count(*) AS n FROM alerts WHERE endpoint_id=%s", (e1,), one=True)["n"]
        a2 = db.q(c, "SELECT count(*) AS n FROM alerts WHERE endpoint_id=%s", (e2,), one=True)["n"]
        l1 = db.q(c, "SELECT count(*) AS n FROM audit_log WHERE org_id=%s", (o1,), one=True)["n"]
        l2 = db.q(c, "SELECT count(*) AS n FROM audit_log WHERE org_id=%s", (o2,), one=True)["n"]
    check(a1 == 1, f"30-day organisation: the 40-day-old alert is gone ({a1} alert left)")
    check(l1 == 1 and l2 == 1, f"audit log: the 40-day-old entry stays (kept >= 365 days), the 400-day-old one is gone ({l1}, {l2})")
    check(a2 == 2, "365-day organisation keeps both alerts")
    with db.conn() as c:
        w1 = [r["start_ns"] for r in db.q(c, "SELECT start_ns FROM windows WHERE endpoint_id=%s", (e1,))]
        w2 = db.q(c, "SELECT count(*) AS n FROM windows WHERE endpoint_id=%s", (e2,), one=True)["n"]
    check(w1 == [1569211200000000000], f"windows: age counts from when the server received them, not the event clock ({w1})")
    check(w2 == 2, "365-day organisation keeps both windows")
finally:
    with db.conn() as c:
        db.q(c, "DELETE FROM endpoints WHERE id IN (%s, %s)", (e1, e2))
        db.q(c, "DELETE FROM orgs WHERE id IN (%s, %s)", (o1, o2))
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
