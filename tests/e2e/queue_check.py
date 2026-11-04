"""Fair job queue against a real database (staging): one organisation with five old jobs, another with one newer job;
the second organisation's job must not wait behind all five."""
import sys
import uuid

from pdp_server import db
from pdp_server.worker import NEXT_JOB

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


orgs, eps = [], {}
with db.conn() as c:
    for name in ("Fair A", "Fair B"):
        o = db.q(c, "INSERT INTO orgs (name) VALUES (%s) RETURNING id", (name,), one=True)["id"]
        orgs.append(o)
        e = str(uuid.uuid4())
        db.q(c, "INSERT INTO endpoints (id, name, org_id) VALUES (%s,%s,%s)", (e, name, o))
        eps[name] = e
    for k in range(5):
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, created_at) VALUES (%s,%s,'fairtest', now() - interval '1 hour' + %s * interval '1 minute')",
             (str(uuid.uuid4()), eps["Fair A"], k))
    db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, created_at) VALUES (%s,%s,'fairtest', now() - interval '10 minutes')", (str(uuid.uuid4()), eps["Fair B"]))
order = []
try:
    for _ in range(6):
        with db.conn() as c:
            j = db.q(c, NEXT_JOB, (["fairtest"],), one=True)
            order.append("A" if str(j["endpoint_id"]) == eps["Fair A"] else "B")
            db.q(c, "UPDATE jobs SET state='done', finished_at=now() WHERE id=%s", (j["id"],))
    check(order[:3] in (["A", "B", "A"], ["B", "A", "A"]) and order.count("B") == 1, f"organisations take turns: {''.join(order)} (plain FIFO would be AAAAAB)")
finally:
    with db.conn() as c:
        db.q(c, "DELETE FROM jobs WHERE kind='fairtest'")
        for e in eps.values():
            db.q(c, "DELETE FROM endpoints WHERE id=%s", (e,))
        for o in orgs:
            db.q(c, "DELETE FROM orgs WHERE id=%s", (o,))
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
