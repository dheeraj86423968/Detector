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
    # a GPU job that ran out of GPU memory is re-queued for later, a bounded number of times; other errors fail it
    from pdp_server.worker import GPU_OOM_RETRIES, gpu_oom_retry, is_gpu_oom
    oom = RuntimeError("CUDA error: out of memory")
    check(is_gpu_oom(oom) and is_gpu_oom(RuntimeError("CUDA out of memory. Tried to allocate 2.00 GiB"))
          and not is_gpu_oom(MemoryError("out of memory")) and not is_gpu_oom(ValueError("bad config")), "GPU out-of-memory recognised")
    jid = str(uuid.uuid4())
    with db.conn() as c:
        db.q(c, "INSERT INTO jobs (id, endpoint_id, kind, state, started_at) VALUES (%s,%s,'fairtest','running',now())", (jid, eps["Fair A"]))
    job = {"id": jid, "kind": "train", "params": {}}
    check(not gpu_oom_retry(job, ValueError("bad config")), "other errors are not retried")
    check(not gpu_oom_retry({**job, "kind": "ingest"}, oom), "only GPU jobs are retried")
    retried = []
    for k in range(GPU_OOM_RETRIES + 1):
        with db.conn() as c:
            job = db.q(c, "SELECT * FROM jobs WHERE id=%s", (jid,), one=True)
        job = {**job, "kind": "train"}
        retried.append(gpu_oom_retry(job, oom))
        with db.conn() as c:
            row = db.q(c, "SELECT state, started_at, params, error FROM jobs WHERE id=%s", (jid,), one=True)
            if k == 0:
                check(row["state"] == "queued" and row["started_at"] is None and "retry 1/" in (row["error"] or ""),
                      f"re-queued with a reason ({row['error']})")
                check(db.q(c, NEXT_JOB, (["fairtest"],), one=True) is None, "not picked up again before the delay")
            db.q(c, "UPDATE jobs SET params = params || '{\"not_before\": 0}'::jsonb WHERE id=%s", (jid,))
            if k < GPU_OOM_RETRIES:
                j = db.q(c, NEXT_JOB, (["fairtest"],), one=True)
                check(j is not None and str(j["id"]) == jid, f"picked up after the delay (attempt {k + 2})")
    check(retried == [True] * GPU_OOM_RETRIES + [False], f"retried {GPU_OOM_RETRIES} times, then fails for good ({retried})")
finally:
    with db.conn() as c:
        db.q(c, "DELETE FROM jobs WHERE kind='fairtest'")
        for e in eps.values():
            db.q(c, "DELETE FROM endpoints WHERE id=%s", (e,))
        for o in orgs:
            db.q(c, "DELETE FROM orgs WHERE id=%s", (o,))
print("FAILURES:", fails)
sys.exit(1 if fails else 0)
