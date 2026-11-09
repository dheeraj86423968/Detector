"""Console import of lab 0.10 (server side, run in an API container: docker exec -i <api> python - ARGS < register10.py).
  retire-benchmarks           mark every non-lab10 benchmark endpoint retired (their alerts came from agents 0.2-0.5)
  register EID SRC_BUNDLE [FLEET]  hard-link copy of the lab bundle (the model the lab scored with) into /data/bundles/EID,
                              signed like a trained bundle, made current; phase protected; FLEET: the fleet label
"""
import json, os, subprocess, sys, uuid, hashlib
from pdp_server import db, pki

cmd = sys.argv[1]
with db.conn() as c:
    if cmd == "retire-benchmarks":
        r = db.q(c, "UPDATE endpoints SET phase='retired' WHERE kind='benchmark' AND phase<>'retired' AND name NOT LIKE 'lab10-%%' RETURNING name")
        print(json.dumps({"retired": sorted(x["name"] for x in r)}))
    elif cmd == "register":
        eid, src = sys.argv[2], sys.argv[3]
        bid = str(uuid.uuid4())
        out = f"/data/bundles/{eid}/{bid}"
        os.makedirs(os.path.dirname(out), exist_ok=True)
        subprocess.run(["cp", "-al", src, out], check=True)
        for f in ("signature.json",):                       # a fresh signature file (never written through a shared link)
            p = os.path.join(out, f)
            if os.path.exists(p):
                os.unlink(p)
        pki.sign_bundle(out)
        manifest = json.load(open(os.path.join(out, "manifest.json")))
        digest = hashlib.sha256(open(os.path.join(out, "manifest.json"), "rb").read()).hexdigest()
        db.q(c, "INSERT INTO bundles (id, endpoint_id, job_id, path, sha256, manifest) VALUES (%s,%s,NULL,%s,%s,%s)",
             (bid, eid, out, digest, json.dumps(manifest)))
        nd = len(manifest.get("train_days") or []) + (1 if manifest.get("val_day") else 0)
        db.q(c, "UPDATE endpoints SET current_bundle=%s, phase='protected', baseline_days_done=%s WHERE id=%s", (bid, nd, eid))
        if len(sys.argv) > 4 and sys.argv[4]:
            db.q(c, "UPDATE endpoints SET config = config || %s WHERE id=%s", (json.dumps({"fleet": sys.argv[4]}), eid))
        print(json.dumps({"endpoint": eid, "bundle": bid, "train_days": manifest.get("train_days"), "val_day": manifest.get("val_day")}))
