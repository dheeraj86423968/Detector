"""Console import of lab 0.10 (agent side, in a pdp/server image on the gateway's network): enrol as a 0.10.0 agent
with a one-time token, then send the lab's 0.10 alert rows (rows13-SET.json.gz, variant P2 = what the 0.10 agent
reports: per window, real-time duplicates within 2 h dropped, one-hop context) through the agent alert API.
  post10.py SET TOKEN CA_SHA256 ROWS_GZ|- STATE_DIR   -> prints the endpoint id (-: enrol only) or {"endpoint_id", "alerts"}"""
import gzip, json, os, sys
from pdp_agent.config import Config
from pdp_agent.agent import Agent, VERSION
from pdp_agent.transport import Transport

name, token, fp, rows_gz, state = sys.argv[1:6]
os.environ["PDP_HOSTNAME"] = name
cfg = Config()
cfg.server_url, cfg.agent_url = "https://gateway", "https://gateway:8443"
cfg.data_dir, cfg.pki_dir, cfg.day_tz, cfg.device = state, os.path.join(state, "pki"), "US/Eastern", "cpu"
os.makedirs(cfg.pki_dir, exist_ok=True)
a = Agent(cfg)
a.enroll(token, ca_sha256=fp)
eid = a.state.get("endpoint_id")
if rows_gz == "-":                       # enrol only
    print(eid); sys.exit(0)
tr = Transport(cfg.agent_url, cfg.server_ca, cfg.cert_path, cfg.key_path, timeout=120)
d = json.load(gzip.open(rows_gz, "rt"))
rows = sorted(d["rows"]["P2"], key=lambda r: (r["window_start_ns"], r["id"]))
out = []
for i, r in enumerate(rows, 1):
    reason = {"layer": r["layer"], "rule": r["rule"], "detail": r["reason"]}
    out.append({"window_start_ns": r["window_start_ns"], "node": {"uuid": r["node_uuid"], "ntype": r["ntype"], "label": r["label"], "display": {}},
                "fused": 0.0, "r1": 0.0, "r2": 0.0, "context": d["ctx"][r["ctx"]], "layer": r["layer"], "rule": r["rule"],
                "reason": r["reason"], "reasons": [reason], "aid": f"lab10:{name}:{r['id']}", "seq": i})
for j in range(0, len(out), 200):
    tr.post_ndjson(f"/v1/endpoints/{eid}/alerts", out[j:j + 200])
print(json.dumps({"endpoint_id": eid, "alerts": len(out), "agent_version": VERSION}))
