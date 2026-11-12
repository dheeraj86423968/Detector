"""Auditor role (read-only administrator, 0.13) against a running stack (staging):

  docker run --rm --network pdp-staging_edge -v $PWD:/src:ro -w /src -e PDP_ADMIN_PASSWORD=<admin pw> \
      --entrypoint python pdp/server:dev tests/e2e/auditor_e2e.py

As the stack's first admin: creates an invite, a disabled webhook channel with a secret URL and signing secret, a
Kubernetes cluster token, and an auditor user (random password, never printed). Signs in as the auditor and checks
that every admin read answers 200 without those secrets, the cluster manifest answers 403, and every change answers
403 (and changes nothing). Removes everything it created afterwards (the cluster token is closed: tokens are kept).
"""
import http.client
import json
import os
import secrets
import ssl
import sys

HOST = os.environ.get("PDP_GATEWAY", "gateway")
fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg, flush=True)
    fails += 0 if ok else 1


raw = ssl.create_default_context(); raw.check_hostname = False; raw.verify_mode = ssl.CERT_NONE


class Console:
    def __init__(self):
        self.cookies = {}

    def call(self, method, path, body=None):
        con = http.client.HTTPSConnection(HOST, 443, context=raw, timeout=60)
        h = {"Content-Type": "application/json"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        con.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = con.getresponse(); data = r.read()
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, val = v.split(";", 1)[0].split("=", 1)
                self.cookies[name] = val
        try:
            return r.status, json.loads(data or b"{}"), data
        except json.JSONDecodeError:
            return r.status, {}, data


A = Console()
st, _, _ = A.call("POST", "/api/login", {"username": "admin", "password": os.environ["PDP_ADMIN_PASSWORD"]})
check(st == 200, "admin signs in")
if st != 200:
    sys.exit(1)

tag = secrets.token_hex(4)
hook_secret = "e2ePATH" + secrets.token_hex(12)
sign_secret = "e2eSIGN" + secrets.token_hex(12)
created = {}
try:
    # ---- secrets an admin creates
    st, inv, _ = A.call("POST", "/api/invites", {"role": "analyst"})
    created["invite"] = inv.get("invite", {}).get("id")
    invite_token = (inv.get("invite", {}).get("link") or "").rsplit("/", 1)[-1]
    check(st == 200 and len(invite_token) > 20, "admin creates an invite (the admin sees its link)")
    st, chn, _ = A.call("POST", "/api/notifications/channels", {"name": f"e2e-audit-{tag}", "kind": "webhook", "enabled": False,
                                                                 "target": f"https://hooks.example.com/services/{hook_secret}?k={hook_secret}",
                                                                 "secret": sign_secret, "events": ["incident"]})
    created["channel"] = chn.get("channel", {}).get("id")
    check(st == 200 and hook_secret in chn.get("channel", {}).get("target", ""), "admin adds a (disabled) webhook channel; the admin sees its URL")
    st, cl, _ = A.call("POST", "/api/clusters", {"cluster": f"e2e-audit-{tag}", "max_nodes": 1, "days": 1})
    created["cluster"] = cl.get("key")
    cluster_yaml = cl.get("manifest") or ""
    cluster_token = next((ln.split(":", 1)[1].strip().strip('"') for ln in cluster_yaml.splitlines() if ln.strip().startswith("token:")), "")
    check(st == 200 and created["cluster"] and len(cluster_token) > 20, "admin creates a Kubernetes cluster token (in its manifest)")
    st, mf, _ = A.call("GET", f"/api/clusters/{created['cluster']}/manifest")
    check(st == 200, "admin downloads the cluster manifest")

    # ---- the auditor
    pw = secrets.token_urlsafe(18)
    uname = f"auditor-e2e-{tag}"
    st, u, _ = A.call("POST", "/api/users", {"username": uname, "password": pw, "role": "auditor", "display_name": "E2E auditor"})
    created["user"] = u.get("id")
    check(st == 200 and created["user"], "admin creates an auditor user")
    st, users, _ = A.call("GET", "/api/users")
    me_row = next((x for x in users.get("users", []) if x["id"] == created["user"]), {})
    check(me_row.get("role") == "auditor" and me_row.get("endpoints") is None, "the user list shows the auditor with all endpoints")
    st, _, _ = A.call("PATCH", f"/api/users/{created['user']}", {"role": "viewer"})
    st2, _, _ = A.call("PATCH", f"/api/users/{created['user']}", {"role": "auditor"})
    check(st == 200 and st2 == 200, "admin can change the role away from auditor and back")
    st, _, _ = A.call("PATCH", f"/api/users/{created['user']}", {"operator": True})
    check(st == 400, "the operator flag cannot be granted through the user API")

    U = Console()
    st, _, _ = U.call("POST", "/api/login", {"username": uname, "password": pw})
    check(st == 200, "auditor signs in")
    st, me, _ = U.call("GET", "/api/me")
    can = me.get("can", {})
    check(st == 200 and me.get("role") == "auditor" and me.get("operator") is False and can.get("view_admin") and can.get("export")
          and not any(can.get(k) for k in ("manage_users", "manage_endpoints", "manage_org", "triage", "run_checks", "operate")),
          "/api/me: auditor, view_admin, every manage_* false, not the operator")

    st, eps, _ = U.call("GET", "/api/endpoints")
    st_a, eps_a, _ = A.call("GET", "/api/endpoints")
    check(st == 200 and sorted(e["id"] for e in eps.get("endpoints", [])) == sorted(e["id"] for e in eps_a.get("endpoints", [])),
          f"auditor sees the same {len(eps_a.get('endpoints', []))} endpoints as the admin")
    ep = (eps_a.get("endpoints") or [{}])[0].get("id") or "00000000-0000-0000-0000-000000000000"

    leaks = (invite_token, hook_secret, sign_secret) + ((cluster_token,) if cluster_token else ())
    reads = ["/api/users", "/api/invites", "/api/audit?limit=500", "/api/security-events", "/api/jobs", "/api/notifications/channels",
             f"/api/notifications/log?channel_id={created['channel']}", "/api/clusters", "/api/org", "/api/org/agent-updates", "/api/overview",
             "/api/incidents", "/api/alerts", "/api/allowlist", "/api/hunts", "/api/sim/campaigns", "/api/reports/weekly",
             "/api/alerts/export?format=ndjson&limit=10"]
    if eps_a.get("endpoints"):
        reads += [f"/api/endpoints/{ep}", f"/api/endpoints/{ep}/overview", f"/api/endpoints/{ep}/posture", f"/api/endpoints/{ep}/checks"]
    for p in reads:
        st, _, body = U.call("GET", p)
        leaked = [i for i, x in enumerate(leaks) if x and x.encode() in body]
        check(st == 200 and not leaked, f"auditor GET {p.split('?')[0]}: 200, no secrets" + (f" (status {st}, leaked #{leaked})" if st != 200 or leaked else ""))
    st, invs, _ = U.call("GET", "/api/invites")
    check(any(i["id"] == created["invite"] and i["link"] is None for i in invs.get("invites", [])), "auditor sees the pending invite without its link")
    st, chs, _ = U.call("GET", "/api/notifications/channels")
    c = next((x for x in chs.get("channels", []) if x["id"] == created["channel"]), {})
    check(c.get("target") == "https://hooks.example.com/..." and c.get("has_secret") is True, "auditor sees the channel's host only, and that it has a secret")
    st, _, body = U.call("GET", f"/api/clusters/{created['cluster']}/manifest")
    check(st == 403 and not (cluster_token and cluster_token.encode() in body), "auditor GET cluster manifest: 403")
    st, _, _ = U.call("GET", "/api/install-progress/0000000000000000")
    check(st == 404, "auditor GET /api/install-progress/{key}: allowed (404 for an unknown key, not 403)")
    st, _, _ = U.call("GET", "/api/operator/orgs")
    check(st == 404, "auditor is not the operator (operator routes 404)")

    # ---- every change refused
    me_id = me.get("user_id")
    muts = [("POST", "/api/users", {"username": f"x-{tag}", "password": "p" * 12, "role": "admin"}),
            ("PATCH", f"/api/users/{me_id}", {"role": "admin"}), ("PATCH", f"/api/users/{created['user']}", {"display_name": "x"}),
            ("DELETE", "/api/users/1", None), ("POST", "/api/invites", {"role": "admin"}), ("DELETE", f"/api/invites/{created['invite']}", None),
            ("POST", "/api/endpoints", {"name": "x"}), ("POST", f"/api/endpoints/{ep}/config", {"config": {"sigma": "high"}}),
            ("POST", f"/api/endpoints/{ep}/approved-executables", {"executables": ["/bin/x"]}), ("POST", f"/api/endpoints/{ep}/retire", None),
            ("DELETE", f"/api/endpoints/{ep}", None), ("POST", f"/api/endpoints/{ep}/commands", {"command": "refetch_bundle"}),
            ("POST", f"/api/endpoints/{ep}/retrain", None), ("POST", f"/api/endpoints/{ep}/respond", {"action": "isolate", "reason": "x"}),
            ("POST", f"/api/endpoints/{ep}/checks", None), ("POST", "/api/allowlist", {"kind": "program", "value": "/bin/x"}),
            ("DELETE", "/api/allowlist/1", None), ("PATCH", "/api/org", {"name": "renamed"}), ("PATCH", "/api/org/agent-updates", {"agent_update": "manual"}),
            ("PUT", "/api/org/sso", {"provider": "google", "client_id": "abc", "domains": ["example.org"]}), ("POST", "/api/org/sso/verify", None),
            ("DELETE", "/api/org/sso", None), ("POST", "/api/notifications/channels", {"name": "x", "kind": "webhook", "target": "https://example.org/x"}),
            ("PATCH", f"/api/notifications/channels/{created['channel']}", {"enabled": True}),
            ("POST", f"/api/notifications/channels/{created['channel']}/test", None),
            ("DELETE", f"/api/notifications/channels/{created['channel']}", None), ("POST", "/api/clusters", {"cluster": "x"}),
            ("POST", f"/api/clusters/{created['cluster']}/revoke", None), ("POST", "/api/alerts/1", {"status": "closed"}),
            ("POST", "/api/incidents/1/assign", {"user_id": me_id}), ("POST", "/api/incidents/1/notes", {"text": "x"}),
            ("POST", "/api/incidents/1/status", {"status": "resolved"}), ("POST", "/api/hunts", {"q": "x", "kind": "process"}),
            ("POST", "/api/sim/campaigns", {"endpoint_id": ep})]
    bad = []
    for m, p, b in muts:
        st, _, _ = U.call(m, p, b)
        if st != 403:
            bad.append(f"{m} {p}: {st}")
    check(not bad, f"auditor refused (403) on all {len(muts)} changes tried" + (f": {bad}" if bad else ""))
    st, chs, _ = A.call("GET", "/api/notifications/channels")
    c = next((x for x in chs.get("channels", []) if x["id"] == created["channel"]), {})
    st2, invs, _ = A.call("GET", "/api/invites")
    st3, org, _ = A.call("GET", "/api/org")
    check(c.get("enabled") is False and any(i["id"] == created["invite"] for i in invs.get("invites", [])) and org.get("org", {}).get("name") != "renamed",
          "nothing changed (channel still disabled, invite still pending, organisation not renamed)")
    st, logs, _ = A.call("GET", "/api/audit?limit=200")
    refused = [e for e in logs.get("entries", []) if e.get("who") in (uname, "E2E auditor") and e.get("status") == 403]
    check(len(refused) >= len(muts) - 2, f"the auditor's refused attempts are in the audit log ({len(refused)})")
    st, _, _ = U.call("POST", "/api/me/sessions/end")
    check(st == 200, "the auditor can still manage their own sessions (as a viewer can)")
finally:
    # ---- clean up everything this run created
    if created.get("user"):
        st, _, _ = A.call("DELETE", f"/api/users/{created['user']}")
        check(st == 200, "cleanup: auditor user deleted")
    if created.get("invite"):
        A.call("DELETE", f"/api/invites/{created['invite']}")
    if created.get("channel"):
        A.call("DELETE", f"/api/notifications/channels/{created['channel']}")
    if created.get("cluster"):
        A.call("POST", f"/api/clusters/{created['cluster']}/revoke")
    st, users, _ = A.call("GET", "/api/users")
    check(not any(x["role"] == "auditor" for x in users.get("users", [])), "cleanup: no auditor left in the organisation")

print(f"{'all passed' if not fails else f'{fails} FAILED'}")
sys.exit(1 if fails else 0)
