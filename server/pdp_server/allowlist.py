"""Allow list: what the customer has reviewed and accepts as normal, so it stops alerting.

Three kinds of entry, each for all endpoints or for selected endpoints:
  program    a program's full path (e.g. /usr/bin/links): no "new program" alerts for it. Compared the way the agent's
             layer 1 compares programs (pdp_engine.layers.program_key), never by name alone (0.6): approving python3
             does not approve /dev/shm/x/python3. A bare name only for endpoints that record programs without paths;
             interpreters, shells and loaders need force + a reason (pdp_server.posture.check_program)
  address    an IP address or network (CIDR, e.g. 203.0.113.0/24): treated as trusted by the data-flow rules
  detection  one specific detection, the (rule, key) pair an alert carries (e.g. untrusted_exec on /opt/app/run.sh)

Enforcement happens in two places:
  * the agent gets the merged list with its configuration (status poll) and applies it before alerting
    (approved_executables, trusted_addresses, suppressed_detections), no new model needed;
  * the server marks alerts that match an entry (alerts.allowed_by) at upload and, when an entry is added, for the
    open alerts already received - allowed alerts are kept for the record but are not part of any incident.

Every addition weakens detection: it needs a reason (the note), is audited with its details and notified to the
organisation's admins (detection_weakened). Removing an entry reopens the alerts it resolved automatically (0.6).
"""
from __future__ import annotations

import ipaddress
import json
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from . import db
from .access import admin, require_endpoint, scope_list, session
from .posture import audit_change, check_program, endpoint_records_paths, entry_risks, program_matches, require_reason, weakened

router = APIRouter()
KINDS = ("program", "address", "detection")
RULE_TEXT = {"novel_executable": "New program", "untrusted_exec": "Executes a downloaded file",
             "untrusted_code_network": "Downloaded program contacts an untrusted address",
             "exfiltration": "Sensitive data sent to an untrusted address", "tainted_modify": "Untrusted modification of a file",
             "tainted_spawn": "Untrusted data starts a program", "novel_executable_repeat": "New program (another run)",
             "fleet_known_executable": "New on this endpoint, known from other endpoints",
             "learned": "Unusual behaviour (or related activity) of a program"}


def _net(value: str):
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def _exe(label: str | None) -> str | None:
    """Program of a process label 'subject <exe> <cmdline>' (the cmdline's first token when no exe was recorded)."""
    if not label or not label.startswith("subject "):
        return None
    parts = label.split(" ")
    if len(parts) > 1 and parts[1] not in ("None", "null", ""):
        return parts[1]
    return parts[2] if len(parts) > 2 and parts[2] not in ("None", "null", "") else None


def _ips_of(alert: dict) -> set[str]:
    out = set()
    for r in alert.get("reasons") or []:
        out.update(re.findall(r"untrusted (?:netflow )?([0-9a-fA-F.:]{3,})", r.get("detail") or ""))
    if alert.get("ntype") == "netflow" and alert.get("label"):
        p = alert["label"].split()
        if len(p) >= 2:
            out.add(p[1])
    return out


def matches(entry: dict, alert: dict) -> bool:
    eps = entry.get("endpoint_ids")
    if eps is not None and str(alert["endpoint_id"]) not in set(eps):
        return False
    kind, value, reasons = entry["kind"], entry["value"], alert.get("reasons") or []
    if kind == "program":
        keys = {r.get("key") for r in reasons if r.get("rule") == "novel_executable"}
        if alert.get("layer") == "novelty" and not keys:
            keys = {_exe(alert.get("label"))}
        return any(program_matches(value, k) for k in keys)
    if kind == "address":
        net = _net(value)
        if net is None or alert.get("layer") not in ("rules", "corroborated", "evidence"):
            return False
        for ip in _ips_of(alert):
            try:
                if ipaddress.ip_address(ip) in net:
                    return True
            except ValueError:
                continue
        return False
    if kind == "detection" and entry.get("rule") == "learned":    # learned / related-activity alerts of a program
        exe = _exe(alert.get("label"))
        return alert.get("layer") in ("learned", "corroborated") and bool(exe) and program_matches(value, exe)
    if kind == "detection":
        return any(r.get("rule") == entry.get("rule") and r.get("key") == value for r in reasons)
    return False


def entries_for(c, endpoint_id: str) -> list[dict]:
    """Entries that apply to an endpoint: its organisation's entries for all endpoints or naming it."""
    rows = db.q(c, "SELECT * FROM allowlist WHERE org_id = (SELECT org_id FROM endpoints WHERE id=%s) ORDER BY created_at", (endpoint_id,))
    return [r for r in rows if r["endpoint_ids"] is None or str(endpoint_id) in set(r["endpoint_ids"])]


def effective_config(c, endpoint_id: str, cfg: dict) -> dict:
    """The endpoint configuration as the agent sees it, with the allow list merged in. Program approvals come from the
    allow list only (0.6): a stray approved_executables in the stored configuration (migrated at start-up) is ignored."""
    es = entries_for(c, endpoint_id)
    out = dict(cfg or {})
    out["approved_executables"] = sorted({e["value"] for e in es if e["kind"] == "program"})
    out["trusted_addresses"] = sorted({e["value"] for e in es if e["kind"] == "address"})
    out["suppressed_detections"] = sorted({(e["rule"], e["value"]) for e in es if e["kind"] == "detection"})
    out["suppressed_detections"] = [list(x) for x in out["suppressed_detections"]]
    return out


def mark_alerts(c, entry: dict, where_status=("open", "ack")) -> int:
    """Mark matching alerts (in the entry's scope) as allowed; -> number of alerts marked."""
    params = [list(where_status)]
    q = ("SELECT id, endpoint_id, ntype, label, coalesce(layer,'learned') AS layer, rule, reasons FROM alerts "
         "WHERE allowed_by IS NULL AND status = ANY(%s)")
    q += " AND endpoint_id IN (SELECT id FROM endpoints WHERE org_id=%s)"; params.append(entry["org_id"])
    if entry.get("endpoint_ids") is not None:
        q += " AND endpoint_id = ANY(%s::uuid[])"; params.append(list(entry["endpoint_ids"]))
    ids = [a["id"] for a in db.q(c, q, tuple(params)) if matches(entry, a)]
    if ids:
        db.q(c, "UPDATE alerts SET allowed_by=%s, status='false_positive', status_by=%s, status_at=now() WHERE id = ANY(%s)",
             (entry["id"], entry.get("created_by"), ids))
    return len(ids)


def mark_new_alerts(c, endpoint_id: str, ids: list[int]) -> None:
    """Alerts just uploaded by an agent that still raised something the allow list covers (an older agent, or an
    entry added since its last configuration poll)."""
    es = entries_for(c, endpoint_id)
    if not es or not ids:
        return
    for a in db.q(c, "SELECT id, endpoint_id, ntype, label, coalesce(layer,'learned') AS layer, rule, reasons FROM alerts WHERE id = ANY(%s)", (ids,)):
        for e in es:
            if matches(e, a):
                db.q(c, "UPDATE alerts SET allowed_by=%s, status='false_positive', status_by=%s, status_at=now() WHERE id=%s",
                     (e["id"], e.get("created_by"), a["id"]))
                break


def remove_entry(c, entry: dict) -> int:
    """Delete an entry. The alerts it resolved automatically (allowed_by = the entry, status still false_positive and
    last set by the entry's creator - or never set since 0.6) are open again; alerts an analyst triaged since keep
    their verdict and only lose the link. -> number of alerts reopened."""
    db.q(c, "DELETE FROM allowlist WHERE id=%s", (entry["id"],))
    with c.cursor() as cur:
        cur.execute("UPDATE alerts SET status='open', allowed_by=NULL, status_by=NULL, status_at=now() WHERE allowed_by=%s "
                    "AND status='false_positive' AND (status_by IS NOT DISTINCT FROM %s OR (status_by IS NULL AND status_at IS NULL))",
                    (entry["id"], entry.get("created_by")))
        n = cur.rowcount
    db.q(c, "UPDATE alerts SET allowed_by=NULL WHERE allowed_by=%s", (entry["id"],))
    return n


def forget_endpoint(c, endpoint_id: str) -> None:
    """A retired endpoint: entries only for it are removed, multi-endpoint entries lose it."""
    for e in db.q(c, "SELECT id, endpoint_ids, created_by FROM allowlist WHERE endpoint_ids ? %s", (endpoint_id,)):
        rest = [x for x in e["endpoint_ids"] if x != endpoint_id]
        if rest:
            db.q(c, "UPDATE allowlist SET endpoint_ids=%s WHERE id=%s", (json.dumps(rest), e["id"]))
        else:
            remove_entry(c, e)


def migrate(c) -> None:
    """Per-endpoint approved_executables in the endpoint configuration become allow-list entries (0.4; 0.6 refuses
    the key on write, so only values stored before that, or enrolled from an older token, are left to migrate). The
    entries keep their values as they were (a migration is not a new approval) and show up in the allow list with
    their risks (name only, interpreter) and the note "migrated from endpoint config"."""
    for ep in db.q(c, "SELECT id, org_id, config FROM endpoints WHERE config ? 'approved_executables'"):
        progs = ep["config"]["approved_executables"]
        for prog in progs if isinstance(progs, list) else []:
            if not isinstance(prog, str) or not prog.strip():
                continue
            if not db.q(c, "SELECT 1 FROM allowlist WHERE kind='program' AND value=%s AND endpoint_ids = %s::jsonb", (prog, json.dumps([str(ep["id"])])), one=True):
                row = db.q(c, "INSERT INTO allowlist (kind, value, endpoint_ids, note, org_id) VALUES ('program', %s, %s, 'migrated from endpoint config', %s) "
                              "RETURNING id", (prog, json.dumps([str(ep["id"])]), ep["org_id"]), one=True)
                db.q(c, "INSERT INTO audit_log (org_id, username, action, target, status, detail) VALUES (%s, 'system', %s, %s, 200, %s)",
                     (ep["org_id"], "allow list: entry migrated from endpoint config", f"entry_id={row['id']}",
                      json.dumps({"value": prog, "endpoint_id": str(ep["id"]), "risks": entry_risks({"kind": "program", "value": prog})})))
        db.q(c, "UPDATE endpoints SET config = config - 'approved_executables' WHERE id=%s", (ep["id"],))
    for ep in db.q(c, "SELECT id FROM endpoints WHERE phase='retired'"):
        forget_endpoint(c, str(ep["id"]))


# ---------------------------------------------------------------------------------------------- API
def _out(r: dict, names: dict, counts: dict) -> dict:
    return {"id": r["id"], "kind": r["kind"], "value": r["value"], "rule": r["rule"],
            "rule_text": RULE_TEXT.get(r["rule"] or "", r["rule"]),
            "endpoints": None if r["endpoint_ids"] is None else [{"id": e, "name": names.get(e, "(removed endpoint)")} for e in r["endpoint_ids"]],
            "note": r["note"], "created_by": r["created_by_name"], "created_at": r["created_at"], "alerts_allowed": counts.get(r["id"], 0),
            "force": bool(r.get("forced")), "risks": entry_risks(r)}


@router.get("/api/allowlist")
def list_allowlist(s=Depends(session), endpoint_id: str | None = None):
    if endpoint_id:
        require_endpoint(s, endpoint_id)
    scope = scope_list(s)
    with db.conn() as c:
        rows = db.q(c, "SELECT a.*, u.username AS created_by_name FROM allowlist a LEFT JOIN users u ON u.id=a.created_by "
                       "WHERE a.org_id=%s ORDER BY a.created_at DESC", (s["org"],))
        names = {str(r["id"]): r["name"] for r in db.q(c, "SELECT id, name FROM endpoints WHERE org_id=%s", (s["org"],))}
        counts = {r["allowed_by"]: r["n"] for r in db.q(c, "SELECT allowed_by, count(*) AS n FROM alerts WHERE allowed_by IS NOT NULL "
                                                           "AND endpoint_id = ANY(%s::uuid[]) GROUP BY 1", (scope or [],))}
    out = []
    for r in rows:
        eps = r["endpoint_ids"]
        if endpoint_id and eps is not None and endpoint_id not in eps:
            continue
        if scope is not None and eps is not None and not (set(eps) & set(scope)):
            continue
        if scope is not None and eps is not None:   # a scoped user sees only their endpoints' names
            r = dict(r, endpoint_ids=[e for e in eps if e in set(scope)])
        out.append(_out(r, names, counts))
    return {"ok": True, "entries": out, "kinds": [
        {"id": "program", "label": "Program", "text": "A program path or name that may run without a 'new program' alert"},
        {"id": "address", "label": "Network address", "text": "An IP address or network (CIDR) that data-flow rules treat as trusted"},
        {"id": "detection", "label": "Specific detection", "text": "One detection (rule and subject) that should not alert again"}]}


class NewEntry(BaseModel):
    kind: str
    value: str = Field(min_length=1, max_length=4096)
    rule: str | None = None
    endpoints: list[str] | None = None
    note: str | None = Field(default=None, max_length=500)       # why this is normal: required (the reason, 0.6)
    reason: str | None = Field(default=None, max_length=500)     # accepted as the note when no note is given
    force: bool = False                                          # allow an interpreter / shell / loader anyway
    resolve_open: bool = True


PROGRAM_RULES = ("learned", "novel_executable")      # detection entries whose value is a program


def _scope_text(c, eps) -> str:
    if eps is None:
        return "all endpoints"
    names = [r["name"] for r in db.q(c, "SELECT name FROM endpoints WHERE id = ANY(%s::uuid[]) ORDER BY name", (list(eps),))]
    return ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")


def create_entry(c, s: dict, kind: str, value: str, rule: str | None, eps: list[str] | None, note: str | None,
                 force: bool = False, resolve_open: bool = True) -> tuple[dict, int]:
    """Validate and add one entry (the caller checked kind / rule / endpoint ids) with its audit row and the
    detection_weakened event -> (row, alerts resolved)."""
    value = value.strip()
    what = (f"{RULE_TEXT.get(rule, rule).lower()} for {value}" if kind == "detection" else
            f"{'program' if kind == 'program' else 'trusted address'} {value}")
    scope = _scope_text(c, eps)
    reason = require_reason([f"allow-list entry added: {what} on {scope}"], note)
    interp = False
    if kind == "program" or (kind == "detection" and rule in PROGRAM_RULES):
        name_ok = eps is not None and all(endpoint_records_paths(c, e) is False for e in eps)
        chk = check_program(value, name_only_ok=name_ok, force=force, reason=reason)
        value, interp = chk["value"], chk["interpreter"]
    change = f"allow-list entry added: {what} on {scope}" + (" (interpreter / shell, allowed with force)" if interp else "")
    dup = db.q(c, "SELECT id FROM allowlist WHERE org_id=%s AND kind=%s AND value=%s AND coalesce(rule,'')=%s AND endpoint_ids IS NOT DISTINCT FROM %s::jsonb",
               (s["org"], kind, value, rule or "", json.dumps(eps) if eps is not None else None), one=True)
    if dup:
        raise HTTPException(409, "this entry is already on the allow list")
    row = db.q(c, "INSERT INTO allowlist (kind, value, rule, endpoint_ids, note, created_by, org_id, forced) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
               (kind, value, rule, json.dumps(eps) if eps is not None else None, reason, s["u"], s["org"], bool(interp and force)), one=True)
    n = mark_alerts(c, row) if resolve_open else 0
    entry = {"id": row["id"], "kind": kind, "value": value, "rule": rule, "endpoints": eps, "note": reason, "forced": bool(interp and force)}
    audit_change(c, s, "allow list: entry added", f"entry_id={row['id']}", before=None, after=entry, reason=reason,
                 extra={"weakens": [change], "alerts_resolved": n})
    weakened(c, s, [change], reason, subject=scope, endpoint_id=eps[0] if eps and len(eps) == 1 else None,
             extra={"entry_id": row["id"], "alerts_resolved": n})
    return row, n


@router.post("/api/allowlist")
def add_entry(req: NewEntry, s=Depends(admin)):
    value = req.value.strip()
    if req.kind not in KINDS:
        raise HTTPException(400, f"kind must be one of {list(KINDS)}")
    if req.kind == "address":
        net = _net(value)
        if net is None:
            raise HTTPException(400, "not an IP address or network (e.g. 203.0.113.7 or 203.0.113.0/24)")
        if net.prefixlen < (16 if net.version == 4 else 48):
            raise HTTPException(400, "the network is too large to trust (at most a /16 for IPv4, /48 for IPv6)")
        value = str(net) if net.num_addresses > 1 else str(net.network_address)
    if req.kind == "detection" and req.rule not in RULE_TEXT:
        raise HTTPException(400, f"rule must be one of {sorted(RULE_TEXT)}")
    if req.kind != "detection" and req.rule:
        raise HTTPException(400, "rule is only used for kind 'detection'")
    with db.conn() as c:
        eps = None
        if req.endpoints is not None:
            from .api import _check_endpoint_ids
            eps = _check_endpoint_ids(c, req.endpoints, s)
            if not eps:
                raise HTTPException(400, "choose at least one endpoint, or all endpoints")
        row, n = create_entry(c, s, req.kind, value, req.rule, eps, req.note or req.reason, req.force, req.resolve_open)
    return {"ok": True, "id": row["id"], "alerts_allowed": n}


@router.delete("/api/allowlist/{entry_id}")
def delete_entry(entry_id: int, s=Depends(admin)):
    """Remove an entry; the alerts it resolved automatically are open again (remove_entry)."""
    with db.conn() as c:
        e = db.q(c, "SELECT * FROM allowlist WHERE id=%s AND org_id=%s", (entry_id, s["org"]), one=True)
        if not e:
            raise HTTPException(404, "not found")
        n = remove_entry(c, e)
        audit_change(c, s, "allow list: entry removed", f"entry_id={entry_id}",
                     before={"kind": e["kind"], "value": e["value"], "rule": e["rule"], "endpoints": e["endpoint_ids"], "note": e["note"]},
                     after=None, extra={"alerts_reopened": n})
    return {"ok": True, "alerts_reopened": n}


@router.get("/api/alerts/{alert_id}/allow-options")
def allow_options(alert_id: int, s=Depends(session)):
    """What could be allowed to stop this alert, as ready-made entries for the console's 'Allow...' dialog."""
    with db.conn() as c:
        a = db.q(c, "SELECT id, endpoint_id, ntype, label, coalesce(layer,'learned') AS layer, rule, reasons, allowed_by FROM alerts WHERE id=%s", (alert_id,), one=True)
    if not a:
        raise HTTPException(404, "not found")
    require_endpoint(s, a["endpoint_id"])
    opts = []
    for r in a["reasons"] or []:
        if r.get("layer") not in ("novelty", "rules", "corroborated", "evidence") or not r.get("key"):
            continue
        if r.get("rule") == "novel_executable":
            opts.append({"kind": "program", "value": r["key"], "rule": None,
                         "title": f"Allow the program {r['key']}", "text": "It may run without a 'new program' alert."})
        elif r.get("rule") in RULE_TEXT:
            opts.append({"kind": "detection", "value": r["key"], "rule": r["rule"],
                         "title": f"Don't alert on this again: {RULE_TEXT[r['rule']].lower()} ({r['key']})",
                         "text": "Only this exact detection is allowed; the same rule still alerts for anything else."})
    if a["layer"] in ("learned", "corroborated") and _exe(a["label"]):
        exe = _exe(a["label"])
        opts.append({"kind": "detection", "value": exe, "rule": "learned",
                     "title": f"Don't raise unusual-behaviour alerts for {exe}",
                     "text": "Its other detections (new program, data-flow rules) still alert."})
    for ip in sorted(_ips_of(a)):
        opts.append({"kind": "address", "value": ip, "rule": None, "title": f"Trust the address {ip}",
                     "text": "Data-flow rules will treat this address as trusted (consider its whole network, e.g. a /24)."})
    seen, uniq = set(), []
    for o in opts:
        k = (o["kind"], o["value"], o["rule"])
        if k not in seen:
            seen.add(k); uniq.append(o)
    return {"ok": True, "alert_id": alert_id, "endpoint_id": str(a["endpoint_id"]), "allowed_by": a["allowed_by"], "options": uniq}
