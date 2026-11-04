"""Allow list: what the customer has reviewed and accepts as normal, so it stops alerting.

Three kinds of entry, each for all endpoints or for selected endpoints:
  program    a program path or name (e.g. /usr/bin/links): no "new program" alerts for it
  address    an IP address or network (CIDR, e.g. 203.0.113.0/24): treated as trusted by the data-flow rules
  detection  one specific detection, the (rule, key) pair an alert carries (e.g. untrusted_exec on /opt/app/run.sh)

Enforcement happens in two places:
  * the agent gets the merged list with its configuration (status poll) and applies it before alerting
    (approved_executables, trusted_addresses, suppressed_detections), no new model needed;
  * the server marks alerts that match an entry (alerts.allowed_by) at upload and, when an entry is added, for the
    open alerts already received - allowed alerts are kept for the record but are not part of any incident.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from . import db
from .access import admin, require_endpoint, scope_list, session

router = APIRouter()
KINDS = ("program", "address", "detection")
RULE_TEXT = {"novel_executable": "New program", "untrusted_exec": "Executes a downloaded file",
             "untrusted_code_network": "Downloaded program contacts an untrusted address",
             "exfiltration": "Sensitive data sent to an untrusted address", "tainted_modify": "Untrusted modification of a file",
             "tainted_spawn": "Untrusted data starts a program",
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
        return any(k and (k == value or ("/" not in value and os.path.basename(k) == value)) for k in keys)
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
        return alert.get("layer") in ("learned", "corroborated") and bool(exe) and (exe == value or ("/" not in value and os.path.basename(exe) == value))
    if kind == "detection":
        return any(r.get("rule") == entry.get("rule") and r.get("key") == value for r in reasons)
    return False


def entries_for(c, endpoint_id: str | None) -> list[dict]:
    rows = db.q(c, "SELECT * FROM allowlist ORDER BY created_at")
    return [r for r in rows if endpoint_id is None or r["endpoint_ids"] is None or str(endpoint_id) in set(r["endpoint_ids"])]


def effective_config(c, endpoint_id: str, cfg: dict) -> dict:
    """The endpoint configuration as the agent sees it, with the allow list merged in."""
    es = entries_for(c, endpoint_id)
    out = dict(cfg or {})
    out["approved_executables"] = sorted(set(out.get("approved_executables") or []) | {e["value"] for e in es if e["kind"] == "program"})
    out["trusted_addresses"] = sorted({e["value"] for e in es if e["kind"] == "address"})
    out["suppressed_detections"] = sorted({(e["rule"], e["value"]) for e in es if e["kind"] == "detection"})
    out["suppressed_detections"] = [list(x) for x in out["suppressed_detections"]]
    return out


def mark_alerts(c, entry: dict, where_status=("open", "ack")) -> int:
    """Mark matching alerts (in the entry's scope) as allowed; -> number of alerts marked."""
    params = [list(where_status)]
    q = ("SELECT id, endpoint_id, ntype, label, coalesce(layer,'learned') AS layer, rule, reasons FROM alerts "
         "WHERE allowed_by IS NULL AND status = ANY(%s)")
    if entry.get("endpoint_ids") is not None:
        q += " AND endpoint_id = ANY(%s::uuid[])"; params.append(list(entry["endpoint_ids"]))
    ids = [a["id"] for a in db.q(c, q, tuple(params)) if matches(entry, a)]
    if ids:
        db.q(c, "UPDATE alerts SET allowed_by=%s, status='false_positive' WHERE id = ANY(%s)", (entry["id"], ids))
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
                db.q(c, "UPDATE alerts SET allowed_by=%s, status='false_positive' WHERE id=%s", (e["id"], a["id"]))
                break


def forget_endpoint(c, endpoint_id: str) -> None:
    """A retired endpoint: entries only for it are removed, multi-endpoint entries lose it."""
    for e in db.q(c, "SELECT id, endpoint_ids FROM allowlist WHERE endpoint_ids ? %s", (endpoint_id,)):
        rest = [x for x in e["endpoint_ids"] if x != endpoint_id]
        if rest:
            db.q(c, "UPDATE allowlist SET endpoint_ids=%s WHERE id=%s", (json.dumps(rest), e["id"]))
        else:
            db.q(c, "DELETE FROM allowlist WHERE id=%s", (e["id"],))
            db.q(c, "UPDATE alerts SET allowed_by=NULL WHERE allowed_by=%s", (e["id"],))


def migrate(c) -> None:
    """0.4: per-endpoint approved_executables in the endpoint configuration become allow-list entries."""
    for ep in db.q(c, "SELECT id, config FROM endpoints WHERE config ? 'approved_executables' AND jsonb_array_length(config->'approved_executables') > 0"):
        for prog in ep["config"]["approved_executables"]:
            if not db.q(c, "SELECT 1 FROM allowlist WHERE kind='program' AND value=%s AND endpoint_ids = %s::jsonb", (prog, json.dumps([str(ep["id"])])), one=True):
                db.q(c, "INSERT INTO allowlist (kind, value, endpoint_ids, note) VALUES ('program', %s, %s, 'approved before 0.4')",
                     (prog, json.dumps([str(ep["id"])])))
        db.q(c, "UPDATE endpoints SET config = config - 'approved_executables' WHERE id=%s", (ep["id"],))
    for ep in db.q(c, "SELECT id FROM endpoints WHERE phase='retired'"):
        forget_endpoint(c, str(ep["id"]))


# ---------------------------------------------------------------------------------------------- API
def _out(r: dict, names: dict, counts: dict) -> dict:
    return {"id": r["id"], "kind": r["kind"], "value": r["value"], "rule": r["rule"],
            "rule_text": RULE_TEXT.get(r["rule"] or "", r["rule"]),
            "endpoints": None if r["endpoint_ids"] is None else [{"id": e, "name": names.get(e, "(removed endpoint)")} for e in r["endpoint_ids"]],
            "note": r["note"], "created_by": r["created_by_name"], "created_at": r["created_at"], "alerts_allowed": counts.get(r["id"], 0)}


@router.get("/api/allowlist")
def list_allowlist(s=Depends(session), endpoint_id: str | None = None):
    if endpoint_id:
        require_endpoint(s, endpoint_id)
    scope = scope_list(s)
    with db.conn() as c:
        rows = db.q(c, "SELECT a.*, u.username AS created_by_name FROM allowlist a LEFT JOIN users u ON u.id=a.created_by ORDER BY a.created_at DESC")
        names = {str(r["id"]): r["name"] for r in db.q(c, "SELECT id, name FROM endpoints")}
        counts = {r["allowed_by"]: r["n"] for r in db.q(c, "SELECT allowed_by, count(*) AS n FROM alerts WHERE allowed_by IS NOT NULL GROUP BY 1")}
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
    note: str | None = Field(default=None, max_length=500)
    resolve_open: bool = True


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
            eps = _check_endpoint_ids(c, req.endpoints)
            if not eps:
                raise HTTPException(400, "choose at least one endpoint, or all endpoints")
        dup = db.q(c, "SELECT id FROM allowlist WHERE kind=%s AND value=%s AND coalesce(rule,'')=%s AND endpoint_ids IS NOT DISTINCT FROM %s::jsonb",
                   (req.kind, value, req.rule or "", json.dumps(eps) if eps is not None else None), one=True)
        if dup:
            raise HTTPException(409, "this entry is already on the allow list")
        row = db.q(c, "INSERT INTO allowlist (kind, value, rule, endpoint_ids, note, created_by) VALUES (%s,%s,%s,%s,%s,%s) RETURNING *",
                   (req.kind, value, req.rule, json.dumps(eps) if eps is not None else None, (req.note or "").strip() or None, s["u"]), one=True)
        n = mark_alerts(c, row) if req.resolve_open else 0
    return {"ok": True, "id": row["id"], "alerts_allowed": n}


@router.delete("/api/allowlist/{entry_id}")
def delete_entry(entry_id: int, s=Depends(admin)):
    with db.conn() as c:
        if not db.q(c, "DELETE FROM allowlist WHERE id=%s RETURNING id", (entry_id,), one=True):
            raise HTTPException(404, "not found")
        db.q(c, "UPDATE alerts SET allowed_by=NULL WHERE allowed_by=%s", (entry_id,))   # they stay marked as false alarms
    return {"ok": True}


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
