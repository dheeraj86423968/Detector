import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowUpRight, Download, ListChecks, Search, ShieldCheck } from "lucide-react";
import { AllowAlertDialog, allowedText } from "../allowlist";
import { Endpoint, IncidentSummary, post, RawAlert, useApi, useCan } from "../api";
import { ALERT_STATUS, DETECTION, entityOf, fmtDateTime, fmtRel, plural, reasonText, SEVERITIES, SEVERITY_LABEL, midTrunc, shortCmd } from "../format";
import { IncidentTable } from "../incidents";
import { Card, cx, DetectionTag, Empty, ErrorState, Loading, Mid, NodeIcon, PageHeader, PathText, ShowMore, StatusBadge, Tabs, Toggle, useShowMore, useToast } from "../ui";

const STATUS_FILTERS = [
  { id: "open", label: "Active" }, { id: "investigating", label: "Investigating" }, { id: "true_positive", label: "Confirmed threat" },
  { id: "resolved", label: "Resolved" }, { id: "false_positive", label: "False alarm" }, { id: "all", label: "All statuses" },
];

export default function Incidents() {
  const [sp, setSp] = useSearchParams();
  const tab = sp.get("tab") === "alerts" ? "alerts" : "incidents";
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n, { replace: true }); };
  const eps = useApi<{ endpoints: Endpoint[] }>("/api/endpoints");
  return (
    <div className="page">
      <PageHeader title="Incidents" subtitle="Each incident groups the detections on one endpoint that happened close together, so you can review an attack as one story." />
      <Tabs value={tab} onChange={v => set("tab", v === "incidents" ? "" : v)} tabs={[{ id: "incidents", label: "Incidents" }, { id: "alerts", label: "All alerts" }]} />
      {tab === "incidents" ? <IncidentList sp={sp} set={set} eps={eps.data?.endpoints || []} /> : <AlertList sp={sp} set={set} eps={eps.data?.endpoints || []} />}
    </div>
  );
}

function EndpointSelect({ value, onChange, eps }: { value: string; onChange: (v: string) => void; eps: Endpoint[] }) {
  const list = eps.filter(e => e.state !== "retired" || e.id === value);
  return (
    <select value={value} onChange={e => onChange(e.target.value)} aria-label="Endpoint">
      <option value="">All endpoints</option>
      {list.map(e => <option key={e.id} value={e.id}>{e.name}{e.state === "retired" ? " (retired)" : ""}</option>)}
    </select>
  );
}

function IncidentList({ sp, set, eps }: { sp: URLSearchParams; set: (k: string, v: string) => void; eps: Endpoint[] }) {
  const status = sp.get("status") || "open", sev = sp.get("severity") || "", ep = sp.get("endpoint_id") || "", owner = sp.get("owner") || "";
  const [q, setQ] = useState("");
  const qs = new URLSearchParams({ status, limit: "500" }); if (sev) qs.set("severity", sev); if (ep) qs.set("endpoint_id", ep); if (owner) qs.set("assignee", owner);
  const { data, error, loading, reload } = useApi<{ incidents: IncidentSummary[] }>(`/api/incidents?${qs}`, 30000);
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (data?.incidents || []).filter(i => !t || i.title.toLowerCase().includes(t) || i.endpoint_name.toLowerCase().includes(t) || i.tactics.some(x => x.toLowerCase().includes(t)) || !!i.behaviours?.some(b => b.label.toLowerCase().includes(t)));
  }, [data, q]);
  const filtered = status !== "all" || sev || ep || q || owner;
  const page = useShowMore(rows, 50, `${status}|${sev}|${ep}|${q}|${owner}`);
  const protectedN = eps.filter(e => e.state === "protected").length;
  return (
    <Card pad={false}>
      <div className="filters">
        <div className="search"><Search size={15} /><input placeholder="Search incidents" value={q} onChange={e => setQ(e.target.value)} /></div>
        <select value={status} onChange={e => set("status", e.target.value === "open" ? "" : e.target.value)} aria-label="Status">
          {STATUS_FILTERS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
        </select>
        <select value={sev} onChange={e => set("severity", e.target.value)} aria-label="Severity">
          <option value="">All severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
        </select>
        <EndpointSelect value={ep} onChange={v => set("endpoint_id", v)} eps={eps} />
        <select value={owner} onChange={e => set("owner", e.target.value)} aria-label="Owner">
          <option value="">Any owner</option><option value="me">Mine</option><option value="none">No owner yet</option>
        </select>
        <div className="filters-end muted">{data ? plural(rows.length, "incident") : ""}</div>
      </div>
      {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
        rows.length === 0 ? (
          <Empty icon={<ShieldCheck size={22} />} title={status === "open" && !sev && !ep && !q ? "No open incidents" : filtered ? "No incidents match these filters" : "No incidents yet"}
            text={status === "open" && !sev && !ep && !q ? (protectedN ? `Nothing needs your attention. Detection is active on ${plural(protectedN, "endpoint")}.` : eps.length ? "No endpoint is protected yet. Endpoints start detecting once they have learned their normal behaviour." : "Add an endpoint to start collecting activity.") : "Try a different status, severity or endpoint."}
            action={filtered ? <button className="btn sm" onClick={() => { set("status", "all"); set("severity", ""); set("endpoint_id", ""); setQ(""); }}>Show all incidents</button> : undefined} />
        ) : <><IncidentTable rows={page.visible} showEndpoint={!ep} /><ShowMore s={page} noun={["incident", "incidents"]} /></>}
    </Card>
  );
}

const ALERT_ACTIONS: [string, string][] = [["ack", "Acknowledge"], ["true_positive", "Confirm threat"], ["false_positive", "False alarm"], ["closed", "Close"], ["open", "Reopen"]];

function AlertList({ sp, set, eps }: { sp: URLSearchParams; set: (k: string, v: string) => void; eps: Endpoint[] }) {
  const can = useCan(); const toast = useToast();
  const ep = sp.get("endpoint_id") || "", status = sp.get("astatus") || "", layer = sp.get("type") || "";
  const showAllowed = sp.get("allowed") === "1";
  const [allowing, setAllowing] = useState<RawAlert | null>(null);
  const qs = new URLSearchParams({ limit: "500" }); if (ep) qs.set("endpoint_id", ep); if (status) qs.set("status", status); if (layer) qs.set("layer", layer);
  const allowedQs = new URLSearchParams(qs); allowedQs.set("allowed", "true"); allowedQs.set("limit", "5000");
  if (!showAllowed) qs.set("allowed", "false");     // filtered on the server, so allowed alerts never crowd out the rest
  const { data, error, loading, reload } = useApi<{ alerts: RawAlert[] }>(`/api/alerts?${qs}`, 30000);
  const allowedData = useApi<{ alerts: RawAlert[] }>(`/api/alerts?${allowedQs}`, 60000);
  // alert -> incident (incident = the endpoint's alerts close in time; its span covers the alert's window)
  const incQs = new URLSearchParams({ status: "all", limit: "2000" }); if (ep) incQs.set("endpoint_id", ep);
  const incs = useApi<{ incidents: IncidentSummary[] }>(`/api/incidents?${incQs}`);
  const incidentOf = useMemo(() => {
    const by: Record<string, IncidentSummary[]> = {};
    for (const i of incs.data?.incidents || []) (by[i.endpoint_id] ||= []).push(i);
    const byId: Record<number, IncidentSummary> = {};
    for (const i of incs.data?.incidents || []) byId[i.id] = i;
    return (a: RawAlert) => (a.incident_id != null ? byId[a.incident_id] : undefined)
      || (by[a.endpoint_id] || []).find(i => a.window_start_ns >= i.first_ns && a.window_start_ns <= i.last_ns);
  }, [incs.data]);
  const exportQs = new URLSearchParams(); if (ep) exportQs.set("endpoint_id", ep); if (status) exportQs.set("status", status);
  const setStatus = async (a: RawAlert, s: string) => {
    try { await post(`/api/alerts/${a.id}`, { status: s }); toast(`Alert marked as ${ALERT_STATUS[s].toLowerCase()}`); reload(); }
    catch (e: any) { toast(e.message, "err"); }
  };
  const fetched = data?.alerts || [];
  const allowedN = allowedData.data?.alerts.length ?? 0;
  const rows = showAllowed ? fetched : fetched.filter(a => a.allowed_by == null);
  const page = useShowMore(rows, 50, `${ep}|${status}|${layer}|${showAllowed}`);
  return (
    <Card pad={false}>
      <div className="filters">
        <EndpointSelect value={ep} onChange={v => set("endpoint_id", v)} eps={eps} />
        <select value={layer} onChange={e => set("type", e.target.value)} aria-label="Detection type">
          <option value="">All detection types</option>
          {Object.entries(DETECTION).filter(([k]) => k !== "evidence").map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <select value={status} onChange={e => set("astatus", e.target.value)} aria-label="Status">
          <option value="">All statuses</option>
          {["open", "ack", "true_positive", "false_positive", "closed"].map(s => <option key={s} value={s}>{ALERT_STATUS[s]}</option>)}
        </select>
        <label className="inline-toggle" title="Alerts covered by the allow list are kept for the record as false alarms"><Toggle checked={showAllowed} onChange={v => set("allowed", v ? "1" : "")} label="Show allowed alerts" />Show allowed{allowedN ? ` (${allowedN.toLocaleString()})` : ""}</label>
        <div className="filters-end">
          <span className="muted">{data ? `${plural(rows.length, "alert")}${fetched.length >= 500 ? " (of the newest 500)" : ""}` : ""}</span>
          {can.export && <><a className="btn sm" href={`/api/alerts/export?${new URLSearchParams([...exportQs, ["format", "csv"]])}`} download><Download size={14} />CSV</a>
          <a className="btn sm" href={`/api/alerts/export?${new URLSearchParams([...exportQs, ["format", "ndjson"]])}`} download><Download size={14} />NDJSON</a></>}
        </div>
      </div>
      {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
        rows.length === 0 ? <Empty icon={<ShieldCheck size={22} />} title="No alerts" text={ep || status || layer ? "No alerts match these filters." : allowedN ? `All ${plural(allowedN, "alert")} shown here are covered by the allow list.` : "Alerts appear here as protected endpoints detect suspicious activity."}
          action={!showAllowed && allowedN > 0 ? <button className="btn sm" onClick={() => set("allowed", "1")}>Show allowed alerts</button> : undefined} /> : (<>
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th style={{ width: 168 }}>Time</th><th style={{ width: "14%" }}>Endpoint</th><th style={{ width: 172 }}>Detection</th><th>What was detected</th><th style={{ width: 132 }}>Status</th><th style={{ width: can.triage ? 236 : 110 }}></th></tr></thead>
              <tbody>{page.visible.map(a => {
                const en = entityOf(a.ntype, a.label); const inc = incidentOf(a);
                return (
                  <tr key={a.id} className={cx(a.allowed_by != null && "row-allowed")}>
                    <td><div className="nowrap" title={fmtDateTime(a.window_start_ns, true)}>{fmtDateTime(a.window_start_ns)}</div><div className="muted sm nowrap">{fmtRel(a.window_start_ns)}</div></td>
                    <td><Link to={`/endpoints/${a.endpoint_id}`} className="subtle-link block-link"><Mid text={a.endpoint} /></Link></td>
                    <td><DetectionTag type={a.layer} /></td>
                    <td className="cell-main">
                      <div className="entity" title={en.full}><NodeIcon type={en.kind} /><Mid text={en.name} className="mono entity-name" title={null} />{en.kind !== "network" && en.full !== en.name && <span className="muted mono ellipsis entity-full">{en.kind === "file" ? midTrunc(en.full, 48) : shortCmd(en.full)}</span>}</div>
                      <div className="reason clamp2" title={reasonText(a.layer, a.reason)}><PathText text={reasonText(a.layer, a.reason)} /></div>
                    </td>
                    <td><StatusBadge status={a.status} />{a.allowed_by != null && <div><Link to="/allowlist" className="pill ok allowed-pill" title={`Covered by allow-list entry ${a.allowed_by}`}><ListChecks size={12} />Allowed</Link></div>}</td>
                    <td><div className="row-actions">
                      {inc && <Link className="btn sm" to={`/incidents/${inc.id}`} title={`Open incident: ${inc.title}`}>Incident<ArrowUpRight size={13} /></Link>}
                      {can.triage && <select className="sm" value="" onChange={e => e.target.value === "allow" ? setAllowing(a) : e.target.value && setStatus(a, e.target.value)} aria-label="Set status">
                        <option value="">Triage…</option>
                        {ALERT_ACTIONS.filter(([s]) => s !== a.status).map(([s, l]) => <option key={s} value={s}>{l}</option>)}
                        {can.manage_endpoints && a.allowed_by == null && <option value="allow">Add to allow list…</option>}
                      </select>}
                      {!can.triage && can.manage_endpoints && a.allowed_by == null && <button className="btn sm" onClick={() => setAllowing(a)}>Allow…</button>}
                    </div></td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
          <ShowMore s={page} noun={["alert", "alerts"]} />
        </>)}
      {allowing && <AllowAlertDialog alertId={allowing.id} endpoint={{ id: allowing.endpoint_id, name: allowing.endpoint }} subject={entityOf(allowing.ntype, allowing.label).full.split("\n")[0]}
        onClose={() => setAllowing(null)} onDone={n => { toast(allowedText(n)); reload(); incs.reload(); }} />}
    </Card>
  );
}
