import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowUpRight, Download, Search, ShieldCheck } from "lucide-react";
import { Endpoint, IncidentSummary, post, RawAlert, useApi, useCan } from "../api";
import { ALERT_STATUS, DETECTION, entityOf, fmtDateTime, fmtRel, plural, reasonText, SEVERITIES, SEVERITY_LABEL } from "../format";
import { IncidentTable } from "../incidents";
import { Card, DetectionTag, Empty, ErrorState, Loading, NodeIcon, PageHeader, StatusBadge, Tabs, useToast } from "../ui";

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
  const status = sp.get("status") || "open", sev = sp.get("severity") || "", ep = sp.get("endpoint_id") || "";
  const [q, setQ] = useState("");
  const qs = new URLSearchParams({ status, limit: "500" }); if (sev) qs.set("severity", sev); if (ep) qs.set("endpoint_id", ep);
  const { data, error, loading, reload } = useApi<{ incidents: IncidentSummary[] }>(`/api/incidents?${qs}`, 30000);
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (data?.incidents || []).filter(i => !t || i.title.toLowerCase().includes(t) || i.endpoint_name.toLowerCase().includes(t) || i.tactics.some(x => x.toLowerCase().includes(t)));
  }, [data, q]);
  const filtered = status !== "all" || sev || ep || q;
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
        <div className="filters-end muted">{data ? plural(rows.length, "incident") : ""}</div>
      </div>
      {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
        rows.length === 0 ? (
          <Empty icon={<ShieldCheck size={22} />} title={filtered ? "No incidents match these filters" : "No incidents"}
            text={status === "open" && !sev && !ep && !q ? `Nothing needs your attention. Detection is active on ${plural(protectedN, "endpoint")}.` : "Try a different status, severity or endpoint."}
            action={filtered ? <button className="btn sm" onClick={() => { set("status", "all"); set("severity", ""); set("endpoint_id", ""); setQ(""); }}>Show all incidents</button> : undefined} />
        ) : <IncidentTable rows={rows} showEndpoint={!ep} />}
    </Card>
  );
}

const ALERT_ACTIONS: [string, string][] = [["ack", "Acknowledge"], ["true_positive", "Confirm threat"], ["false_positive", "False alarm"], ["closed", "Close"], ["open", "Reopen"]];

function AlertList({ sp, set, eps }: { sp: URLSearchParams; set: (k: string, v: string) => void; eps: Endpoint[] }) {
  const can = useCan(); const toast = useToast();
  const ep = sp.get("endpoint_id") || "", status = sp.get("astatus") || "", layer = sp.get("type") || "";
  const qs = new URLSearchParams({ limit: "500" }); if (ep) qs.set("endpoint_id", ep); if (status) qs.set("status", status); if (layer) qs.set("layer", layer);
  const { data, error, loading, reload } = useApi<{ alerts: RawAlert[] }>(`/api/alerts?${qs}`, 30000);
  // alert -> incident (incident = the endpoint's alerts close in time; its span covers the alert's window)
  const incQs = new URLSearchParams({ status: "all", limit: "2000" }); if (ep) incQs.set("endpoint_id", ep);
  const incs = useApi<{ incidents: IncidentSummary[] }>(`/api/incidents?${incQs}`);
  const incidentOf = useMemo(() => {
    const by: Record<string, IncidentSummary[]> = {};
    for (const i of incs.data?.incidents || []) (by[i.endpoint_id] ||= []).push(i);
    return (a: RawAlert) => (by[a.endpoint_id] || []).find(i => a.window_start_ns >= i.first_ns && a.window_start_ns <= i.last_ns);
  }, [incs.data]);
  const exportQs = new URLSearchParams(); if (ep) exportQs.set("endpoint_id", ep); if (status) exportQs.set("status", status);
  const setStatus = async (a: RawAlert, s: string) => {
    try { await post(`/api/alerts/${a.id}`, { status: s }); toast(`Alert marked as ${ALERT_STATUS[s].toLowerCase()}`); reload(); }
    catch (e: any) { toast(e.message, "err"); }
  };
  const rows = data?.alerts || [];
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
        <div className="filters-end">
          <span className="muted">{data ? `${plural(rows.length, "alert")}${rows.length >= 500 ? " (newest 500)" : ""}` : ""}</span>
          <a className="btn sm" href={`/api/alerts/export?${new URLSearchParams([...exportQs, ["format", "csv"]])}`} download><Download size={14} />CSV</a>
          <a className="btn sm" href={`/api/alerts/export?${new URLSearchParams([...exportQs, ["format", "ndjson"]])}`} download><Download size={14} />NDJSON</a>
        </div>
      </div>
      {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
        rows.length === 0 ? <Empty icon={<ShieldCheck size={22} />} title="No alerts" text={ep || status || layer ? "No alerts match these filters." : "Alerts appear here as protected endpoints detect suspicious activity."} /> : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th style={{ width: 168 }}>Time</th><th style={{ width: "14%" }}>Endpoint</th><th style={{ width: 172 }}>Detection</th><th>What was detected</th><th style={{ width: 132 }}>Status</th><th style={{ width: can.triage ? 236 : 110 }}></th></tr></thead>
              <tbody>{rows.map(a => {
                const en = entityOf(a.ntype, a.label); const inc = incidentOf(a);
                return (
                  <tr key={a.id}>
                    <td><div className="nowrap" title={fmtDateTime(a.window_start_ns, true)}>{fmtDateTime(a.window_start_ns)}</div><div className="muted sm nowrap">{fmtRel(a.window_start_ns)}</div></td>
                    <td><Link to={`/endpoints/${a.endpoint_id}`} className="ellipsis subtle-link" title={a.endpoint}>{a.endpoint}</Link></td>
                    <td><DetectionTag type={a.layer} /></td>
                    <td className="cell-main">
                      <div className="entity" title={en.full}><NodeIcon type={en.kind} /><span className="mono ellipsis">{en.name}</span><span className="muted mono ellipsis entity-full">{en.full !== en.name ? en.full : ""}</span></div>
                      <div className="reason clamp2" title={reasonText(a.layer, a.reason)}>{reasonText(a.layer, a.reason)}</div>
                    </td>
                    <td><StatusBadge status={a.status} /></td>
                    <td><div className="row-actions">
                      {inc && <Link className="btn sm" to={`/incidents/${inc.id}`} title={`Open incident: ${inc.title}`}>Incident<ArrowUpRight size={13} /></Link>}
                      {can.triage && <select className="sm" value="" onChange={e => e.target.value && setStatus(a, e.target.value)} aria-label="Set status">
                        <option value="">Triage…</option>
                        {ALERT_ACTIONS.filter(([s]) => s !== a.status).map(([s, l]) => <option key={s} value={s}>{l}</option>)}
                      </select>}
                    </div></td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
        )}
    </Card>
  );
}
