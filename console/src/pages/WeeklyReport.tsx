import { Printer } from "lucide-react";
import { Link } from "react-router-dom";
import { useApi } from "../api";
import { Card, ErrorState, Loading, PageHeader, SeverityBadge, StatusBadge } from "../ui";

type Weekly = { org: string; from: string; to: string; incidents_new: number; incidents_new_by_severity: Record<string, number>; incidents_open: number;
  alerts: number; false_alarms: number; confirmed: number; endpoints: number; endpoints_online: number; endpoints_by_phase: Record<string, number>;
  top: { id: number; title: string; severity: any; endpoint: string; status: string }[] };

/** Printable weekly summary (browser print -> PDF); the same numbers as the Monday notification. */
export default function WeeklyReport() {
  const { data, error, loading, reload } = useApi<Weekly>("/api/reports/weekly");
  if (loading && !data) return <div className="page"><Loading block /></div>;
  if (error && !data) return <div className="page"><ErrorState error={error} onRetry={reload} /></div>;
  const w = data!;
  const d = (x: string) => new Date(x).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  return (
    <div className="page report">
      <PageHeader title={`Weekly summary: ${w.org}`} subtitle={`${d(w.from)} to ${d(w.to)}`}
        actions={<button className="btn no-print" onClick={() => window.print()}><Printer size={16} />Print / save as PDF</button>} />
      <div className="kpis">
        <div className="kpi"><b>{w.incidents_new}</b>new incidents</div>
        <div className="kpi"><b>{w.incidents_open}</b>still open</div>
        <div className="kpi"><b>{w.alerts}</b>alerts ({w.confirmed} confirmed, {w.false_alarms} false alarms)</div>
        <div className="kpi"><b>{w.endpoints_online} / {w.endpoints}</b>endpoints reporting</div>
      </div>
      <Card title="New incidents by severity">
        <p>{Object.entries(w.incidents_new_by_severity).map(([s, n]) => `${n} ${s}`).join(" · ")}</p>
      </Card>
      <Card title="Most important new incidents" pad={false}>
        {w.top.length === 0 ? <p className="pad muted">No new incidents this week.</p> : (
          <table className="table middle"><tbody>{w.top.map(t => (
            <tr key={t.id}><td style={{ width: 110 }}><SeverityBadge severity={t.severity} /></td>
              <td><Link to={`/incidents/${t.id}`}>{t.title}</Link><div className="muted sm">{t.endpoint}</div></td>
              <td style={{ width: 140 }}><StatusBadge status={t.status} /></td></tr>))}</tbody></table>
        )}
      </Card>
      <Card title="Endpoints">
        <p>{Object.entries(w.endpoints_by_phase).map(([p, n]) => `${n} ${p === "baseline" ? "learning" : p}`).join(" · ") || "No endpoints yet."}</p>
      </Card>
    </div>
  );
}
