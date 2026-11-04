import { Link } from "react-router-dom";
import { ArrowRight, CheckCircle2, CircleSlash, FlaskConical, ShieldCheck, Hourglass, WifiOff, TriangleAlert, ServerCrash } from "lucide-react";
import { Overview, Severity, useApi } from "../api";
import { DailyBars } from "../chart";
import { plural, SEVERITIES, SEVERITY_LABEL } from "../format";
import { IncidentTable } from "../incidents";
import { Card, Empty, ErrorState, Loading, PageHeader } from "../ui";

const ATTENTION_ICON: Record<string, JSX.Element> = {
  offline: <WifiOff size={16} />, dropping_events: <ServerCrash size={16} />, check_failed: <TriangleAlert size={16} />, no_check: <FlaskConical size={16} />,
};

export default function OverviewPage() {
  const { data, error, loading, reload } = useApi<Overview>("/api/overview", 30000);
  if (loading && !data) return <><PageHeader title="Overview" /><Loading block /></>;
  if (error && !data) return <><PageHeader title="Overview" /><ErrorState error={error} onRetry={reload} /></>;
  const d = data!;
  const e = d.endpoints, inc = d.incidents;
  const sevMax = Math.max(1, ...SEVERITIES.map(s => inc.by_severity[s] || 0));
  const per = d.per_day.map(p => ({ date: p.date, value: p.incidents }));
  const total14 = per.reduce((s, p) => s + p.value, 0);
  const headline = inc.open > 0
    ? <>{plural(inc.open, "open incident")} across your endpoints. Detection is active on {plural(e.protected, "endpoint")}.</>
    : e.protected > 0 ? <>No open incidents. Detection is active on {plural(e.protected, "endpoint")}.</>
      : e.total > 0 ? <>No endpoint is protected yet — endpoints start detecting once they have learned their normal behaviour.</>
        : <>No endpoints yet. Add an endpoint to start collecting activity.</>;
  return (
    <div className="page">
      <PageHeader title="Overview" subtitle={headline} />
      <div className="grid grid-2">
        <Card title="Endpoints" subtitle={`${plural(e.total, "endpoint")} enrolled`} actions={<Link to="/endpoints" className="card-link">View all <ArrowRight size={14} /></Link>}>
          <div className="fleet">
            <FleetStat icon={<ShieldCheck size={18} />} tone="ok" n={e.protected} label="Protected" hint="detection active" />
            <FleetStat icon={<Hourglass size={18} />} tone="info" n={e.learning} label="Learning" hint="building baseline" />
            <FleetStat icon={<WifiOff size={18} />} tone={e.offline ? "bad" : "muted"} n={e.offline} label="Offline" hint="not reporting" />
          </div>
          {e.total > 0 && <div className="fleet-bar" aria-hidden>
            {e.protected > 0 && <span className="ok" style={{ flex: e.protected }} />}
            {e.learning > 0 && <span className="info" style={{ flex: e.learning }} />}
            {e.offline > 0 && <span className="bad" style={{ flex: e.offline }} />}
          </div>}
        </Card>
        <Card title="Open incidents" subtitle={inc.last_7d ? `${plural(inc.last_7d, "incident")} in the last 7 days` : "None detected in the last 7 days"}
          actions={<Link to="/incidents" className="card-link">View all <ArrowRight size={14} /></Link>}>
          <div className="open-inc">
            <div className="big-num">{inc.open.toLocaleString()}</div>
            <div className="sev-bars">
              {SEVERITIES.map((s: Severity) => (
                <Link key={s} to={`/incidents?severity=${s}`} className="sev-row">
                  <span className={`sev-dot sev-${s}`} /><span className="sev-name">{SEVERITY_LABEL[s]}</span>
                  <span className="sev-track"><span className={`sev-fill sev-${s}`} style={{ width: `${(100 * (inc.by_severity[s] || 0)) / sevMax}%` }} /></span>
                  <span className="sev-n">{(inc.by_severity[s] || 0).toLocaleString()}</span>
                </Link>
              ))}
            </div>
          </div>
        </Card>
      </div>
      <div className="grid grid-main-side">
        <Card title="Incidents per day" subtitle={total14 ? `${plural(total14, "incident")} in the last 14 days` : "Last 14 days"}>
          <DailyBars data={per} unit={["incident", "incidents"]} />
          {total14 === 0 && <div className="chart-note">No incidents were detected in the last 14 days.</div>}
        </Card>
        <Card title="Needs attention" pad={false}>
          {d.attention.length === 0 ? (
            <Empty icon={<CheckCircle2 size={22} />} title="Everything looks healthy" text="All endpoints are reporting and their detection checks pass." />
          ) : (
            <ul className="attention">
              {d.attention.slice(0, 5).map((a, i) => (
                <li key={i}>
                  <Link to={`/endpoints/${a.endpoint_id}`}>
                    <span className={`att-icon k-${a.kind}`}>{ATTENTION_ICON[a.kind] || <CircleSlash size={16} />}</span>
                    <span className="att-text">{a.text}</span>
                    <ArrowRight size={14} className="att-go" />
                  </Link>
                </li>
              ))}
              {d.attention.length > 5 && <li className="att-more"><Link to="/endpoints">{d.attention.length - 5} more on the Endpoints page</Link></li>}
            </ul>
          )}
        </Card>
      </div>
      <Card title="Recent incidents" pad={false} actions={<Link to="/incidents?status=all" className="card-link">All incidents <ArrowRight size={14} /></Link>}>
        {d.recent_incidents.length === 0
          ? <Empty icon={<ShieldCheck size={22} />} title="No incidents" text={e.protected ? `Detection is active on ${plural(e.protected, "endpoint")}.` : "Incidents appear here once endpoints are protected."} />
          : <IncidentTable rows={d.recent_incidents} compact />}
      </Card>
    </div>
  );
}

function FleetStat({ icon, tone, n, label, hint }: { icon: JSX.Element; tone: string; n: number; label: string; hint: string }) {
  return (
    <div className={`fleet-stat tone-${tone}`}>
      <span className="fleet-icon">{icon}</span>
      <div><div className="fleet-n">{n.toLocaleString()}</div><div className="fleet-label">{label}</div><div className="fleet-hint">{hint}</div></div>
    </div>
  );
}
