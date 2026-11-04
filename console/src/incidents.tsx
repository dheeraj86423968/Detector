import { Link, useNavigate } from "react-router-dom";
import type { IncidentSummary } from "./api";
import { fmtDateTime, fmtDuration, fmtRel, plural } from "./format";
import { Chip, Mid, PathText, SeverityBadge, StatusBadge } from "./ui";

/** The incident list used on Overview, Incidents and an endpoint's page. */
export function IncidentTable({ rows, showEndpoint = true, compact }: { rows: IncidentSummary[]; showEndpoint?: boolean; compact?: boolean }) {
  const nav = useNavigate();
  return (
    <div className="table-wrap">
      <table className="table clickable">
        <thead>
          <tr>
            <th style={{ width: 104 }}>Severity</th>
            <th>Incident</th>
            {showEndpoint && <th style={{ width: "18%" }}>Endpoint</th>}
            <th style={{ width: 206 }}>Detected</th>
            {!compact && <th className="num" style={{ width: 80 }}>Alerts</th>}
            <th style={{ width: 140 }}>Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(i => (
            <tr key={i.id} onClick={() => nav(`/incidents/${i.id}`)}>
              <td><SeverityBadge severity={i.severity} /></td>
              <td className="cell-main">
                <Link to={`/incidents/${i.id}`} className="row-title wrap2" onClick={e => e.stopPropagation()} title={i.title}><PathText text={i.title} max={48} /></Link>
                <div className="row-meta">
                  {!compact && (i.behaviours?.length
                    ? <>{i.behaviours.slice(0, 3).map(b => <Chip key={b.label} serious={b.serious} title={`${b.tactic}: ${b.text}`}>{b.label}</Chip>)}
                        {i.behaviours.length > 3 && <Chip title={i.behaviours.slice(3).map(b => b.label).join(", ")}>+{i.behaviours.length - 3} more</Chip>}</>
                    : i.tactics.map(t => <Chip key={t}>{t}</Chip>))}
                  <span className="muted">{plural(i.processes, "process", "processes")}</span>
                  {compact && <span className="muted">· {plural(i.alerts, "alert")}</span>}
                </div>
              </td>
              {showEndpoint && <td><Link to={`/endpoints/${i.endpoint_id}`} className="subtle-link block-link" onClick={e => e.stopPropagation()}><Mid text={i.endpoint_name} /></Link></td>}
              <td>
                <div className="nowrap" title={fmtDateTime(i.first_ns, true)}>{fmtDateTime(i.first_ns)}</div>
                <div className="muted sm nowrap">{fmtRel(i.first_ns)}{i.last_ns - i.first_ns > 6e10 ? ` · lasted ${fmtDuration(i.last_ns - i.first_ns)}` : ""}</div>
              </td>
              {!compact && <td className="num">{i.alerts.toLocaleString()}</td>}
              <td><StatusBadge status={i.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
