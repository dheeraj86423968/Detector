import { useEffect, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, fmtTs, GraphNode, Incident as Inc, LAYER_NAME } from "../api";
import { ProvenanceGraph, TYPE_COLOR, TYPE_NAME } from "../graph";

const dur = (a: number | null, b: number | null) => (a && b ? `${Math.max(1, Math.round((b - a) / 6e10))} min` : "–");

function KillChainCard({ title, items, empty }: { title: string; items: any[]; empty: string }) {
  return (
    <div className="kc">
      <h3>{title} <span className="muted">{items.length}</span></h3>
      {items.length === 0 ? <p className="muted sm">{empty}</p> :
        <ul>{items.slice(0, 8).map((it, i) => (
          <li key={i} className={it.flagged ? "flag" : ""}>
            <span className="mono t">{fmtTs(it.ts).slice(11, 19)}</span>
            <span className="l" title={it.label}>{it.label}</span>
            {it.fused != null && <span className="score f">{it.fused.toFixed(1)}</span>}
          </li>))}
          {items.length > 8 && <li className="muted sm">+{items.length - 8} more</li>}
        </ul>}
    </div>
  );
}

export default function Incident() {
  const { id } = useParams();
  const [sp, setSp] = useSearchParams();
  const focus = sp.get("focus_ns");
  const [inc, setInc] = useState<Inc | null>(null);
  const [alertWins, setAlertWins] = useState<number[]>([]);
  const [epName, setEpName] = useState("");
  const [sel, setSel] = useState<GraphNode | null>(null);
  const [cut, setCut] = useState<number>(0);

  useEffect(() => { api(`/api/endpoints/${id}`).then(r => setEpName(r.endpoint.name)); api(`/api/alerts?endpoint_id=${id}&limit=1000`).then(r => setAlertWins([...new Set<number>(r.alerts.map((a: any) => a.window_start_ns))].sort((a, b) => a - b))); }, [id]);
  useEffect(() => {
    setInc(null); setSel(null);
    api(`/api/endpoints/${id}/incident${focus ? `?focus_ns=${focus}` : ""}`).then((r: Inc) => {
      setInc(r);
      const ts = r.edges.map(e => e.ts_ns); setCut(ts.length ? Math.max(...ts) : 0);
    });
  }, [id, focus]);

  const minT = useMemo(() => (inc?.edges.length ? Math.min(...inc.edges.map(e => e.ts_ns)) : 0), [inc]);
  const maxT = useMemo(() => (inc?.edges.length ? Math.max(...inc.edges.map(e => e.ts_ns)) : 0), [inc]);
  const nowWin = inc?.focus_ns ?? null;
  const idx = nowWin != null ? alertWins.indexOf(alertWins.reduce((p, w) => (Math.abs(w - nowWin) < Math.abs(p - nowWin) ? w : p), alertWins[0] ?? 0)) : -1;
  const goto = (w: number | undefined) => w != null && setSp({ focus_ns: String(w) });

  if (!inc) return <p className="muted">Loading incident…</p>;
  const s = inc.summary;
  if (!s) return <div><h1>{epName}</h1><p className="muted">No detections on this endpoint yet.</p></div>;

  return (
    <div>
      <div className="row between">
        <h1 style={{ margin: 0 }}>Detected attack <span className="muted">· {epName}</span></h1>
        <div className="row">
          <button className="ghost" disabled={idx <= 0} onClick={() => goto(alertWins[idx - 1])}>‹ prev window</button>
          <select value={nowWin ?? ""} onChange={e => goto(+e.target.value)}>
            {alertWins.map(w => <option key={w} value={w}>{fmtTs(w)}</option>)}
          </select>
          <button className="ghost" disabled={idx < 0 || idx >= alertWins.length - 1} onClick={() => goto(alertWins[idx + 1])}>next window ›</button>
          <button className="ghost" onClick={() => setSp({})}>strongest</button>
        </div>
      </div>
      <div className="kpis">
        <div className="kpi bad"><div className="v">{s.flagged_nodes}</div><div className="l">flagged entities</div></div>
        <div className="kpi"><div className="v">{s.max_fused.toFixed(1)}×</div><div className="l">peak anomaly (× threshold)</div></div>
        <div className="kpi"><div className="v">{s.external_connections.length}</div><div className="l">external connections</div></div>
        <div className="kpi"><div className="v">{s.executed_files.length + s.written_files.length}</div><div className="l">files executed / written</div></div>
        <div className="kpi"><div className="v">{dur(s.first_ns, s.last_ns)}</div><div className="l">over {s.windows} window(s)</div></div>
        {s.by_layer && <div className="kpi"><div className="v">{(s.by_layer.novelty || 0) + (s.by_layer.rules || 0)}</div><div className="l">deterministic detections</div></div>}
      </div>
      {s.detections && s.detections.length > 0 && <div className="card">
        <h2>Why this was flagged</h2>
        <table><tbody>{s.detections.map((d, i) => <tr key={i}><td className="mono">{fmtTs(d.ts).slice(11, 19)}</td>
          <td><span className={`pill layer-${d.layer}`}>{LAYER_NAME[d.layer] || d.layer}</span></td><td>{d.reason}</td></tr>)}</tbody></table>
      </div>}

      <div className="killchain">
        <KillChainCard title="Processes flagged" items={s.flagged_processes} empty="none" />
        <KillChainCard title="Files executed" items={s.executed_files} empty="no new executables run" />
        <KillChainCard title="Files written / dropped" items={s.written_files} empty="no files written by flagged processes" />
        <KillChainCard title="External connections" items={s.external_connections} empty="no outbound connections" />
      </div>

      <div className="attack-grid">
        <div>
          <div className="card tbar">
            <span className="muted sm">Attack provenance graph — flagged entities in red, sized by anomaly. Hover to isolate, click for detail, double-click to expand.</span>
            <div className="row">
              <span className="muted sm">{fmtTs(minT).slice(11, 19)}</span>
              <input type="range" min={minT} max={maxT} value={cut} onChange={e => setCut(+e.target.value)} style={{ width: 260 }} />
              <span className="mono sm">{cut ? fmtTs(cut).slice(11, 19) : ""}</span>
            </div>
          </div>
          <div style={{ position: "relative" }}>
            <ProvenanceGraph nodes={inc.nodes} edges={inc.edges} cut={cut} height={600} onSelect={setSel}
              onExpand={() => { }} />
            <div className="legend">
              <span style={{ background: "#ff5c5c" }} />flagged
              <span style={{ background: TYPE_COLOR.subject }} />process
              <span style={{ background: TYPE_COLOR.file }} />file
              <span style={{ background: TYPE_COLOR.netflow }} />socket
            </div>
          </div>
        </div>
        <div className="card detail">
          <h2>Entity detail</h2>
          {sel ? <>
            <div className="pill" style={{ background: sel.flagged ? "#3d1c1c" : "var(--line)", color: sel.flagged ? "var(--bad)" : "var(--text)" }}>{TYPE_NAME[sel.ntype] || sel.ntype}</div>
            <p className="mono break">{sel.label}</p>
            {sel.flagged ? <table className="mini"><tbody>
              <tr><td>fused</td><td className="score">{sel.flagged.fused.toFixed(2)}×</td></tr>
              <tr><td>detector-1</td><td className="score">{sel.flagged.r1.toFixed(2)}×</td></tr>
              <tr><td>detector-2</td><td className="score">{sel.flagged.r2.toFixed(2)}×</td></tr>
            </tbody></table> : <p className="muted sm">context entity (not flagged)</p>}
          </> : <p className="muted">Click an entity in the graph.</p>}
          <h2>Jump to alerts</h2>
          <p className="sm"><Link to={`/alerts?endpoint_id=${id}`}>Alert list for this endpoint →</Link></p>
          <p className="sm muted">{inc.nodes.length} entities · {inc.edges.length} events in this incident</p>
        </div>
      </div>
    </div>
  );
}
