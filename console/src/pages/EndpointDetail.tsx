import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ago, api, Alert, Endpoint, fmtTs, isStale, LAYER_NAME, useMe, WindowRow } from "../api";

export default function EndpointDetail() {
  const { id } = useParams();
  const me = useMe(); const admin = me?.role === "admin";
  const [d, setD] = useState<any>(null); const [alerts, setAlerts] = useState<Alert[]>([]);
  const [msg, setMsg] = useState<{ text: string; err?: boolean } | null>(null); const [newProg, setNewProg] = useState("");
  const load = () => { api(`/api/endpoints/${id}`).then(setD); api(`/api/alerts?endpoint_id=${id}&limit=50`).then(r => setAlerts(r.alerts)); };
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, [id]);
  if (!d) return <p className="muted">Loading…</p>;
  const ep: Endpoint = d.endpoint; const h = ep.health; const retired = ep.phase === "retired";
  // run an action, report the server's error (FastAPI {detail}) instead of failing silently
  const act = async (fn: () => Promise<any>, ok: string) => { setMsg(null); try { await fn(); setMsg({ text: ok }); load(); } catch (e: any) { setMsg({ text: e.message, err: true }); } };
  const post = (path: string, body?: any) => api(`/api/endpoints/${id}/${path}`, { method: "POST", body: body ? JSON.stringify(body) : undefined });
  const retire = () => { if (confirm(`Permanently retire ${ep.name}? Its agent will no longer be accepted and its raw telemetry is dropped. This cannot be undone.`)) act(() => post("retire"), "endpoint retired"); };
  const rows = (d.timeline as WindowRow[]).map(w => ({ t: fmtTs(w.start_ns).slice(5, 16), fused: +w.max_fused.toFixed(2), d1: +w.max_r1.toFixed(2), d2: +w.max_r2.toFixed(2), alerts: w.alerts }));
  const agree = d.timeline.filter((w: WindowRow) => w.max_r1 > 1 && w.max_r2 > 1).length;
  const only1 = d.timeline.filter((w: WindowRow) => w.max_r1 > 1 && w.max_r2 <= 1).length;
  const only2 = d.timeline.filter((w: WindowRow) => w.max_r2 > 1 && w.max_r1 <= 1).length;
  const totalAlerts = d.timeline.reduce((s: number, w: WindowRow) => s + w.alerts, 0);
  return (
    <div>
      <div className="row between">
        <h1 style={{ margin: 0 }}>{ep.name} <span className={`pill ${ep.phase}`}>{ep.phase}</span></h1>
        <div className="row">
          {admin && !retired && <button className="ghost" onClick={() => act(() => post("commands", { command: "refetch_bundle" }), "re-fetch requested; the agent re-downloads and re-verifies its bundle on its next poll")}>Re-fetch bundle</button>}
          {admin && !retired && <button className="ghost danger" onClick={retire}>Retire endpoint</button>}
          {totalAlerts > 0 && <Link className="btn primary-link" to={`/incident/${id}`}>View detected attack →</Link>}
        </div>
      </div>
      {msg && <p className={msg.err ? "err" : "ok"}>{msg.text}</p>}
      <div className="kpis">
        <div className="kpi"><div className="v mono">{h?.agent_version ?? "–"}</div><div className="l">agent version</div></div>
        <div className="kpi"><div className="v">{h ? h.queue_depth : "–"}</div><div className="l">upload queue depth</div></div>
        <div className="kpi"><div className="v">{h?.cpu_pct != null ? `${h.cpu_pct.toFixed(1)}%` : "–"}</div><div className="l">agent CPU</div></div>
        <div className="kpi"><div className="v">{h?.rss_mb != null ? `${h.rss_mb.toFixed(0)} MB` : "–"}</div><div className="l">agent RSS</div></div>
        <div className={`kpi ${isStale(h) && !retired ? "bad" : ""}`}><div className="v">{h ? ago(h.at) : "never"}</div><div className="l">since last heartbeat{isStale(h) && !retired ? " (stale)" : ""}</div></div>
        <div className="kpi"><div className="v mono" style={{ fontSize: 14 }}>{h?.last_window_end_ns ? fmtTs(h.last_window_end_ns) : "–"}</div><div className="l">last window shipped</div></div>
      </div>
      <div className="kpis">
        <div className="kpi"><div className="v">{d.timeline.length}</div><div className="l">windows scored</div></div>
        <div className="kpi"><div className="v">{d.timeline.reduce((s: number, w: WindowRow) => s + w.alerts, 0)}</div><div className="l">alerted nodes</div></div>
        <div className="kpi"><div className="v">{agree}</div><div className="l">windows both detectors elevated</div></div>
        <div className="kpi"><div className="v">{only1} / {only2}</div><div className="l">only detector-1 / only detector-2</div></div>
        <div className="kpi"><div className="v">{ep.baseline_days_done}</div><div className="l">baseline days</div></div>
      </div>
      <div className="card">
        <h2>Fused anomaly score per window (1.0 = alert threshold)</h2>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={rows}><CartesianGrid stroke="#263040" /><XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={40} /><YAxis /><Tooltip />
            <ReferenceLine y={1} stroke="#ffb454" strokeDasharray="4 4" /><Area dataKey="fused" stroke="#4cc2ff" fill="#4cc2ff33" isAnimationActive={false} /></AreaChart>
        </ResponsiveContainer>
        <h2>Detector agreement (normalised scores: score / own threshold)</h2>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={rows}><CartesianGrid stroke="#263040" /><XAxis dataKey="t" tick={{ fontSize: 10 }} minTickGap={40} /><YAxis /><Tooltip /><Legend />
            <ReferenceLine y={1} stroke="#ffb454" strokeDasharray="4 4" /><Line dataKey="d1" name="detector-1" stroke="#5fd38d" dot={false} isAnimationActive={false} /><Line dataKey="d2" name="detector-2" stroke="#ff6b6b" dot={false} isAnimationActive={false} /></LineChart>
        </ResponsiveContainer>
      </div>
      <div className="grid2">
        <div className="card">
          <h2>Recent alerts</h2>
          <table><thead><tr><th>Window</th><th>Detection</th><th>Entity</th><th>Fused</th><th>Status</th></tr></thead>
            <tbody>{alerts.map(a => <tr key={a.id}><td className="mono">{fmtTs(a.window_start_ns)}</td><td><span className={`pill layer-${a.layer || "learned"}`}>{LAYER_NAME[a.layer || "learned"]}</span></td><td><Link to={`/alerts/${a.id}`}>{a.label.slice(0, 60)}</Link></td><td className="score">{a.fused.toFixed(2)}</td><td><span className="pill">{a.status}</span></td></tr>)}</tbody></table>
        </div>
        <div className="card">
          <h2>Jobs</h2>
          <table><thead><tr><th>Kind</th><th>State</th><th>Created</th><th>Error</th></tr></thead>
            <tbody>{d.jobs.map((j: any) => <tr key={j.id}><td>{j.kind} <span className="muted mono">{JSON.stringify(j.params)}</span></td><td><span className={`pill ${j.state}`}>{j.state}</span></td><td className="muted">{new Date(j.created_at).toLocaleString()}</td><td className="err">{j.error}</td></tr>)}</tbody></table>
          <p><button className="ghost" disabled={retired} onClick={() => act(() => post("retrain"), "retrain queued")}>Retrain detectors</button></p>
          <h2>Alert sensitivity (false-positive budget)</h2>
          <p className="muted">Validation-max is the strictest threshold. A percentile budget trades a small, bounded false-positive rate for recall of attacks the baseline never quite covered.</p>
          <p>
            <select value={ep.config?.fp_budget ?? ""} disabled={retired} onChange={e => { const v = e.target.value || null; act(() => post("config", { config: { fp_budget: v } }), `sensitivity set to ${v ? v + "th percentile" : "validation-max"}`); }}>
              <option value="">validation-max (default)</option>
              <option value="99">99th percentile</option>
              <option value="99.9">99.9th percentile</option>
              <option value="99.99">99.99th percentile</option>
            </select>
            <span className="muted"> applied on the agent's next poll</span>
          </p>
          <h2>Detection layers</h2>
          <p className="muted">Layer 1 alerts on programs that never ran during the baseline; approve a program to stop its alerts (applied on the
            agent's next poll, no retraining). Layer 3 (learned) alerts on its own at most this many times a day, highest scores first.</p>
          <p>Learned-only alerts per day <input type="number" min={0} style={{ width: 80 }} disabled={retired || !admin} defaultValue={ep.config?.learned_daily_budget ?? 20}
            onBlur={e => { const v = parseInt(e.target.value, 10); if (!isNaN(v) && v !== (ep.config?.learned_daily_budget ?? 20)) act(() => post("config", { config: { learned_daily_budget: v } }), `learned daily budget set to ${v}`); }} /></p>
          <p><label><input type="checkbox" disabled={retired || !admin} checked={ep.config?.learned_alerts ?? true}
            onChange={e => act(() => post("config", { config: { learned_alerts: e.target.checked } }), e.target.checked ? "learned-layer alerts on" : "learned layer set to ranking only")} />
            {" "}Learned layer raises alerts (off = it only ranks; alerts come from layers 1-2)</label></p>
          <p className="muted sm">Approved programs ({(ep.config?.approved_executables || []).length})</p>
          <div className="mono sm">{(ep.config?.approved_executables || []).map((x: string) => <div key={x}>{x} {admin && !retired && <button className="ghost" onClick={() => act(() => post("approved-executables", { executables: [x], approve: false }), `${x} revoked`)}>revoke</button>}</div>)}</div>
          {admin && !retired && <p><input placeholder="/opt/app/bin/tool" value={newProg} onChange={e => setNewProg(e.target.value)} />
            <button className="ghost" disabled={!newProg.trim()} onClick={() => act(() => post("approved-executables", { executables: [newProg.trim()], approve: true }).then(() => setNewProg("")), `${newProg.trim()} approved`)}>Approve program</button></p>}
          <h2>Baseline days</h2>
          <p className="mono">{d.baseline_days.map((b: any) => `${b.date}${b.complete ? "✓" : "…"}`).join("  ")}</p>
        </div>
      </div>
    </div>
  );
}
