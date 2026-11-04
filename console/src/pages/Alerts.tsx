import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, Alert, fmtTs, LAYER_NAME } from "../api";

export default function Alerts() {
  const [sp] = useSearchParams(); const eid = sp.get("endpoint_id") || "";
  const [rows, setRows] = useState<Alert[]>([]); const [status, setStatus] = useState(""); const [layer, setLayer] = useState(""); const [epName, setEpName] = useState("");
  const q = (extra: Record<string, string>) => { const p = new URLSearchParams(extra); if (eid) p.set("endpoint_id", eid); if (status) p.set("status", status); if (layer) p.set("layer", layer); return p.toString(); };
  const load = () => api(`/api/alerts?${q({ limit: "300" })}`).then(r => setRows(r.alerts));
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, [status, eid, layer]);
  useEffect(() => { setEpName(""); if (eid) api(`/api/endpoints/${encodeURIComponent(eid)}`).then(r => setEpName(r.endpoint.name)).catch(() => { }); }, [eid]);
  const set = async (id: number, s: string) => { await api(`/api/alerts/${id}`, { method: "POST", body: JSON.stringify({ status: s }) }); load(); };
  return (
    <div>
      <h1>Alerts</h1>
      <div className="row between">
        <div className="row">
          <span>Status <select value={status} onChange={e => setStatus(e.target.value)}><option value="">all</option>{["open", "ack", "closed", "true_positive", "false_positive"].map(s => <option key={s}>{s}</option>)}</select></span>
          <span>Layer <select value={layer} onChange={e => setLayer(e.target.value)}><option value="">all</option>{Object.entries(LAYER_NAME).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></span>
          {eid && <span>Endpoint <Link to={`/endpoints/${eid}`}>{epName || eid}</Link> <Link className="muted sm" to="/alerts">clear</Link></span>}
        </div>
        <div className="row">
          <a className="btn" href={`/api/alerts/export?${q({ format: "csv" })}`} download>Export CSV</a>
          <a className="btn" href={`/api/alerts/export?${q({ format: "ndjson" })}`} download>Export NDJSON</a>
        </div>
      </div>
      <table>
        <thead><tr><th>Window</th><th>Endpoint</th><th>Detection</th><th>Entity</th><th>Fused</th><th>d1</th><th>d2</th><th>Status</th><th></th></tr></thead>
        <tbody>{rows.map(a => (
          <tr key={a.id}><td className="mono">{fmtTs(a.window_start_ns)}</td><td>{a.endpoint}</td>
            <td><span className={`pill layer-${a.layer || "learned"}`}>{LAYER_NAME[a.layer || "learned"]}</span>{a.reason && <div className="muted sm">{a.reason.slice(0, 110)}</div>}</td>
            <td><Link to={`/alerts/${a.id}`}>{a.label.slice(0, 80)}</Link> <span className="muted">{a.ntype}</span></td>
            <td className="score">{a.fused.toFixed(2)}</td><td className="score">{a.r1.toFixed(2)}</td><td className="score">{a.r2.toFixed(2)}</td>
            <td><span className="pill">{a.status}</span></td>
            <td>{["ack", "true_positive", "false_positive", "closed"].map(s => <button key={s} className="ghost" onClick={() => set(a.id, s)}>{s.replace("_", " ")}</button>)}</td></tr>))}
        </tbody>
      </table>
      {rows.length === 0 && <p className="muted">No alerts{eid || status ? " match the current filter" : ""}.</p>}
    </div>
  );
}
