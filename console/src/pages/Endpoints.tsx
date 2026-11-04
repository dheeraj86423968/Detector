import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, EnrollToken, Endpoint, fmtTs, isStale, useMe } from "../api";

export default function Endpoints() {
  const me = useMe();
  const [eps, setEps] = useState<Endpoint[]>([]); const [name, setName] = useState(""); const [tok, setTok] = useState<EnrollToken | null>(null); const [err, setErr] = useState("");
  const load = () => api("/api/endpoints").then(r => setEps(r.endpoints));
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);
  const add = async () => {
    setErr("");
    try { const r = await api<EnrollToken>("/api/endpoints", { method: "POST", body: JSON.stringify({ name }) }); setTok(r); setName(""); load(); }
    catch (e: any) { setErr(e.message); }
  };
  const copy = (s: string) => navigator.clipboard?.writeText(s).catch(() => { });
  return (
    <div>
      <h1>Endpoints</h1>
      {me?.role === "admin" && <div className="card">
        <b>Add endpoint</b> <input value={name} onChange={e => setName(e.target.value)} placeholder="name" /> <button className="primary" onClick={add} disabled={!name}>Create token</button>
        {err && <span className="err"> {err}</span>}
        {tok && <div>
          <p>Install the agent on the host and run (token valid {tok.expires_in_hours} h, single use):</p>
          <p><code className="mono sel break">{tok.enroll_command}</code> <button className="ghost" onClick={() => copy(tok.enroll_command)}>copy</button></p>
          <p className="sm">CA fingerprint (sha256 of the CA certificate DER): <code className="mono sel break">{tok.ca_sha256}</code> <button className="ghost" onClick={() => copy(tok.ca_sha256)}>copy</button></p>
          <p className="muted sm">Docker image form: <code className="mono sel break">docker run ... -e PDP_ENROLL_TOKEN={tok.token} -e PDP_CA_SHA256={tok.ca_sha256} pdp/agent:dev run</code></p>
          <p className="muted sm">The same fingerprint is the pin for the desktop console's server settings.</p>
        </div>}
      </div>}
      <table>
        <thead><tr><th>Name</th><th>Host</th><th>Phase</th><th>Baseline days</th><th>Open alerts</th><th>Agent</th><th>Queue</th><th>Last window</th><th>CPU / RSS</th><th>Last seen</th></tr></thead>
        <tbody>{eps.map(e => {
          const h = e.health;
          return <tr key={e.id} className={e.phase === "retired" ? "retired" : ""}><td><Link to={`/endpoints/${e.id}`}>{e.name}</Link> <span className="muted">{e.kind !== "live" ? e.kind : ""}</span></td><td>{e.hostname}</td>
            <td><span className={`pill ${e.phase}`}>{e.phase}</span> {e.phase !== "retired" && isStale(h) && <span className="pill stale" title="no heartbeat for more than 5 minutes">stale</span>}</td>
            <td>{e.baseline_days_done}</td><td>{e.open_alerts}</td>
            <td className="mono">{h?.agent_version ?? "–"}</td><td className="score">{h ? h.queue_depth : "–"}</td>
            <td className="mono">{h?.last_window_end_ns ? fmtTs(h.last_window_end_ns) : "–"}</td>
            <td className="score">{h ? `${h.cpu_pct != null ? h.cpu_pct.toFixed(0) + "%" : "–"} / ${h.rss_mb != null ? h.rss_mb.toFixed(0) + " MB" : "–"}` : "–"}</td>
            <td className="muted">{e.last_seen ? new Date(e.last_seen).toLocaleString() : "never"}</td></tr>;
        })}</tbody>
      </table>
    </div>
  );
}
