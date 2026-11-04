import { useEffect, useState } from "react";
import { api } from "../api";

export default function Jobs() {
  const [rows, setRows] = useState<any[]>([]);
  useEffect(() => { const load = () => api("/api/jobs").then(r => setRows(r.jobs)); load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, []);
  return (
    <div>
      <h1>Jobs</h1>
      <table><thead><tr><th>Endpoint</th><th>Kind</th><th>State</th><th>Params</th><th>Created</th><th>Finished</th><th>Error</th></tr></thead>
        <tbody>{rows.map(j => <tr key={j.id}><td>{j.endpoint}</td><td>{j.kind}</td><td><span className={`pill ${j.state}`}>{j.state}</span></td><td className="mono">{JSON.stringify(j.params)}</td>
          <td className="muted">{new Date(j.created_at).toLocaleString()}</td><td className="muted">{j.finished_at ? new Date(j.finished_at).toLocaleString() : ""}</td><td className="err">{j.error}</td></tr>)}</tbody></table>
    </div>
  );
}
