import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, Endpoint } from "../api";

const pct = (x: number | null | undefined) => (x == null ? "–" : `${(100 * x).toFixed(0)}%`);
const ci = (c?: [number, number]) => (c ? `[${(100 * c[0]).toFixed(0)}–${(100 * c[1]).toFixed(0)}]` : "");

export default function Simulation() {
  const [camps, setCamps] = useState<any[]>([]); const [sel, setSel] = useState<any>(null);
  const [eps, setEps] = useState<Endpoint[]>([]); const [fam, setFam] = useState<string[]>([]); const [levels, setLevels] = useState<string[]>([]);
  const [form, setForm] = useState({ name: "", endpoint_id: "", runs: 40, attacks_per_pass: 3, days: "validation", families: [] as string[], evasion_levels: ["none", "low", "medium", "high"], seed: "" });
  const [msg, setMsg] = useState("");
  const load = () => api("/api/sim/campaigns").then(r => setCamps(r.campaigns)).catch(() => setCamps([]));
  useEffect(() => {
    load(); const t = setInterval(load, 15000);
    api("/api/endpoints").then(r => { setEps(r.endpoints); if (r.endpoints[0]) setForm(f => ({ ...f, endpoint_id: f.endpoint_id || r.endpoints[0].id })); });
    api("/api/sim/families").then(r => { setFam(r.families); setLevels(r.evasion_levels); setForm(f => ({ ...f, families: r.families })); });
    return () => clearInterval(t);
  }, []);
  const open = (c: any) => api(`/api/sim/campaigns/${c.id}/results`).then(setSel);
  const toggle = (key: "families" | "evasion_levels", v: string) => setForm(f => ({ ...f, [key]: f[key].includes(v) ? f[key].filter(x => x !== v) : [...f[key], v] }));
  const submit = async () => {
    try {
      const spec = { runs: +form.runs, attacks_per_pass: +form.attacks_per_pass, days: form.days.split(",").map(s => s.trim()).filter(Boolean), families: form.families, evasion_levels: form.evasion_levels, seed: form.seed ? +form.seed : undefined };
      const r = await api("/api/sim/campaigns", { method: "POST", body: JSON.stringify({ name: form.name || `campaign ${new Date().toISOString().slice(0, 16)}`, endpoint_id: form.endpoint_id, spec }) });
      setMsg(`queued campaign ${r.id} (seed ${r.seed})`); load();
    } catch (e: any) { setMsg(e.message); }
  };
  const s = sel?.summary;
  return (
    <div>
      <h1>Adversarial simulation</h1>
      <p className="muted">Randomised campaigns of synthetic attacks (modelled on DARPA TC E3/E5 and OpTC behaviours, living-off-the-land, privilege escalation and lateral movement, exfiltration, ransomware) and transplants of real DARPA attack subgraphs, injected into a benign day of the endpoint and scored by the deployed detectors from their real runtime. Evasion levels combine mimicry padding, label camouflage and slow-and-low spreading.</p>
      <div className="card">
        <h2>New campaign</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6, auto)", gap: 10, alignItems: "center" }}>
          <input placeholder="name" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
          <select value={form.endpoint_id} onChange={e => setForm({ ...form, endpoint_id: e.target.value })}>{eps.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}</select>
          <label>runs <input type="number" value={form.runs} style={{ width: 70 }} onChange={e => setForm({ ...form, runs: +e.target.value })} /></label>
          <label>per pass <input type="number" value={form.attacks_per_pass} style={{ width: 60 }} onChange={e => setForm({ ...form, attacks_per_pass: +e.target.value })} /></label>
          <label>days <input value={form.days} style={{ width: 200 }} onChange={e => setForm({ ...form, days: e.target.value })} title="validation or YYYY-MM-DD, comma separated" /></label>
          <label>seed <input value={form.seed} style={{ width: 90 }} placeholder="random" onChange={e => setForm({ ...form, seed: e.target.value })} /></label>
        </div>
        <p>Families: {fam.map(f => <label key={f} style={{ marginRight: 10 }}><input type="checkbox" checked={form.families.includes(f)} onChange={() => toggle("families", f)} /> {f}</label>)}</p>
        <p>Evasion: {levels.map(l => <label key={l} style={{ marginRight: 10 }}><input type="checkbox" checked={form.evasion_levels.includes(l)} onChange={() => toggle("evasion_levels", l)} /> {l}</label>)}</p>
        <button className="primary" onClick={submit} disabled={!form.endpoint_id || !form.families.length}>Run campaign</button> <span className="muted">{msg}</span>
      </div>
      <table><thead><tr><th>Campaign</th><th>Endpoint</th><th>Runs</th><th>State</th><th>Detection (fused)</th><th>Robustness none→high</th><th>FP / endpoint-day</th><th>Created</th></tr></thead>
        <tbody>{camps.map(c => <tr key={c.id} onClick={() => open(c)} style={{ cursor: "pointer" }}><td>{c.name}</td><td>{c.endpoint}</td><td>{c.runs}</td><td><span className={`pill ${c.state}`}>{c.state}</span></td>
          <td className="score">{c.summary ? `${pct(c.summary.detection_rate)} ${ci(c.summary.detection_rate_ci)}` : ""}</td>
          <td className="score">{c.summary?.robustness ? Object.entries(c.summary.robustness).map(([k, v]) => `${k} ${pct(v as number)}`).join(" · ") : ""}</td>
          <td className="score">{c.summary?.fp_per_day?.toFixed(1)}</td><td className="muted">{new Date(c.created_at).toLocaleString()}</td></tr>)}</tbody></table>
      {sel && s && <div className="card">
        <h2>{sel.campaign.name} · {s.runs} attacks on {s.days.join(", ")} · seed {sel.campaign.seed} · {(s.elapsed_s / 60).toFixed(1)} min</h2>
        <div className="kpis">
          <div className="kpi"><div className="v">{pct(s.overall.fused.rate)}</div><div className="l">detected (fused) {ci(s.overall.fused.ci)}</div></div>
          <div className="kpi"><div className="v">{pct(s.overall.d1.rate)} / {pct(s.overall.d2.rate)}</div><div className="l">detector-1 / detector-2 alone</div></div>
          <div className="kpi"><div className="v">{s.overall.ttd_median_s != null ? `${(s.overall.ttd_median_s / 60).toFixed(1)} min` : "–"}</div><div className="l">median time-to-detect {s.overall.ttd_ci_s ? `[${(s.overall.ttd_ci_s[0] / 60).toFixed(1)}–${(s.overall.ttd_ci_s[1] / 60).toFixed(1)}]` : ""}</div></div>
          <div className="kpi"><div className="v">{s.fp_per_day.toFixed(1)}</div><div className="l">false-positive nodes / endpoint-day (clean)</div></div>
          <div className="kpi"><div className="v">{s.collateral_fp_mean.toFixed(1)}</div><div className="l">collateral FP nodes per attack pass</div></div>
          <div className="kpi"><div className="v">{pct(s.overall.node_recall_mean)}</div><div className="l">mean attack-node recall</div></div>
        </div>
        <h2>Detection rate by attack family</h2>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={s.by_family.map((b: any) => ({ family: b.family.replace("transplant:", "real:"), fused: b.fused.rate, d1: b.d1.rate, d2: b.d2.rate }))}><CartesianGrid stroke="#263040" /><XAxis dataKey="family" tick={{ fontSize: 10 }} interval={0} angle={-15} height={50} /><YAxis domain={[0, 1]} /><Tooltip /><Legend />
            <Bar dataKey="fused" fill="#4cc2ff" name="fused" isAnimationActive={false} /><Bar dataKey="d1" fill="#5fd38d" name="detector-1" /><Bar dataKey="d2" fill="#ff6b6b" name="detector-2" /></BarChart>
        </ResponsiveContainer>
        <h2>Robustness against evasion strength</h2>
        <table><thead><tr><th>Evasion level</th><th>Runs</th><th>Fused</th><th>detector-1</th><th>detector-2</th><th>Median time-to-detect</th><th>Node recall</th><th>Median max fused score</th></tr></thead>
          <tbody>{s.by_evasion.map((r: any) => <tr key={r.level}><td>{r.level}</td><td>{r.runs}</td><td className="score">{pct(r.fused.rate)} <span className="muted">{ci(r.fused.ci)}</span></td><td className="score">{pct(r.d1.rate)}</td><td className="score">{pct(r.d2.rate)}</td>
            <td>{r.ttd_median_s != null ? `${(r.ttd_median_s / 60).toFixed(1)} min` : "–"}</td><td className="score">{pct(r.node_recall_mean)}</td><td className="score">{r.max_fused_median?.toFixed(2)}</td></tr>)}</tbody></table>
        <h2>Family × evasion (fused detection rate)</h2>
        <table><thead><tr><th>Family</th>{s.by_evasion.map((r: any) => <th key={r.level}>{r.level}</th>)}</tr></thead>
          <tbody>{s.by_family.map((b: any) => <tr key={b.family}><td>{b.family}</td>{s.by_evasion.map((l: any) => { const m = s.matrix.find((x: any) => x.family === b.family && x.level === l.level); return <td key={l.level} className="score" style={{ background: m?.fused.rate != null ? `rgba(76,194,255,${0.1 + 0.5 * m.fused.rate})` : undefined }}>{m ? `${pct(m.fused.rate)} (${m.fused.k}/${m.fused.n})` : ""}</td>; })}</tr>)}</tbody></table>
        <h2>Runs</h2>
        <table><thead><tr><th>#</th><th>Family</th><th>Evasion</th><th>Host process</th><th>Nodes / edges</th><th>Detected</th><th>TTD</th><th>Max fused / d1 / d2</th><th>Flagged entities</th></tr></thead>
          <tbody>{sel.runs.map((r: any) => <tr key={r.run_index}><td>{r.run_index}</td><td>{r.attack.family}</td><td>{typeof r.attack.evasion === "string" ? r.attack.evasion : JSON.stringify(r.attack.evasion)}</td><td className="mono">{r.attack.host?.label?.slice(0, 40)}</td><td>{r.attack.n_malicious} / {r.attack.n_edges}</td>
            <td><span className={`pill ${r.result.detected.fused ? "protected" : "failed"}`}>{r.result.detected.fused ? "detected" : "missed"}</span> <span className="muted">{r.result.detected.d1 ? "d1 " : ""}{r.result.detected.d2 ? "d2" : ""}</span></td>
            <td>{r.result.ttd_s.fused != null ? `${(r.result.ttd_s.fused / 60).toFixed(1)} min` : "–"}</td><td className="score">{r.result.max.fused.toFixed(2)} / {r.result.max.r1.toFixed(2)} / {r.result.max.r2.toFixed(2)}</td>
            <td className="mono">{(r.result.flagged_labels || []).slice(0, 3).join("; ").slice(0, 90)}</td></tr>)}</tbody></table>
      </div>}
    </div>
  );
}
