import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, Plus, Search, Server } from "lucide-react";
import { ApiError, Endpoint, EnrollToken, post, useApi, useCan } from "../api";
import { fmtDateTime, fmtRel, plural } from "../format";
import { Card, CopyField, Dialog, Empty, EndpointStateBadge, ErrorState, Field, Loading, PageHeader, Segmented, Toggle } from "../ui";
import { ClusterForm, ClusterResult, ClustersCard, NewCluster } from "../clusters";
import { AgentUpdates } from "../updates";

export default function Endpoints() {
  const can = useCan(); const nav = useNavigate();
  const { data, error, loading, reload } = useApi<{ endpoints: Endpoint[] }>("/api/endpoints", 20000);
  const [q, setQ] = useState(""); const [retired, setRetired] = useState(false); const [adding, setAdding] = useState(false);
  // "#/endpoints?add=1" (from the overview's get-started card) opens the add dialog
  const [params, setParams] = useSearchParams();
  useEffect(() => {
    if (params.get("add") !== "1") return;
    if (can.manage_endpoints) setAdding(true);
    const p = new URLSearchParams(params); p.delete("add"); setParams(p, { replace: true });
  }, [params, setParams, can.manage_endpoints]);
  const all = data?.endpoints || [];
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    const order: Record<string, number> = { offline: 0, learning: 1, training: 1, protected: 2, retired: 3 };
    return all.filter(e => (retired || e.state !== "retired") && (!t || e.name.toLowerCase().includes(t) || (e.hostname || "").toLowerCase().includes(t)))
      .sort((a, b) => (b.open_incidents || 0) - (a.open_incidents || 0) || order[a.state] - order[b.state] || a.name.localeCompare(b.name));
  }, [all, q, retired]);
  const retiredN = all.filter(e => e.state === "retired").length;
  const active = all.length - retiredN;
  return (
    <div className="page">
      <PageHeader title="Endpoints" subtitle={data ? `${plural(active, "endpoint")} · ${all.filter(e => e.state === "protected").length} protected` : undefined}
        actions={can.manage_endpoints && <button className="btn primary" onClick={() => setAdding(true)}><Plus size={16} />Add endpoint</button>} />
      {active > 0 && <AgentUpdates />}
      <Card pad={false}>
        <div className="filters">
          <div className="search"><Search size={15} /><input placeholder="Search by name or host" value={q} onChange={e => setQ(e.target.value)} /></div>
          {retiredN > 0 && <label className="inline-toggle"><Toggle checked={retired} onChange={setRetired} label="Show retired" />Show retired ({retiredN})</label>}
          <div className="filters-end muted">{data ? plural(rows.length, "endpoint") : ""}</div>
        </div>
        {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
          rows.length === 0 ? <Empty icon={<Server size={22} />} title={all.length ? "No endpoints match" : "No endpoints yet"}
            text={all.length ? "Try another search." : "Install the PDP agent on a Linux host to start learning its normal behaviour."}
            action={!all.length && can.manage_endpoints ? <button className="btn primary" onClick={() => setAdding(true)}><Plus size={16} />Add endpoint</button> : undefined} /> : (
            <div className="table-wrap">
              <table className="table clickable">
                <thead><tr><th>Endpoint</th><th style={{ width: "30%" }}>Status</th><th className="num" style={{ width: 150 }}>Open incidents</th><th style={{ width: 150 }}>Last seen</th><th style={{ width: 110 }}>Agent</th></tr></thead>
                <tbody>{rows.map(e => (
                  <tr key={e.id} onClick={() => nav(`/endpoints/${e.id}`)} className={e.state === "retired" ? "row-muted" : ""}>
                    <td className="cell-main">
                      <Link to={`/endpoints/${e.id}`} className="row-title" onClick={ev => ev.stopPropagation()}>{e.name}</Link>
                      <div className="row-meta muted">{e.hostname}{e.os ? ` · ${e.os === "linux" ? "Linux" : e.os}` : ""}{e.kind && e.kind !== "live" ? ` · ${e.kind === "benchmark" ? "dataset replay" : e.kind}` : ""}</div>
                    </td>
                    <td><EndpointStateBadge state={e.state} text={e.state_text} />{e.state_text && <div className="muted sm ellipsis" title={e.state_text}>{e.state_text}</div>}</td>
                    <td className="num">{e.open_incidents ? <Link to={`/incidents?endpoint_id=${e.id}`} className="count-pill" onClick={ev => ev.stopPropagation()}>{e.open_incidents}</Link> : <span className="muted">0</span>}</td>
                    <td title={fmtDateTime(e.last_seen, true)}>{e.last_seen ? fmtRel(e.last_seen) : <span className="muted">never</span>}</td>
                    <td className="mono">{e.agent_version || "—"}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
      </Card>
      {can.manage_endpoints && <ClustersCard key={String(adding)} />}
      {adding && <AddEndpointDialog onClose={() => setAdding(false)} onCreated={reload} />}
    </div>
  );
}

function AddEndpointDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [mode, setMode] = useState<"server" | "k8s">("server"); const [cl, setCl] = useState<{ c: NewCluster; name: string } | null>(null);
  const [name, setName] = useState(""); const [tok, setTok] = useState<EnrollToken | null>(null);
  const [err, setErr] = useState<{ text: string; limit: boolean } | null>(null); const [busy, setBusy] = useState(false);
  const create = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(null); setBusy(true);
    try { setTok(await post<EnrollToken>("/api/endpoints", { name: name.trim() })); onCreated(); }
    catch (ex: any) {
      // 403 here is the organisation's endpoint limit; the server says what the limit is
      const limit = ex instanceof ApiError && ex.status === 403;
      setErr({ text: limit ? ex.detail || "Your organisation has reached its endpoint limit." : ex.message, limit });
    }
    setBusy(false);
  };
  const primary = tok?.install_command || tok?.enroll_command || "";
  if (mode === "k8s") return (
    <Dialog title={cl ? `Install the agent on cluster ${cl.name}` : "Add endpoint"} width={680} onClose={onClose}
      subtitle={cl ? "One agent per node, as a DaemonSet." : "A Kubernetes cluster: one manifest installs the agent on every node."}
      footer={cl ? <button className="btn primary" onClick={onClose}>Done</button> : <>
        <button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="add-k8s">Continue</button></>}>
      {!cl && <div style={{ marginBottom: 16 }}><Segmented value={mode} onChange={setMode} options={[{ id: "server", label: "One server" }, { id: "k8s", label: "Kubernetes cluster" }]} /></div>}
      {cl ? <ClusterResult c={cl.c} name={cl.name} /> : <ClusterForm id="add-k8s" onCreated={(c, n) => { setCl({ c, name: n }); onCreated(); }} />}
    </Dialog>
  );
  return (
    <Dialog title={tok ? `Install the agent on ${name.trim()}` : "Add endpoint"} width={680} onClose={onClose}
      subtitle={tok ? `The command contains a one-time token, valid for ${plural(tok.expires_in_hours, "hour")}.` : "Name the server, then run one command on it to install the agent."}
      footer={tok ? <button className="btn primary" onClick={onClose}>Done</button> : <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" form="add-ep" disabled={!name.trim() || busy}>{busy && <Loader2 size={14} className="spin" />}Continue</button></>}>
      {!tok ? (
        <form id="add-ep" onSubmit={create}>
          <div style={{ marginBottom: 16 }}><Segmented value={mode} onChange={setMode} options={[{ id: "server", label: "One server" }, { id: "k8s", label: "Kubernetes cluster" }]} /></div>
          <Field label="Endpoint name" hint="Shown in the console, e.g. web-01 or build-server.">
            <input value={name} onChange={e => setName(e.target.value)} autoFocus maxLength={128} placeholder="web-01" />
          </Field>
          {err && <div className="err">{err.text}{err.limit && <> Retire an endpoint you no longer use, or contact PDP support to raise the limit.</>}</div>}
        </form>
      ) : (
        <div className="install">
          <div className="install-step">Run on the Linux server as root</div>
          <CopyField multiline value={primary} />
          <div className="install-req">Needs Linux kernel 5.8 or newer, internet access to this console, and Docker (installed automatically if missing).</div>
          <div className="install-note">
            The endpoint appears here as soon as the agent enrols. Detection starts after one hour with an early model that
            reports high-confidence findings; it is retrained as the agent learns and is complete after 8 days.
          </div>
          <details className="install-more">
            <summary>Other ways to install</summary>
            {tok.docker_command && <CopyField label="Servers that only run containers: start the agent with Docker" multiline value={tok.docker_command} />}
            {tok.install_command && tok.enroll_command && <CopyField label="Agent already installed: enrol it with" multiline value={tok.enroll_command} />}
            <CopyField label="Server CA fingerprint (SHA-256), also used to pin the desktop console" value={tok.ca_sha256} />
          </details>
        </div>
      )}
    </Dialog>
  );
}
