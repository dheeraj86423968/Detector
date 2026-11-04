import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Loader2, Plus, Search, Server } from "lucide-react";
import { Endpoint, EnrollToken, post, useApi, useCan } from "../api";
import { fmtDateTime, fmtRel, plural } from "../format";
import { Card, CopyField, Dialog, Empty, EndpointStateBadge, ErrorState, Field, Loading, PageHeader, Segmented, Toggle } from "../ui";

export default function Endpoints() {
  const can = useCan(); const nav = useNavigate();
  const { data, error, loading, reload } = useApi<{ endpoints: Endpoint[] }>("/api/endpoints", 20000);
  const [q, setQ] = useState(""); const [retired, setRetired] = useState(false); const [adding, setAdding] = useState(false);
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
      {adding && <AddEndpointDialog onClose={() => setAdding(false)} onCreated={reload} />}
    </div>
  );
}

function AddEndpointDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState(""); const [tok, setTok] = useState<EnrollToken | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false); const [how, setHow] = useState<"package" | "docker">("package");
  const create = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try { setTok(await post<EnrollToken>("/api/endpoints", { name: name.trim() })); onCreated(); } catch (ex: any) { setErr(ex.message); }
    setBusy(false);
  };
  const server = `https://${window.location.host}`;
  const isDocker = !!tok?.docker_command;
  return (
    <Dialog title={tok ? `Install the agent on ${name}` : "Add endpoint"} width={680} onClose={onClose}
      subtitle={tok ? `The enrolment token is valid for ${tok.expires_in_hours} hours and can be used once.` : "Create a one-time enrolment token, then run the install command on the host."}
      footer={tok ? <button className="btn primary" onClick={onClose}>Done</button> : <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" form="add-ep" disabled={!name.trim() || busy}>{busy && <Loader2 size={14} className="spin" />}Create token</button></>}>
      {!tok ? (
        <form id="add-ep" onSubmit={create}>
          <Field label="Endpoint name" hint="Shown in the console, e.g. web-01 or build-server.">
            <input value={name} onChange={e => setName(e.target.value)} autoFocus maxLength={128} placeholder="web-01" />
          </Field>
          {err && <div className="err">{err}</div>}
        </form>
      ) : (
        <div className="install">
          <Segmented value={how} onChange={setHow} options={[{ id: "package", label: "Linux package" }, { id: "docker", label: isDocker ? "Docker" : "Manual enrolment" }]} />
          {how === "package" ? <>
            <ol className="steps">
              <li>Install the <b>pdp-agent</b> package (.deb or .rpm) on the host.</li>
              <li>Run this command as root:</li>
            </ol>
            <CopyField multiline value={tok.install_command || `sudo pdp-agent-install --server ${server} --token ${tok.token} --ca-sha256 ${tok.ca_sha256}`} />
          </> : <>
            <p className="muted">{isDocker ? "Run the agent as a container on the host:" : "On a host where the agent is already installed, enrol it with:"}</p>
            <CopyField multiline value={tok.docker_command || tok.enroll_command} />
          </>}
          <div className="install-note">
            The endpoint appears here once the agent enrols. It first learns the host's normal behaviour for a few days; detection starts automatically after that.
          </div>
          <CopyField label="Server CA fingerprint (SHA-256) — also used to pin the desktop console" value={tok.ca_sha256} />
        </div>
      )}
    </Dialog>
  );
}
