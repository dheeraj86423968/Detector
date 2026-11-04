import { useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { post, useApi } from "./api";
import { fmtDate, plural } from "./format";
import { Card, CopyField, Field, useToast } from "./ui";

/** Kubernetes: one manifest (DaemonSet) per cluster, enrolling every node with one limited, expiring fleet token. */
type Cluster = { key: string; cluster: string; uses: number; max_nodes: number; expires_at: string; active: boolean; endpoints: number };
export type NewCluster = { key: string; expires_at: string; max_nodes: number; manifest: string };

export const saveText = (name: string, text: string) => {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/yaml" })); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};

export function ClusterForm({ id, onCreated }: { id: string; onCreated: (c: NewCluster, name: string) => void }) {
  const [name, setName] = useState(""); const [nodes, setNodes] = useState(20); const [days, setDays] = useState(30);
  const [err, setErr] = useState<string | null>(null);
  return (
    <form id={id} onSubmit={async e => {
      e.preventDefault(); setErr(null);
      try { onCreated(await post<NewCluster>("/api/clusters", { cluster: name.trim(), max_nodes: nodes, days }), name.trim()); }
      catch (ex: any) { setErr(ex.message); }
    }}>
      <Field label="Cluster name" hint="Each node appears as its own endpoint, named after the node.">
        <input value={name} onChange={e => setName(e.target.value)} autoFocus maxLength={63} placeholder="prod-eu-1" />
      </Field>
      <div className="hrow">
        <Field label="Nodes it may enrol" hint="Room for growth; new nodes beyond this need a new manifest.">
          <input type="number" min={1} max={5000} value={nodes} onChange={e => setNodes(Number(e.target.value))} />
        </Field>
        <Field label="Valid for (days)" hint="New nodes can join until then; enrolled nodes keep working.">
          <input type="number" min={1} max={365} value={days} onChange={e => setDays(Number(e.target.value))} />
        </Field>
      </div>
      {err && <div className="err">{err}</div>}
    </form>
  );
}

export function ClusterResult({ c, name }: { c: NewCluster; name: string }) {
  const file = `pdp-agent-${name.replace(/[^A-Za-z0-9._-]+/g, "-")}.yaml`;
  return (
    <div className="install">
      <div className="install-step">Save the manifest, then apply it with access to the cluster</div>
      <div className="hrow"><button className="btn primary" onClick={() => saveText(file, c.manifest)}><Download size={16} />Download {file}</button></div>
      <CopyField multiline value={`kubectl apply -f ${file}`} />
      <div className="install-req">Needs Linux nodes with kernel 5.8 or newer and privileged pods allowed in the pdp-system namespace.
        The file holds an enrolment token for up to {plural(c.max_nodes, "node")}, valid until {fmtDate(c.expires_at)}: keep it like a password.</div>
      <div className="install-note">To update the agents later, download a fresh manifest from the Kubernetes clusters list and apply it again.</div>
    </div>
  );
}

export function ClustersCard() {
  const { data, reload } = useApi<{ clusters: Cluster[] }>("/api/clusters");
  const toast = useToast(); const [busy, setBusy] = useState<string | null>(null);
  if (!data?.clusters.length) return null;
  const download = async (c: Cluster) => {
    setBusy(c.key);
    try {
      const r = await fetch(`/api/clusters/${c.key}/manifest`, { credentials: "same-origin" });
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
      saveText(`pdp-agent-${c.cluster.replace(/[^A-Za-z0-9._-]+/g, "-")}.yaml`, await r.text());
    } catch (e: any) { toast(e.message, "err"); } finally { setBusy(null); }
  };
  return (
    <Card title="Kubernetes clusters" pad={false}>
      <table className="table middle"><tbody>{data.clusters.map(c => (
        <tr key={c.key} className={c.active ? "" : "row-muted"}>
          <td><b>{c.cluster}</b><div className="muted sm">{plural(c.endpoints, "endpoint")} · {c.uses} of {c.max_nodes} enrolments used</div></td>
          <td className="muted sm">{c.active ? `new nodes can join until ${fmtDate(c.expires_at)}` : "closed to new nodes"}</td>
          <td style={{ width: 280, textAlign: "right" }}>{c.active && <>
            <button className="btn sm" disabled={busy === c.key} onClick={() => download(c)}>{busy === c.key ? <Loader2 size={14} className="spin" /> : <Download size={14} />}Manifest</button>{" "}
            <button className="btn sm" onClick={async () => { await post(`/api/clusters/${c.key}/revoke`); toast("Closed: no new nodes can join with this manifest"); reload(); }}>Close to new nodes</button></>}
          </td></tr>))}</tbody></table>
    </Card>
  );
}
