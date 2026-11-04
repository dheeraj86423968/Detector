import { useState } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { patch, useApi, useCan } from "./api";
import { Card, Dialog, Field, useToast } from "./ui";

type Policy = { policy: string; latest: string | null; target: string | null; held: string | null; staged: boolean;
  versions: Record<string, number>; canary_minutes: number };

const label = (p: string) => p === "auto" ? "Automatic" : p === "manual" ? "Manual" : `Pinned to ${p}`;

/** Agent updates for the organisation: policy, rollout state, versions in use (Endpoints page). */
export function AgentUpdates() {
  const can = useCan(); const toast = useToast();
  const { data, reload } = useApi<Policy>("/api/org/agent-updates", 30000);
  const [edit, setEdit] = useState(false);
  if (!data) return null;
  const versions = Object.entries(data.versions).sort();
  const behind = versions.filter(([v]) => v !== data.target).reduce((n, [, k]) => n + k, 0);
  return (
    <Card className="updates-card">
      <div className="updates-row">
        <RefreshCw size={16} className="muted" />
        <div className="min0">
          <div><b>Agent updates: {label(data.policy)}</b>{data.latest && <span className="muted"> · latest {data.latest}</span>}</div>
          <div className="muted sm">
            {data.held ? <span className="warn-text"><AlertTriangle size={13} /> Rollout paused: {data.held}</span>
              : data.policy === "manual" ? "Agents keep their version until you choose one."
              : behind === 0 ? `All agents run ${data.target}.`
              : data.staged ? `Updating to ${data.target}: one endpoint first, the rest after it has run ${Math.round(data.canary_minutes)} minutes without problems.`
              : `Updating ${behind} agent${behind === 1 ? "" : "s"} to ${data.target}.`}
            {versions.length > 0 && <> In use: {versions.map(([v, n]) => `${v} (${n})`).join(", ")}.</>}
          </div>
        </div>
        {can.manage_org && <button className="btn sm" onClick={() => setEdit(true)}>Change</button>}
      </div>
      {edit && <PolicyDialog cur={data} onClose={() => setEdit(false)} onDone={() => { toast("Update policy saved"); reload(); }} />}
    </Card>
  );
}

function PolicyDialog({ cur, onClose, onDone }: { cur: Policy; onClose: () => void; onDone: () => void }) {
  const [mode, setMode] = useState(cur.policy === "auto" || cur.policy === "manual" ? cur.policy : "pin");
  const [ver, setVer] = useState(cur.policy !== "auto" && cur.policy !== "manual" ? cur.policy : cur.latest || "");
  const [err, setErr] = useState<string | null>(null);
  const save = async () => {
    try { await patch("/api/org/agent-updates", { agent_update: mode === "pin" ? ver.trim() : mode }); onDone(); onClose(); }
    catch (e: any) { setErr(e.message); }
  };
  return (
    <Dialog title="Agent updates" onClose={onClose} footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={save}>Save</button></>}>
      <Field label="How agents are updated" error={err}>
        <div className="check-list">
          <label className="check"><input type="radio" checked={mode === "auto"} onChange={() => setMode("auto")} />Automatic (recommended): every new version, one endpoint first</label>
          <label className="check"><input type="radio" checked={mode === "pin"} onChange={() => setMode("pin")} />Pinned to a version</label>
          <label className="check"><input type="radio" checked={mode === "manual"} onChange={() => setMode("manual")} />Manual: never update agents</label>
        </div>
      </Field>
      {mode === "pin" && <Field label="Version" hint={cur.latest ? `Latest on this server: ${cur.latest}` : undefined}><input value={ver} onChange={e => setVer(e.target.value)} className="mono" placeholder="0.3.8" /></Field>}
      <p className="muted sm">An update is pulled by the host's updater and checked: if the new agent does not start and report within a few
        minutes, the host goes back to the previous version and the rollout pauses for your organisation.</p>
    </Dialog>
  );
}
