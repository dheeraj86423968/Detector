import { useState } from "react";
import { Ban, Unplug, Plug } from "lucide-react";
import { api, post, useApi, useCan } from "./api";
import { Card, Confirm, useToast } from "./ui";

/** Response actions are on for the organisation (Security settings) and the user is an admin. */
export function useResponse(): boolean {
  const can = useCan();
  const { data } = useApi<{ org: { response_actions?: boolean } }>(can.manage_org ? "/api/org" : null);
  return !!(can.manage_org && data?.org.response_actions);
}

/** Queue an action and report the agent's answer (it acts within its next status poll, about 30 s). */
export async function runAction(endpointId: string, body: { action: string; node_uuid?: string }, toast: (t: string, tone?: "ok" | "err" | "info") => void, done?: () => void) {
  try {
    const r = await post<{ id: string }>(`/api/endpoints/${endpointId}/respond`, body);
    toast("Sent to the agent; it acts within about 30 seconds", "info");
    for (let i = 0; i < 40; i++) {
      await new Promise(res => setTimeout(res, 3000));
      const j = await api<{ state: string; result: string | null }>(`/api/endpoints/${endpointId}/commands/${r.id}`);
      if (j.state !== "queued" && j.state !== "running") {
        toast(j.result || j.state, (j.result || "").startsWith("ok") ? "ok" : "err"); done?.(); return;
      }
    }
    toast("No answer from the agent yet; check the endpoint later", "err");
  } catch (e: any) { toast(e.message, "err"); }
}

export function StopProcessButton({ endpointId, nodeUuid, label }: { endpointId: string; nodeUuid: string; label: string }) {
  const toast = useToast(); const [ask, setAsk] = useState(false);
  return (<>
    <button className="btn sm danger-soft" title="Stop this process on the endpoint" onClick={e => { e.stopPropagation(); setAsk(true); }}><Ban size={14} />Stop</button>
    {ask && <Confirm danger title="Stop this process?" confirmLabel="Stop process" onClose={() => setAsk(false)}
      text={<p>The agent ends <code className="code-inline">{label}</code> on the endpoint, if it still runs as the same process (a reused process id is never touched).</p>}
      onConfirm={async () => { setAsk(false); await runAction(endpointId, { action: "kill_process", node_uuid: nodeUuid }, toast); }} />}
  </>);
}

export function IsolationCard({ endpointId, isolated, reload }: { endpointId: string; isolated: boolean; reload: () => void }) {
  const toast = useToast(); const [ask, setAsk] = useState<"isolate" | "release" | null>(null);
  return (
    <Card title="Response" className="learning-card">
      <div className="row-gap">
        {isolated ? <><Unplug size={16} className="warn-text" /><b>Isolated:</b> only the M.D Lab Detector server is reachable from this endpoint.</>
          : <><Plug size={16} className="muted" />Network normal.</>}
        <span style={{ flex: 1 }} />
        {isolated ? <button className="btn" onClick={() => setAsk("release")}>Release</button>
          : <button className="btn danger-soft" onClick={() => setAsk("isolate")}><Unplug size={15} />Isolate endpoint</button>}
      </div>
      {ask && <Confirm danger={ask === "isolate"} title={ask === "isolate" ? "Isolate this endpoint?" : "Release this endpoint?"} confirmLabel={ask === "isolate" ? "Isolate" : "Release"}
        onClose={() => setAsk(null)}
        text={ask === "isolate" ? <p>All network traffic of the endpoint is blocked except to the M.D Lab Detector server (and DNS), until you release it. Its services stop being reachable. It stays isolated across agent restarts.</p>
          : <p>Network traffic of the endpoint is allowed again.</p>}
        onConfirm={async () => { const a = ask; setAsk(null); await runAction(endpointId, { action: a }, toast, reload); }} />}
    </Card>
  );
}
