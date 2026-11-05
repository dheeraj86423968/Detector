import { useState } from "react";
import { Loader2, Trash2 } from "lucide-react";
import { del, post } from "./api";
import { CopyField, cx, Dialog, useToast } from "./ui";

/** Remove an endpoint: retire it (its alerts and incidents stay for the record) or delete it with all its data.
 *  Either way its agent's certificate stops working; the agent itself is removed on the host with the uninstall
 *  command. Deleting asks for the endpoint's name. */
export function RemoveEndpointDialog({ ep, onClose, onDone }: {
  ep: { id: string; name: string; state?: string }; onClose: () => void; onDone: (how: "retired" | "deleted") => void;
}) {
  const toast = useToast();
  const retired = ep.state === "retired";
  const [how, setHow] = useState<"retire" | "delete">(retired ? "delete" : "retire");
  const [typed, setTyped] = useState(""); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const uninstall = `curl -fsSL ${window.location.origin}/install.sh | sudo bash -s -- --uninstall --purge`;
  const ready = how === "retire" || typed.trim() === ep.name;
  const go = async () => {
    setBusy(true); setErr("");
    try {
      if (how === "retire") { await post(`/api/endpoints/${ep.id}/retire`); toast(`${ep.name} retired`); onDone("retired"); }
      else { await del(`/api/endpoints/${ep.id}`); toast(`${ep.name} deleted`); onDone("deleted"); }
      onClose();
    } catch (e: any) { setErr(e.message); setBusy(false); }
  };
  return (
    <Dialog title={`Remove ${ep.name}`} width={600} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button>
        <button className={cx("btn", how === "delete" ? "danger" : "primary")} disabled={!ready || busy} onClick={go}>
          {busy ? <Loader2 size={14} className="spin" /> : <Trash2 size={14} />}{how === "retire" ? "Retire endpoint" : "Delete permanently"}</button></>}>
      <div className="remove-choice">
        {!retired && <label className={cx("choice", how === "retire" && "on")}>
          <input type="radio" name="how" checked={how === "retire"} onChange={() => setHow("retire")} />
          <div><b>Retire</b><div className="muted sm">Stops accepting its agent and deletes its raw activity data. Its alerts and incidents stay for the
            record, shown under "Show retired". It no longer counts against your endpoint limit.</div></div>
        </label>}
        <label className={cx("choice", how === "delete" && "on")}>
          <input type="radio" name="how" checked={how === "delete"} onChange={() => setHow("delete")} />
          <div><b>Delete permanently</b><div className="muted sm">Deletes the endpoint with everything about it: alerts, incidents, models,
            activity data and detection checks. This cannot be undone.</div></div>
        </label>
      </div>
      {how === "delete" && <label className="field" style={{ marginTop: 14 }}>
        <span className="field-label">Type <b>{ep.name}</b> to confirm</span>
        <input value={typed} onChange={e => setTyped(e.target.value)} autoFocus />
      </label>}
      <div style={{ marginTop: 16 }}>
        <CopyField label="Then remove the agent from the server (as root)" multiline value={uninstall} />
        <div className="muted sm" style={{ marginTop: 4 }}>Until then the agent keeps running there, but the server no longer accepts its data.</div>
      </div>
      {err && <div className="err">{err}</div>}
    </Dialog>
  );
}
