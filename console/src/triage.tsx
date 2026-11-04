import { useState } from "react";
import { MessageSquare, UserRound } from "lucide-react";
import { post, useCan } from "./api";
import { fmtDateTime, fmtRel } from "./format";
import { Card, useToast } from "./ui";

export type HistoryRow = { id: number; kind: "status" | "assign" | "note"; text: string | null; value: string | null; at: string; by: string | null };
export type Person = { id: number; name: string };

const STATUS_TEXT: Record<string, string> = { open: "reopened it", investigating: "started investigating", true_positive: "confirmed it as a real threat",
  false_positive: "marked it a false alarm", resolved: "resolved it" };

/** Owner, notes and history of an incident (incident page). */
export function TriageCard({ incidentId, assignee, assignable, history, reload }:
  { incidentId: number; assignee: Person | null; assignable: Person[]; history: HistoryRow[]; reload: () => void }) {
  const can = useCan(); const toast = useToast();
  const [note, setNote] = useState(""); const [busy, setBusy] = useState(false);
  const assign = async (v: string) => {
    try { await post(`/api/incidents/${incidentId}/assign`, { user_id: v ? Number(v) : null }); toast(v ? "Owner set" : "Owner removed"); reload(); }
    catch (e: any) { toast(e.message, "err"); }
  };
  const addNote = async () => {
    if (!note.trim()) return;
    setBusy(true);
    try { await post(`/api/incidents/${incidentId}/notes`, { text: note }); setNote(""); reload(); }
    catch (e: any) { toast(e.message, "err"); } finally { setBusy(false); }
  };
  return (
    <Card title="Triage" className="triage-card">
      <div className="triage-owner">
        <UserRound size={16} className="muted" />
        <span className="muted">Owner</span>
        {can.triage ? (
          <select value={assignee?.id ?? ""} onChange={e => assign(e.target.value)} aria-label="Owner">
            <option value="">Nobody yet</option>
            {assignable.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        ) : <b>{assignee?.name || "Nobody yet"}</b>}
      </div>
      {can.triage && <div className="triage-note">
        <textarea rows={2} placeholder="Add a note: what you checked, who you contacted, what you changed…" value={note} onChange={e => setNote(e.target.value)} />
        <button className="btn sm" disabled={busy || !note.trim()} onClick={addNote}><MessageSquare size={14} />Add note</button>
      </div>}
      {history.length > 0 ? (
        <ol className="triage-history">
          {[...history].reverse().map(h => (
            <li key={h.id} className={h.kind}>
              <div><b>{h.by || "Someone"}</b>{" "}
                {h.kind === "note" ? "wrote" : h.kind === "assign" ? (h.value ? <>assigned it to <b>{h.text}</b></> : "removed the owner") : STATUS_TEXT[h.value || ""] || `set it to ${h.value}`}
                <span className="muted sm" title={fmtDateTime(h.at, true)}> · {fmtRel(h.at)}</span></div>
              {h.text && h.kind !== "assign" && <div className="triage-text">{h.text}</div>}
            </li>
          ))}
        </ol>
      ) : <p className="muted sm">No notes or changes yet.</p>}
    </Card>
  );
}
