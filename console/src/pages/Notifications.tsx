import { useState } from "react";
import { AlertTriangle, Bell, Hash, Mail, MessageSquare, Plus, Send, Server, Trash2, Webhook } from "lucide-react";
import { del, patch, post, useApi, useCan } from "../api";
import { fmtDateTime, fmtRel } from "../format";
import { Card, Confirm, Dialog, Empty, ErrorState, Field, Loading, Mid, PageHeader, ReadOnlyHint, Segmented, Toggle, useToast } from "../ui";

type Kind = "email" | "slack" | "teams" | "webhook" | "syslog";
type Channel = {
  id: number; name: string; kind: Kind; target: string; has_secret: boolean; min_severity: string; events: string[];
  every_alert: boolean; enabled: boolean; created_by: string | null; created_at: string; last_ok_at: string | null;
  last_error: string | null; last_error_at: string | null;
};
type Resp = { channels: Channel[]; email_available: boolean; notifier_running: boolean };
type LogRow = { key: string; subject: string | null; state: string; detail: string | null; at: string };

const KIND: Record<Kind, { label: string; icon: JSX.Element; target: string; placeholder: string; hint: string }> = {
  email: { label: "E-mail", icon: <Mail size={16} />, target: "Recipients", placeholder: "soc@example.com, oncall@example.com",
    hint: "Up to ten addresses, separated by commas." },
  slack: { label: "Slack", icon: <Hash size={16} />, target: "Incoming webhook URL", placeholder: "https://hooks.slack.com/services/…",
    hint: "In Slack: Apps → Incoming Webhooks → Add to a channel, then paste the webhook URL here." },
  teams: { label: "Teams", icon: <MessageSquare size={16} />, target: "Incoming webhook URL", placeholder: "https://…webhook.office.com/…",
    hint: "In the Teams channel: ••• → Workflows → “Post to a channel when a webhook request is received”, then paste the URL." },
  webhook: { label: "Webhook", icon: <Webhook size={16} />, target: "HTTPS URL", placeholder: "https://soar.example.com/pdp",
    hint: "M.D Lab Detector POSTs JSON. With a signing secret every request carries X-PDP-Signature: sha256=HMAC(secret, timestamp + \".\" + body)." },
  syslog: { label: "Syslog (SIEM)", icon: <Server size={16} />, target: "Syslog address", placeholder: "tls://siem.example.com:6514",
    hint: "CEF over tls://, tcp:// or udp://. Use TLS across the internet." },
};
const EVENT_TEXT: Record<string, string> = {
  incident: "Incidents", agent_offline: "Agent offline / back", weekly: "Weekly summary (Monday morning)", agent_health: "Agent health (lost events, disk, updates)",
  platform: "Platform problems (operator: backups, job queues, server disk)",
  detection_weakened: "Detection weakened (settings, allow list, model posture; always sent with incidents)",
  response_action: "Response actions (process stopped, endpoint isolated; always sent with incidents)",
};
const SEV_TEXT: Record<string, string> = { low: "Low and above", medium: "Medium and above", high: "High and above", critical: "Critical only" };

export default function Notifications() {
  const can = useCan(); const toast = useToast();
  const { data, error, loading, reload } = useApi<Resp>("/api/notifications/channels", 15000);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Channel | null>(null);
  const [removing, setRemoving] = useState<Channel | null>(null);
  const [logOf, setLogOf] = useState<Channel | null>(null);
  const edit = can.manage_org;      // auditors (view_admin) see the channels read-only, URLs reduced to their host by the server
  if (!edit && !can.view_admin) return <div className="page"><PageHeader title="Notifications" /><Card><p className="muted">Only administrators manage notifications.</p></Card></div>;
  const chans = data?.channels || [];
  const test = async (c: Channel) => {
    try { await post(`/api/notifications/channels/${c.id}/test`); toast(`Test message on its way to ${c.name}`); setTimeout(reload, 4000); }
    catch (e: any) { toast(e.message, "err"); }
  };
  const toggle = async (c: Channel, v: boolean) => {
    try { await patch(`/api/notifications/channels/${c.id}`, { enabled: v }); reload(); } catch (e: any) { toast(e.message, "err"); }
  };
  return (
    <div className="page">
      <PageHeader title="Notifications" subtitle="Where M.D Lab Detector tells your team about incidents and agent problems, and feeds your SIEM."
        actions={edit && <button className="btn primary" onClick={() => setAdding(true)}><Plus size={16} />Add channel</button>} />
      {!edit && <ReadOnlyHint text="Read-only: you can see where notifications go and what was sent, but not change channels. Webhook addresses show only their host." />}
      {data && !data.notifier_running && <div className="banner warn"><AlertTriangle size={16} />The notification service is not running on this server; messages are queued until it is back.</div>}
      <Card pad={false}>
        {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
          chans.length === 0 ? (
            <Empty icon={<Bell size={22} />} title="No notification channels yet"
              text="Add an e-mail list, a Slack or Teams channel, or a webhook, and M.D Lab Detector sends new incidents (high severity and above by default), agents that stop reporting, and collector problems there within seconds. Send a test message to check it."
              action={edit ? <button className="btn primary" onClick={() => setAdding(true)}><Plus size={16} />Add channel</button> : undefined} />
          ) : (
            <div className="table-wrap">
              <table className="table middle">
                <thead><tr><th>Channel</th><th style={{ width: "26%" }}>Sends</th><th style={{ width: "24%" }}>Last delivery</th><th style={{ width: 70 }}>On</th><th style={{ width: 230 }}></th></tr></thead>
                <tbody>{chans.map(c => (
                  <tr key={c.id}>
                    <td className="cell-main">
                      <div className="allow-entry">
                        <span className="muted">{KIND[c.kind].icon}</span>
                        <div className="min0">
                          <div className="ellipsis"><b>{c.name}</b> <span className="muted sm">{KIND[c.kind].label}</span></div>
                          <Mid text={c.kind === "email" ? c.target : shortUrl(c.target)} className="mono muted sm" title={c.kind === "email" ? c.target : undefined} />
                        </div>
                      </div>
                    </td>
                    <td className="sm">
                      {c.events.includes("incident") && <div>Incidents · {SEV_TEXT[c.min_severity]}</div>}
                      {c.events.filter(e => e !== "incident").map(e => <div key={e}>{EVENT_TEXT[e]}</div>)}
                      {c.every_alert && <div>Every alert (SIEM feed)</div>}
                      {!c.events.length && !c.every_alert && <span className="muted">Nothing selected</span>}
                    </td>
                    <td className="sm">
                      {c.last_error && (!c.last_ok_at || (c.last_error_at || "") > c.last_ok_at)
                        ? <div className="err-text" title={c.last_error}><AlertTriangle size={13} /> Failed {fmtRel(c.last_error_at)}: <span className="clamp2">{c.last_error}</span></div>
                        : c.last_ok_at ? <span title={fmtDateTime(c.last_ok_at, true)}>Delivered {fmtRel(c.last_ok_at)}</span> : <span className="muted">Nothing sent yet</span>}
                    </td>
                    <td><Toggle checked={c.enabled} disabled={!edit} onChange={v => toggle(c, v)} label={`${c.enabled ? "Disable" : "Enable"} ${c.name}`} /></td>
                    <td className="row-actions">
                      {edit && <button className="btn sm" onClick={() => test(c)} title="Send a test message now"><Send size={14} />Test</button>}
                      <button className="btn sm ghost" onClick={() => setLogOf(c)}>History</button>
                      {edit && <button className="btn sm ghost" onClick={() => setEditing(c)}>Edit</button>}
                      {edit && <button className="btn sm ghost" onClick={() => setRemoving(c)} title="Delete channel"><Trash2 size={14} /></button>}
                    </td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
      </Card>
      <p className="muted sm pad-top">At most 20 messages per channel and hour; anything beyond is summarised in one message per hour, so a noisy endpoint cannot flood a channel.</p>
      {(adding || editing) && <ChannelDialog ch={editing} emailOk={!!data?.email_available} onClose={() => { setAdding(false); setEditing(null); }}
        onDone={(c, created) => { toast(created ? `${c.name} added. Send a test message to check it.` : `${c.name} saved`); reload(); }} />}
      {removing && <Confirm danger title={`Delete ${removing.name}?`} confirmLabel="Delete channel" onClose={() => setRemoving(null)}
        text={<p>M.D Lab Detector stops sending to this channel. Its delivery history is deleted with it.</p>}
        onConfirm={async () => { await del(`/api/notifications/channels/${removing.id}`); toast("Channel deleted"); reload(); }} />}
      {logOf && <LogDialog ch={logOf} onClose={() => setLogOf(null)} />}
    </div>
  );
}

function shortUrl(u: string) {
  try { const x = new URL(u.replace(/^(tls|tcp|udp):/, "https:")); return `${u.split(":")[0]}://${x.host}${x.pathname.length > 1 ? "/…" : ""}`; } catch { return u; }
}

function ChannelDialog({ ch, emailOk, onClose, onDone }: { ch: Channel | null; emailOk: boolean; onClose: () => void; onDone: (c: Channel, created: boolean) => void }) {
  const [kind, setKind] = useState<Kind>(ch?.kind || "slack");
  const [name, setName] = useState(ch?.name || "");
  const [target, setTarget] = useState(ch?.target || "");
  const [secret, setSecret] = useState("");
  const [sev, setSev] = useState(ch?.min_severity || "high");
  const [events, setEvents] = useState<string[]>(ch?.events || ["incident", "agent_offline", "agent_health", "weekly", "detection_weakened", "response_action"]);
  const [every, setEvery] = useState(!!ch?.every_alert);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const k = KIND[kind];
  const flip = (e: string) => setEvents(events.includes(e) ? events.filter(x => x !== e) : [...events, e]);
  const save = async () => {
    setBusy(true); setErr(null);
    try {
      const body: any = { name: name.trim() || k.label, target, min_severity: sev, events, every_alert: every && (kind === "webhook" || kind === "syslog") };
      if (secret) body.secret = secret;
      const r = ch ? await patch<{ channel: Channel }>(`/api/notifications/channels/${ch.id}`, body)
                   : await post<{ channel: Channel }>("/api/notifications/channels", { ...body, kind });
      onDone(r.channel, !ch); onClose();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <Dialog title={ch ? `Edit ${ch.name}` : "Add a notification channel"} onClose={onClose} width={600}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy || !target.trim() || (kind === "email" && !emailOk)} onClick={save}>{ch ? "Save" : "Add channel"}</button></>}>
      {!ch && <Field label="Type">
        <Segmented value={kind} onChange={v => { setKind(v); setErr(null); }} options={(Object.keys(KIND) as Kind[]).map(x => ({ id: x, label: KIND[x].label }))} />
      </Field>}
      {kind === "email" && !emailOk && <div className="banner warn"><AlertTriangle size={16} />E-mail is not set up on this server yet. Use Slack, Teams or a webhook, or ask your provider.</div>}
      <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} placeholder={kind === "email" ? "Security team" : kind === "slack" ? "#security-alerts" : k.label} /></Field>
      <Field label={k.target} hint={k.hint} error={err}><input value={target} onChange={e => setTarget(e.target.value)} placeholder={k.placeholder} className="mono" /></Field>
      {kind === "webhook" && <Field label="Signing secret" hint={ch?.has_secret ? "A secret is set. Enter a new one to replace it." : "Optional. Lets your receiver check that a request came from M.D Lab Detector."}>
        <input value={secret} onChange={e => setSecret(e.target.value)} type="password" autoComplete="new-password" /></Field>}
      <Field label="Send">
        <div className="check-list">
          {(["incident", "agent_offline", "agent_health", "weekly", "detection_weakened", "response_action", ...(useCan().operate ? ["platform"] as const : [])] as const).map(e => (
            <label key={e} className="check"><input type="checkbox" checked={events.includes(e)} onChange={() => flip(e)} />{EVENT_TEXT[e]}</label>))}
          {(kind === "webhook" || kind === "syslog") && <label className="check"><input type="checkbox" checked={every} onChange={() => setEvery(!every)} />Every single alert as well (SIEM feed)</label>}
        </div>
      </Field>
      {events.includes("incident") && <Field label="Incidents of severity" hint="A message when an incident reaches this severity, and again if it escalates.">
        <select value={sev} onChange={e => setSev(e.target.value)}>{Object.entries(SEV_TEXT).map(([v, t]) => <option key={v} value={v}>{t}</option>)}</select>
      </Field>}
    </Dialog>
  );
}

function LogDialog({ ch, onClose }: { ch: Channel; onClose: () => void }) {
  const { data, error, loading } = useApi<{ log: LogRow[] }>(`/api/notifications/log?channel_id=${ch.id}&limit=100`, 5000);
  const STATE: Record<string, string> = { sent: "Sent", failed: "Failed", suppressed: "Held back (hourly limit)", digest: "Summary sent", queued: "Queued" };
  return (
    <Dialog title={`${ch.name}: recent messages`} onClose={onClose} width={720} footer={<button className="btn" onClick={onClose}>Close</button>}>
      {loading && !data ? <Loading block /> : error ? <ErrorState error={error} /> : !data?.log.length ? <p className="muted">Nothing sent yet.</p> : (
        <table className="table middle"><thead><tr><th style={{ width: 150 }}>When</th><th>Message</th><th style={{ width: 170 }}>Result</th></tr></thead>
          <tbody>{data.log.map(r => (
            <tr key={r.key}><td className="sm" title={fmtDateTime(r.at, true)}>{fmtRel(r.at)}</td>
              <td className="sm"><span className="clamp2">{r.subject || r.key}</span></td>
              <td className="sm">{r.state === "failed" ? <span className="err-text" title={r.detail || ""}>{STATE[r.state]}{r.detail ? `: ${r.detail}` : ""}</span> : STATE[r.state] || r.state}</td></tr>
          ))}</tbody></table>
      )}
    </Dialog>
  );
}
