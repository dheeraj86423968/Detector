import { useCallback, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, CheckCircle2, ChevronRight, Clock, Cpu, FileText, Globe, Layers, Play, RotateCcw, Search, Server, ShieldCheck, ShieldX, Siren, X } from "lucide-react";
import { AllowAlertDialog, addressOptions, allowedText } from "../allowlist";
import { AllowOption, api, ApiError, GNode, IncidentDetail as Detail, IncidentStatus, IncidentSummary, post, useApi, useCan } from "../api";
import { detection, fmtDateTime, fmtRel, fmtSpan, fmtTime, plural, reasonText, shortCmd } from "../format";
import { AttackGraph } from "../graph/AttackGraph";
import type { VNode } from "../graph/model";
import { TriageCard } from "../triage";
import { Card, Chip, cx, DetectionTag, Empty, ErrorState, Loading, Mid, NodeIcon, PageHeader, PathText, SeverityBadge, ShowMore, StatusBadge, useShowMore, useToast } from "../ui";

const ACTIONS: { status: IncidentStatus; label: string; icon: JSX.Element; tone?: string; done: string }[] = [
  { status: "investigating", label: "Mark as investigating", icon: <Search size={15} />, done: "Incident marked as investigating" },
  { status: "true_positive", label: "Confirm threat", icon: <Siren size={15} />, tone: "danger-soft", done: "Incident confirmed as a real threat" },
  { status: "false_positive", label: "False alarm", icon: <ShieldX size={15} />, done: "Incident marked as a false alarm" },
  { status: "resolved", label: "Resolve", icon: <CheckCircle2 size={15} />, tone: "primary", done: "Incident resolved" },
];

const STORY_ICON: Record<string, JSX.Element> = {
  process: <Play size={13} />, exec: <Cpu size={13} />, write: <FileText size={13} />, read: <FileText size={13} />, network: <Globe size={13} />,
};

export default function IncidentDetail() {
  const { id } = useParams();
  const can = useCan(); const toast = useToast(); const nav = useNavigate();
  const { data, error, loading, reload } = useApi<Detail>(`/api/incidents/${id}`);
  const [sel, setSel] = useState<{ id: string; node: VNode } | null>(null);
  const [focus, setFocus] = useState<{ id: string; nonce: number } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [allow, setAllow] = useState<{ alertId?: number | null; preset?: AllowOption[]; subject: string } | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const graphRef = useRef<HTMLDivElement>(null);
  const onSelect = useCallback((nid: string | null, node: VNode | null) => setSel(nid && node ? { id: nid, node } : null), []);
  const focusNode = (nid: string, scroll = false) => {
    setFocus({ id: nid, nonce: Date.now() });
    if (scroll) graphRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  };
  const nodeMap = useMemo(() => new Map((data?.graph.nodes || []).map(n => [n.id, n])), [data]);
  const alertRows = useShowMore(data?.alerts || [], 25, id);

  if (loading && !data) return <div className="page"><PageHeader title="Incident" crumbs={<Crumbs />} /><Loading block /></div>;
  if (error && !data) return <div className="page"><PageHeader title="Incident" crumbs={<Crumbs />} /><ErrorState error={error.status === 404 ? "This incident does not exist or is on an endpoint you do not have access to." : error} onRetry={reload} /></div>;
  const d = data!; const inc = d.incident;

  const setStatus = async (a: typeof ACTIONS[number] | { status: IncidentStatus; done: string }) => {
    setBusy(a.status);
    try { await post(`/api/incidents/${inc.id}/status`, { status: a.status }); toast(a.done); await reload(); }
    catch (e: any) { toast(e.message, "err"); }
    setBusy(null);
  };
  // allowed alerts leave incidents: the incident may now start at a later alert (new id) or be gone
  const afterAllow = async (n: number) => {
    const msg = allowedText(n);
    try { await api(`/api/incidents/${inc.id}`); toast(msg); setSel(null); reload(); return; }
    catch (e) { if (!(e instanceof ApiError && e.status === 404)) { toast(msg); reload(); return; } }
    const rest = await api<{ incidents: IncidentSummary[] }>(`/api/incidents?endpoint_id=${inc.endpoint_id}&status=all&limit=500`).catch(() => null);
    // an incident's id is the id of its first alert, so what remains of this one carries one of its alert ids
    const mine = new Set(d.alerts.map(x => x.id));
    const next = rest?.incidents.find(i => mine.has(i.id));
    if (next) { toast(`${msg} · the incident continues with its remaining alerts`); nav(`/incidents/${next.id}`, { replace: true }); }
    else { toast(`${msg} · no alerts are left in this incident`); nav("/incidents"); }
  };
  const allowNode = (n: GNode) => {
    const subject = n.type === "process" ? n.details?.Program && !n.details.Program.startsWith("(") ? n.details.Program : n.label : n.title || n.label;
    if (n.detection?.alert_id != null) setAllow({ alertId: n.detection.alert_id, subject });
    else if (n.type === "network" && n.details?.Address) setAllow({ preset: addressOptions(n.details.Address), subject: n.details.Address });
  };
  const detections = d.story.filter(s => s.kind === "detection").length;
  const selNode = sel ? nodeMap.get(sel.id) || sel.node : null;

  return (
    <div className="page incident-page">
      <PageHeader crumbs={<Crumbs id={inc.id} />}
        title={<span className="inc-title"><SeverityBadge severity={inc.severity} size="lg" /><span title={inc.title}><PathText text={inc.title} max={48} /></span></span>}
      >
        <div className="inc-bar">
          <div className="inc-meta">
            <Link to={`/endpoints/${inc.endpoint_id}`} className="meta-item subtle-link"><Server size={14} /><span className="meta-ep"><Mid text={inc.endpoint_name} /></span></Link>
            <span className="meta-item" title={fmtRel(inc.first_ns)}><Clock size={14} />{fmtSpan(inc.first_ns, inc.last_ns)}</span>
            <span className="meta-item">{plural(inc.alerts, "alert")} · {plural(inc.processes, "process", "processes")}</span>
            {!inc.behaviours?.length && inc.tactics.map(t => <Chip key={t}>{t}</Chip>)}
          </div>
          <div className="triage">
            <StatusBadge status={inc.status} />
            {can.triage && <>
              {ACTIONS.filter(a => a.status !== inc.status).map(a => (
                <button key={a.status} className={cx("btn", a.tone)} disabled={!!busy} onClick={() => setStatus(a)}>{a.icon}{a.label}</button>
              ))}
              {inc.status !== "open" && <button className="btn ghost" disabled={!!busy} onClick={() => setStatus({ status: "open", done: "Incident reopened" })} title="Set the incident back to open"><RotateCcw size={15} />Reopen</button>}
            </>}
          </div>
        </div>
      </PageHeader>

      {!!inc.behaviours?.length && (
        <div className="beh-strip" aria-label="Recognised attack behaviour">
          {inc.behaviours.map(b => (
            <button key={b.label} type="button" className={cx("beh", b.serious && "serious")} disabled={!b.node}
              onClick={() => b.node && focusNode(b.node, true)} title={b.node ? `${b.text} - click to find it in the graph` : b.text}>
              <span className="beh-h"><span className="beh-dot" />{b.label}<span className="beh-tac">{b.tactic}</span></span>
              <span className="beh-x">{b.text}</span>
            </button>
          ))}
        </div>
      )}

      <TriageCard incidentId={inc.id} assignee={(data as any).assignee || null} assignable={(data as any).assignable || []}
        history={(data as any).history || []} reload={reload} />

      <div className="inc-grid" ref={graphRef}>
        <Card className="story-card" title="What happened" subtitle={`${plural(d.story.length, "step")} · ${plural(detections, "detection")} · click a step to find it in the graph`} pad={false}>
          {d.story.length === 0 ? <Empty title="No activity recorded" text="The detections of this incident have no recorded activity around them." /> : (
            <ol className="story">
              {d.story.map((s, i) => {
                const det = s.detection ? detection(s.detection.type) : null;
                const on = !!sel && !!s.node && (s.node === sel.id || !!sel.node.stack?.members.includes(s.node) || !!sel.node.cluster?.members.includes(s.node));
                return (
                  <li key={i} className={cx(det && "det", on && "on", !s.node && "static")} style={det ? ({ ["--dc" as any]: det.color }) : undefined}
                    onClick={() => s.node && focusNode(s.node)} title={s.text.length > 90 ? s.text : undefined}>
                    <span className="story-n">{i + 1}</span>
                    <div className="story-body">
                      {det && <DetectionTag type={s.detection!.type} />}
                      <div className="story-text">
                        {!det && <span className="story-kind">{STORY_ICON[s.kind] || <ChevronRight size={13} />}</span>}
                        <PathText text={det ? reasonText(s.detection!.type, s.detection!.reason || s.text) : s.text} max={34} />{(s as any).count > 1 && <span className="muted"> ×{(s as any).count}</span>}
                      </div>
                    </div>
                    <span className="story-time" title={fmtDateTime(s.ts_ns, true)}>{fmtTime(s.ts_ns)}</span>
                  </li>
                );
              })}
            </ol>
          )}
        </Card>

        <div className="graph-card card">
          {d.graph.nodes.length === 0 ? <Empty title="No graph for this incident" text="The agent did not record any activity around these detections." /> : (
            <>
              <AttackGraph nodes={d.graph.nodes} edges={d.graph.edges} selected={sel?.id || null} onSelect={onSelect} focus={focus} expanded={expanded} setExpanded={setExpanded} />
              {selNode && <NodePanel node={selNode} vnode={sel!.node} d={d} onClose={() => setSel(null)} onFocus={nid => focusNode(nid)}
                onAllow={can.manage_endpoints ? allowNode : undefined}
                onExpand={() => { setExpanded(x => new Set([...x, sel!.id])); setSel(null); }} />}
            </>
          )}
          {d.graph.truncated && <div className="graph-trunc">The graph was trimmed to its most relevant part.</div>}
        </div>
      </div>

      <Card title="Alerts in this incident" subtitle="Each alert is one detection on one process, file or network peer." pad={false}>
        <div className="table-wrap">
          <table className="table clickable">
            <thead><tr><th style={{ width: 96 }}>Time</th><th style={{ width: 186 }}>Detection</th><th style={{ width: "28%" }}>Entity</th><th>Why it was flagged</th><th style={{ width: 120 }}>Status</th>{can.manage_endpoints && <th style={{ width: 118 }}></th>}</tr></thead>
            <tbody>{alertRows.visible.map(a => {
              const n = nodeMap.get(a.node);
              return (
                <tr key={a.id} onClick={() => focusNode(a.node, true)} className={cx(sel?.id === a.node && "row-on")}>
                  <td title={fmtDateTime(a.ts_ns, true)}>{fmtTime(a.ts_ns, false)}</td>
                  <td><DetectionTag type={a.type} /></td>
                  <td><div className="entity" title={a.title || a.label}><NodeIcon type={n?.type || "process"} /><Mid text={a.label} className="mono entity-name" title={null} /></div>
                    {a.title && a.title !== a.label && (n?.type === "file" ? <div className="muted mono sm flex-min"><Mid text={a.title} /></div>
                      : <div className="muted mono sm ellipsis" title={a.title}>{shortCmd(a.title)}</div>)}</td>
                  <td className="reason"><PathText text={reasonText(a.type, a.reason)} /></td>
                  <td><StatusBadge status={a.status} /></td>
                  {can.manage_endpoints && <td className="row-actions"><button className="btn sm" title="Add this activity to the allow list" onClick={e => { e.stopPropagation(); setAllow({ alertId: a.id, subject: n?.type === "process" && n.details?.Program && !n.details.Program.startsWith("(") ? n.details.Program : a.title || a.label }); }}><ShieldCheck size={14} />Allow…</button></td>}
                </tr>
              );
            })}</tbody>
          </table>
        </div>
        <ShowMore s={alertRows} noun={["alert", "alerts"]} />
      </Card>

      {allow && <AllowAlertDialog alertId={allow.alertId} preset={allow.preset} subject={allow.subject} endpoint={{ id: inc.endpoint_id, name: inc.endpoint_name }}
        onClose={() => setAllow(null)} onDone={afterAllow} />}
    </div>
  );
}

function Crumbs({ id }: { id?: number }) {
  return <><Link to="/incidents"><ArrowLeft size={14} />Incidents</Link>{id != null && <><ChevronRight size={14} className="muted" /><span>Incident {id}</span></>}</>;
}

// edges point along the information flow; phrase them from the selected entity's point of view
const TARGET_ACTS = new Set(["READ", "EXECUTE", "RECVFROM", "RECVMSG", "OPEN", "MMAP"]);
const PASSIVE: Record<string, string> = { READ: "read by", WRITE: "written by", EXECUTE: "executed by", CLONE: "started by", CONNECT: "contacted by",
  SENDTO: "received data from", SENDMSG: "received data from", RECVFROM: "sent data to", RECVMSG: "sent data to", OPEN: "opened by", MMAP: "mapped by" };
function relVerb(e: { source: string; target: string; op: string; label?: string }, me: string) {
  const actor = TARGET_ACTS.has(e.op) ? e.target : e.source;
  return actor === me ? (e.label || e.op.toLowerCase()) : PASSIVE[e.op] || `${e.label || e.op.toLowerCase()} by`;
}

const DETAIL_ORDER = ["Program", "Command line", "Path", "Address", "Port", "Scope", "PID", "User", "Files", "Paths"];
const notRecorded = (v: string) => /^\(?not recorded/i.test(v);
const cap = (v: string) => v.charAt(0).toUpperCase() + v.slice(1);

function NodePanel({ node, vnode, d, onClose, onFocus, onAllow, onExpand }: { node: GNode; vnode: VNode; d: Detail; onClose: () => void; onFocus: (id: string) => void; onAllow?: (n: GNode) => void; onExpand: () => void }) {
  const det = node.alerted && node.detection ? node.detection : null;
  const nm = new Map(d.graph.nodes.map(n => [n.id, n]));
  const ids = new Set(vnode.stack?.members || [node.id]);
  const rel = d.graph.edges.filter(e => ids.has(e.source) || ids.has(e.target)).sort((a, b) => (a.order || 0) - (b.order || 0));
  const isGroup = node.type === "group";
  const details = Object.entries(node.details || {}).filter(([k]) => k !== "Examples" && !(isGroup && k === "Files"))
    .sort(([a], [b]) => (DETAIL_ORDER.indexOf(a) + 99) % 99 - (DETAIL_ORDER.indexOf(b) + 99) % 99);
  // server-side groups carry a sample of their paths in details.Examples; client-side clusters list their members
  const examples = typeof node.details?.Examples === "string" ? node.details.Examples.split(/,\s+/).filter(Boolean) : [];
  const sample: string[] = vnode.cluster ? vnode.cluster.members.map(m => nm.get(m)?.title || m) : ((node as any).sample || examples);
  const fileCount = vnode.cluster ? sample.length : Number(node.details?.Files ?? node.count ?? sample.length);
  const typeName = vnode.stack ? `${vnode.stack.members.length} similar processes` : node.type === "process" ? "Process" : node.type === "file" ? "File" : node.type === "network" ? "Network peer" : "File group";
  const canTrust = onAllow && !det && node.type === "network" && !!node.details?.Address;
  return (
    <aside className="node-panel" aria-label="Entity details">
      <div className="np-head">
        <span className={cx("np-icon", `t-${node.type}`)}><NodeIcon type={node.type} size={16} /></span>
        <div className="np-title"><div className="np-type">{typeName}</div><div className="np-label" title={node.title || node.label}>{node.label}</div></div>
        <button className="icon-btn" onClick={onClose} aria-label="Close details"><X size={16} /></button>
      </div>
      <div className="np-body">
        {det && (
          <div className="np-det" style={{ ["--dc" as any]: detection(det.type).color }}>
            <DetectionTag type={det.type} />
            <div className="np-reason">{reasonText(det.type, det.reason)}</div>
            <div className="np-det-foot">
              {det.alert_id != null && <span className="muted sm">Alert {det.alert_id}</span>}
              {det.alert_id != null && onAllow && <button className="btn sm" onClick={() => onAllow(node)} title="This is normal for us: add it to the allow list"><ShieldCheck size={14} />Allow…</button>}
            </div>
          </div>
        )}
        {canTrust && <div className="np-trust">
          <div className="muted sm">A known service or partner? Trusted addresses do not count as untrusted destinations in data-flow detections.</div>
          <button className="btn sm" onClick={() => onAllow!(node)}><ShieldCheck size={14} />Trust this address</button>
        </div>}
        {(details.length > 0 || node.first_ns) && <dl className="kv">
          {details.map(([k, v]) => {
            const t = String(v); const nr = notRecorded(t);
            return <div key={k}><dt>{k}</dt><dd className={cx(!nr && !["PID", "Scope", "Files"].includes(k) && "mono", k === "Command line" && "cmd", nr && "muted")}>{nr ? "Not recorded by the collector" : k === "Scope" ? cap(t) : t}</dd></div>;
          })}
          {node.first_ns ? <div><dt>First seen</dt><dd>{fmtDateTime(node.first_ns, true)}</dd></div> : null}
        </dl>}
        {isGroup && sample.length === 0 && node.details?.Paths && <div className="note">The collector recorded these {plural(fileCount, "file")} without their paths, so they are grouped into one node.</div>}
        {sample.length > 0 && <div className="np-sec">
          <div className="np-sec-title">{vnode.cluster ? `${sample.length} files` : `Files (${fileCount.toLocaleString()})`}</div>
          <ul className="np-files">{sample.slice(0, 60).map(s => <li key={s} className="mono" title={s}><Mid text={s} title={null} /></li>)}</ul>
          {fileCount > Math.min(sample.length, 60) && <div className="muted sm">{sample.length < fileCount ? `Showing ${Math.min(sample.length, 60)} examples` : `Showing 60 of ${fileCount.toLocaleString()}`}</div>}
          {vnode.cluster && <button className="btn sm" onClick={onExpand}><Layers size={14} />Show each file in the graph</button>}
        </div>}
        {vnode.stack && <div className="np-sec">
          <div className="np-sec-title">{vnode.stack.members.length} processes</div>
          <ul className="np-files">{vnode.stack.members.slice(0, 60).map(m => { const x = nm.get(m); return <li key={m} className="mono" title={x?.title || m}>{x?.details?.PID ? `${x.details.PID} · ` : ""}{x?.title || x?.label || m}</li>; })}</ul>
          {vnode.stack.members.length > 60 && <div className="muted sm">Showing 60 of {vnode.stack.members.length}</div>}
          <button className="btn sm" onClick={onExpand}><Layers size={14} />Show each process in the graph</button>
        </div>}
        {rel.length > 0 && !vnode.cluster && !vnode.stack && <div className="np-sec">
          <div className="np-sec-title">Activity ({rel.length})</div>
          <ul className="np-rel">{rel.slice(0, 40).map(e => {
            const out = ids.has(e.source); const other = nm.get(out ? e.target : e.source);
            if (!other) return null;
            return (
              <li key={e.id} onClick={() => onFocus(other.id)} title={other.title || other.label}>
                <span className="np-op">{relVerb(e, out ? e.source : e.target)}</span>
                <NodeIcon type={other.type} size={13} /><Mid text={other.label} className="mono np-rel-name" title={null} />
                {other.alerted && <span className="np-dot" style={{ background: detection(other.detection?.type).color }} />}
              </li>
            );
          })}</ul>
          {rel.length > 40 && <div className="muted sm">Showing the first 40 of {rel.length}</div>}
        </div>}
      </div>
    </aside>
  );
}
