import { useCallback, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, CheckCircle2, ChevronRight, Clock, Cpu, FileText, Globe, Layers, Play, RotateCcw, Search, Server, ShieldCheck, ShieldX, Siren, X } from "lucide-react";
import { GNode, IncidentDetail as Detail, IncidentStatus, post, useApi, useCan } from "../api";
import { detection, fmtDateTime, fmtRel, fmtSpan, fmtTime, plural, reasonText } from "../format";
import { AttackGraph } from "../graph/AttackGraph";
import type { VNode } from "../graph/model";
import { Card, Chip, Confirm, cx, DetectionTag, Empty, ErrorState, Loading, NodeIcon, PageHeader, SeverityBadge, StatusBadge, useToast } from "../ui";

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
  const can = useCan(); const toast = useToast();
  const { data, error, loading, reload } = useApi<Detail>(`/api/incidents/${id}`);
  const [sel, setSel] = useState<{ id: string; node: VNode } | null>(null);
  const [focus, setFocus] = useState<{ id: string; nonce: number } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [approve, setApprove] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const graphRef = useRef<HTMLDivElement>(null);
  const onSelect = useCallback((nid: string | null, node: VNode | null) => setSel(nid && node ? { id: nid, node } : null), []);
  const focusNode = (nid: string, scroll = false) => {
    setFocus({ id: nid, nonce: Date.now() });
    if (scroll) graphRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  };
  const nodeMap = useMemo(() => new Map((data?.graph.nodes || []).map(n => [n.id, n])), [data]);

  if (loading && !data) return <div className="page"><PageHeader title="Incident" crumbs={<Crumbs />} /><Loading block /></div>;
  if (error && !data) return <div className="page"><PageHeader title="Incident" crumbs={<Crumbs />} /><ErrorState error={error.status === 404 ? "This incident does not exist or is on an endpoint you do not have access to." : error} onRetry={reload} /></div>;
  const d = data!; const inc = d.incident;

  const setStatus = async (a: typeof ACTIONS[number] | { status: IncidentStatus; done: string }) => {
    setBusy(a.status);
    try { await post(`/api/incidents/${inc.id}/status`, { status: a.status }); toast(a.done); await reload(); }
    catch (e: any) { toast(e.message, "err"); }
    setBusy(null);
  };
  const detections = d.story.filter(s => s.kind === "detection").length;
  const selNode = sel ? nodeMap.get(sel.id) || sel.node : null;

  return (
    <div className="page incident-page">
      <PageHeader crumbs={<Crumbs id={inc.id} />}
        title={<span className="inc-title"><SeverityBadge severity={inc.severity} size="lg" /><span>{inc.title}</span></span>}
      >
        <div className="inc-bar">
          <div className="inc-meta">
            <Link to={`/endpoints/${inc.endpoint_id}`} className="meta-item subtle-link"><Server size={14} />{inc.endpoint_name}</Link>
            <span className="meta-item" title={fmtRel(inc.first_ns)}><Clock size={14} />{fmtSpan(inc.first_ns, inc.last_ns)}</span>
            <span className="meta-item">{plural(inc.alerts, "alert")} · {plural(inc.processes, "process", "processes")}</span>
            {inc.tactics.map(t => <Chip key={t}>{t}</Chip>)}
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

      <div className="inc-grid" ref={graphRef}>
        <Card className="story-card" title="What happened" subtitle={`${plural(d.story.length, "step")} · ${plural(detections, "detection")} · click a step to find it in the graph`} pad={false}>
          {d.story.length === 0 ? <Empty title="No activity recorded" text="The detections of this incident have no recorded activity around them." /> : (
            <ol className="story">
              {d.story.map((s, i) => {
                const det = s.detection ? detection(s.detection.type) : null;
                const on = !!sel && !!s.node && (s.node === sel.id || !!sel.node.stack?.members.includes(s.node) || !!sel.node.cluster?.members.includes(s.node));
                return (
                  <li key={i} className={cx(det && "det", on && "on", !s.node && "static")} style={det ? ({ ["--dc" as any]: det.color }) : undefined}
                    onClick={() => s.node && focusNode(s.node)}>
                    <span className="story-n">{i + 1}</span>
                    <div className="story-body">
                      {det && <DetectionTag type={s.detection!.type} />}
                      <div className="story-text">
                        {!det && <span className="story-kind">{STORY_ICON[s.kind] || <ChevronRight size={13} />}</span>}
                        {det ? reasonText(s.detection!.type, s.detection!.reason || s.text) : s.text}{(s as any).count > 1 && <span className="muted"> ×{(s as any).count}</span>}
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
                onApprove={can.manage_endpoints ? setApprove : undefined}
                onExpand={() => { setExpanded(x => new Set([...x, sel!.id])); setSel(null); }} />}
            </>
          )}
          {d.graph.truncated && <div className="graph-trunc">The graph was trimmed to its most relevant part.</div>}
        </div>
      </div>

      <Card title="Alerts in this incident" subtitle="Each alert is one detection on one process, file or network peer." pad={false}>
        <div className="table-wrap">
          <table className="table clickable">
            <thead><tr><th style={{ width: 120 }}>Time</th><th style={{ width: 190 }}>Detection</th><th style={{ width: "28%" }}>Entity</th><th>Why it was flagged</th><th style={{ width: 130 }}>Status</th></tr></thead>
            <tbody>{d.alerts.map(a => {
              const n = nodeMap.get(a.node);
              return (
                <tr key={a.id} onClick={() => focusNode(a.node, true)} className={cx(sel?.id === a.node && "row-on")}>
                  <td title={fmtDateTime(a.ts_ns, true)}>{fmtTime(a.ts_ns, false)}</td>
                  <td><DetectionTag type={a.type} /></td>
                  <td><div className="entity" title={a.title || a.label}><NodeIcon type={n?.type || "process"} /><span className="mono ellipsis">{a.label}</span></div>
                    {a.title && a.title !== a.label && <div className="muted mono sm ellipsis" title={a.title}>{a.title}</div>}</td>
                  <td className="reason">{reasonText(a.type, a.reason)}</td>
                  <td><StatusBadge status={a.status} /></td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      </Card>

      {approve && <Confirm title="Approve this program?" confirmLabel="Approve program"
        text={<>
          <p>PDP will treat <code className="code-inline">{approve}</code> as a normal program on <b>{inc.endpoint_name}</b> and stop raising “New program” alerts for it. Its open alerts are marked as false alarms.</p>
          <p className="muted">Only approve programs you recognise. You can revoke the approval in the endpoint's settings.</p>
        </>}
        onClose={() => setApprove(null)}
        onConfirm={async () => { await post(`/api/endpoints/${inc.endpoint_id}/approved-executables`, { executables: [approve], approve: true }); toast(`${approve} approved on ${inc.endpoint_name}`); reload(); }} />}
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

const DETAIL_ORDER =["Program", "Command line", "Path", "Address", "Port", "PID", "User"];

function NodePanel({ node, vnode, d, onClose, onFocus, onApprove, onExpand }: { node: GNode; vnode: VNode; d: Detail; onClose: () => void; onFocus: (id: string) => void; onApprove?: (prog: string) => void; onExpand: () => void }) {
  const det = node.alerted && node.detection ? node.detection : null;
  const nm = new Map(d.graph.nodes.map(n => [n.id, n]));
  const ids = new Set(vnode.stack?.members || [node.id]);
  const rel = d.graph.edges.filter(e => ids.has(e.source) || ids.has(e.target)).sort((a, b) => (a.order || 0) - (b.order || 0));
  const details = Object.entries(node.details || {}).filter(([k]) => k !== "Examples" && k !== "Files")
    .sort(([a], [b]) => (DETAIL_ORDER.indexOf(a) + 99) % 99 - (DETAIL_ORDER.indexOf(b) + 99) % 99);
  const sample: string[] = vnode.cluster ? vnode.cluster.members.map(m => nm.get(m)?.title || m) : ((node as any).sample || []);
  const program = node.type === "process" ? node.details?.Program : null;
  const typeName = vnode.stack ? `${vnode.stack.members.length} similar processes` : node.type === "process" ? "Process" : node.type === "file" ? "File" : node.type === "network" ? "Network peer" : "File group";
  return (
    <aside className="node-panel" aria-label="Entity details">
      <div className="np-head">
        <span className={cx("np-icon", `t-${node.type}`)}><NodeIcon type={node.type} size={16} /></span>
        <div className="np-title"><div className="np-type">{typeName}</div><div className="np-label" title={node.label}>{node.label}</div></div>
        <button className="icon-btn" onClick={onClose} aria-label="Close details"><X size={16} /></button>
      </div>
      <div className="np-body">
        {det && (
          <div className="np-det" style={{ ["--dc" as any]: detection(det.type).color }}>
            <DetectionTag type={det.type} />
            <div className="np-reason">{reasonText(det.type, det.reason)}</div>
            {det.alert_id != null && <div className="muted sm">Alert {det.alert_id}</div>}
            {det.type === "novelty" && program && onApprove && (
              <button className="btn sm" onClick={() => onApprove(program)}><ShieldCheck size={14} />Approve program</button>
            )}
          </div>
        )}
        {details.length > 0 && <dl className="kv">
          {details.map(([k, v]) => <div key={k}><dt>{k}</dt><dd className={cx(k !== "PID" && "mono", k === "Command line" && "cmd")}>{String(v)}</dd></div>)}
          {node.first_ns ? <div><dt>First seen</dt><dd>{fmtDateTime(node.first_ns, true)}</dd></div> : null}
        </dl>}
        {details.length === 0 && node.first_ns ? <dl className="kv"><div><dt>First seen</dt><dd>{fmtDateTime(node.first_ns, true)}</dd></div></dl> : null}
        {sample.length > 0 && <div className="np-sec">
          <div className="np-sec-title">{vnode.cluster ? `${sample.length} files` : `Files (${node.count ?? sample.length})`}</div>
          <ul className="np-files">{sample.slice(0, 60).map(s => <li key={s} className="mono" title={s}>{s}</li>)}</ul>
          {vnode.cluster && <button className="btn sm" onClick={onExpand}><Layers size={14} />Show each file in the graph</button>}
        </div>}
        {vnode.stack && <div className="np-sec">
          <div className="np-sec-title">{vnode.stack.members.length} processes</div>
          <ul className="np-files">{vnode.stack.members.slice(0, 60).map(m => { const x = nm.get(m); return <li key={m} className="mono" title={x?.title || m}>{x?.details?.PID ? `${x.details.PID} · ` : ""}{x?.title || x?.label || m}</li>; })}</ul>
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
                <NodeIcon type={other.type} size={13} /><span className="mono ellipsis">{other.label}</span>
                {other.alerted && <span className="np-dot" style={{ background: detection(other.detection?.type).color }} />}
              </li>
            );
          })}</ul>
        </div>}
      </div>
    </aside>
  );
}
