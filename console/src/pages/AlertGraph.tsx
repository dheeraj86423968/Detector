import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, fmtTs, GraphEdge, GraphNode, LAYER_NAME, useMe } from "../api";
import { ProvenanceGraph, TYPE_COLOR, TYPE_NAME } from "../graph";

export default function AlertGraph() {
  const { id } = useParams();
  const [data, setData] = useState<{ alert: any; nodes: GraphNode[]; edges: GraphEdge[] } | null>(null);
  const [sel, setSel] = useState<GraphNode | null>(null);
  const [cut, setCut] = useState(0);
  const me = useMe(); const [msg, setMsg] = useState("");

  const load = (expand?: string) => api(`/api/alerts/${id}/graph${expand ? `?expand=${encodeURIComponent(expand)}` : ""}`).then(r => {
    setData(d => expand && d ? { alert: r.alert, nodes: mergeNodes(d.nodes, r.nodes), edges: mergeEdges(d.edges, r.edges) } : r);
    const ts = r.edges.map((e: GraphEdge) => e.ts_ns); if (ts.length) setCut(Math.max(...ts));
  });
  useEffect(() => { load(); setSel(null); }, [id]);

  const minT = useMemo(() => (data?.edges.length ? Math.min(...data.edges.map(e => e.ts_ns)) : 0), [data]);
  const maxT = useMemo(() => (data?.edges.length ? Math.max(...data.edges.map(e => e.ts_ns)) : 0), [data]);
  if (!data) return <p className="muted">Loading…</p>;
  const a = data.alert;
  return (
    <div>
      <div className="row between">
        <h1 style={{ margin: 0 }}>Alert · {a?.label?.replace(/^(subject|file|netflow) /, "").slice(0, 70)}</h1>
        {a && <Link className="ghost btn" to={`/incident/${a.endpoint_id}?focus_ns=${a.window_start_ns}`}>See full attack graph →</Link>}
      </div>
      {a?.reason && <p><span className={`pill layer-${a.layer || "learned"}`}>{LAYER_NAME[a.layer || "learned"]}</span> {a.reason}</p>}
      {(a?.reasons || []).length > 1 && <ul className="sm">{a.reasons.slice(1, 6).map((r: any, i: number) => <li key={i} className="muted">{LAYER_NAME[r.layer] || r.layer}: {r.detail}</li>)}</ul>}
      {a?.layer === "novelty" && me?.role === "admin" && (() => {
        const prog = (a.reasons || []).find((r: any) => r.rule === "novel_executable")?.key;
        return prog ? <p><button className="ghost" onClick={async () => {
          try { await api(`/api/endpoints/${a.endpoint_id}/approved-executables`, { method: "POST", body: JSON.stringify({ executables: [prog], approve: true }) }); setMsg(`${prog} approved: no further novelty alerts for it on this endpoint (open ones marked false positive)`); }
          catch (e: any) { setMsg(e.message); } }}>Approve program {prog}</button> <span className="muted sm">{msg}</span></p> : null; })()}
      <p className="muted sm">learned score: fused {a?.fused?.toFixed(2)}× · detector-1 {a?.r1?.toFixed(2)}× · detector-2 {a?.r2?.toFixed(2)}× · window {a ? fmtTs(a.window_start_ns) : ""}</p>
      <div className="card tbar">
        <span className="muted sm">Window-local neighbourhood. Double-click a node to expand it.</span>
        <div className="row"><span className="muted sm">{fmtTs(minT).slice(11, 19)}</span>
          <input type="range" min={minT} max={maxT} value={cut} onChange={e => setCut(+e.target.value)} style={{ width: 260 }} />
          <span className="mono sm">{cut ? fmtTs(cut).slice(11, 19) : ""}</span></div>
      </div>
      <div className="attack-grid">
        <div style={{ position: "relative" }}>
          <ProvenanceGraph nodes={data.nodes} edges={data.edges} cut={cut} height={560} onSelect={setSel} onExpand={load} />
          <div className="legend"><span style={{ background: "#ff5c5c" }} />flagged<span style={{ background: TYPE_COLOR.subject }} />process<span style={{ background: TYPE_COLOR.file }} />file<span style={{ background: TYPE_COLOR.netflow }} />socket</div>
        </div>
        <div className="card detail">
          <h2>Entity detail</h2>
          {sel ? <>
            <div className="pill">{TYPE_NAME[sel.ntype] || sel.ntype}</div>
            <p className="mono break">{sel.label}</p>
            {sel.flagged && <p className="err sm">flagged ({LAYER_NAME[sel.flagged.layer || "learned"]}) · fused {sel.flagged.fused.toFixed(2)}×</p>}
            {sel.flagged?.reason && <p className="sm">{sel.flagged.reason}</p>}
          </> : <p className="muted">Click an entity.</p>}
          <p className="sm muted">{data.nodes.length} entities · {data.edges.length} events</p>
        </div>
      </div>
    </div>
  );
}

function mergeNodes(a: GraphNode[], b: GraphNode[]) { const m = new Map(a.map(n => [n.uuid, n])); b.forEach(n => m.set(n.uuid, n)); return [...m.values()]; }
function mergeEdges(a: GraphEdge[], b: GraphEdge[]) { const k = (e: GraphEdge) => `${e.src}|${e.dst}|${e.op}|${e.ts_ns}`; const m = new Map(a.map(e => [k(e), e])); b.forEach(e => m.set(k(e), e)); return [...m.values()]; }
