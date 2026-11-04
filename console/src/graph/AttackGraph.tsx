import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  BaseEdge, Controls, Edge, MiniMap, EdgeLabelRenderer, EdgeProps, getBezierPath, Handle, MarkerType, Node, NodeProps, NodeToolbar, Panel, Position,
  ReactFlow, ReactFlowProvider, useReactFlow, useStore,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Maximize2, Minimize2, Route, Waypoints } from "lucide-react";
import type { GEdge, GNode } from "../api";
import { detection, DETECTION, midTrunc, reasonText, shortCmd } from "../format";
import { cx, NodeIcon, Segmented } from "../ui";
import { attackPath, clusterLeaves, layout, stackSiblings, VNode } from "./model";

export type Mode = "path" | "full";
const MIN_READABLE = 0.55;
const PANEL_W = 360;   // width of the details panel that overlays the canvas (styles.css .node-panel)
type NodeData = { n: VNode; dim: boolean; hl: boolean; sel: boolean; hover: boolean };
type EdgeData = { e: GEdge & { step: number }; showLabel: boolean; hl: boolean; dim: boolean; offset: number; path: boolean };

// node boxes are fixed-size: ~16 characters of name and ~22 of detail line fit; long names keep their end
const LABEL_MAX = 17, SUB_MAX = 24;
const known = (v?: string | null) => (v && !/^\(?not recorded/i.test(v) ? v : "");
const nodeLabel = (n: VNode) => {
  if (n.type === "network" && n.details?.Address) return n.details.Address;
  if (n.type === "group" && !n.cluster) {
    const m = /^(\d[\d,]*) (?:system )?files?\b/.exec(n.label);
    if (m) return `${m[1]} ${m[1] === "1" ? "file" : "files"}`;
  }
  return n.label;
};
const sublabel = (n: VNode) => {
  if (n.stack) return n.title || "";
  if (n.type === "process") {
    const cmd = (n.details?.["Command line"] || n.title || "").split("\n")[0];
    const prog = known(n.details?.Program);
    // a bare command line that only repeats the name says nothing: show where the program lives instead
    return cmd && cmd !== n.label ? shortCmd(cmd, 18) : prog ? midTrunc(prog, SUB_MAX) : cmd;
  }
  if (n.type === "file") { const p = n.details?.Path || n.title || ""; const i = p.lastIndexOf("/"); return midTrunc(i > 0 ? p.slice(0, i) : p, SUB_MAX); }
  if (n.type === "network") {
    const port = n.details?.Port, scope = n.details?.Scope === "external" ? "public" : n.details?.Scope === "local network" ? "local" : n.details?.Scope;
    const full = [port ? `port ${port}` : "", scope || ""].filter(Boolean).join(" · ");
    return full.length <= 18 ? full || "Network peer" : port ? `port ${port}` : full;
  }
  if (n.cluster) return n.title || "";
  if (n.details?.Paths) return "paths not recorded";
  return /system file/.test(n.label) ? "libraries and system files" : "grouped files";
};
const TYPE_NAME: Record<string, string> = { process: "Process", file: "File", network: "Network", group: "File group" };

const GraphNode = memo(function GraphNode({ data }: NodeProps<Node<NodeData>>) {
  const { n, dim, hl, sel, hover } = data;
  const d = n.alerted && n.detection ? detection(n.detection.type) : null;
  return (
    <div className={cx("gnode", `t-${n.type}`, d && "alerted", dim && "dim", hl && "hl", sel && "sel")} style={d ? ({ ["--dc" as any]: d.color }) : undefined}>
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <span className="gicon"><NodeIcon type={n.type} size={15} /></span>
      <span className="gtext">
        <span className="glabel">{midTrunc(nodeLabel(n), LABEL_MAX)}</span>
        <span className="gsub">{sublabel(n)}</span>
      </span>
      {d && <span className="gbadge">{d.short}</span>}
      {n.stack && <span className="gstack">×{n.stack.members.length}</span>}
      <Handle type="source" position={Position.Right} isConnectable={false} />
      <NodeToolbar isVisible={hover && !sel} position={Position.Top} offset={8}>
        <div className="gtip">
          <div className="gtip-type">{TYPE_NAME[n.type]}{d ? <> · <b style={{ color: d.color }}>{d.label}</b></> : null}</div>
          <div className="gtip-title">{n.title || n.label}</div>
          {d && <div className="gtip-reason">{reasonText(n.detection!.type, n.detection!.reason)}</div>}
          <div className="gtip-hint">Click for details</div>
        </div>
      </NodeToolbar>
    </div>
  );
});

const zoomSel = (s: { transform: [number, number, number] }) => s.transform[2];
const GraphEdgeView = memo(function GraphEdgeView({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, markerEnd }: EdgeProps<Edge<EdgeData>>) {
  const zoom = useStore(zoomSel);
  const [path, lx, ly] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const d = data!;
  const show = d.hl || (d.showLabel && zoom > 0.3);
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} className={cx("gedge", d.hl && "hl", d.dim && "dim", d.path && "onpath")} />
      {show && (
        <EdgeLabelRenderer>
          {zoom < 0.7 && !d.hl ? (
            <div className={cx("elabel far", d.dim && "dim")} style={{ transform: `translate(-50%, -50%) translate(${lx}px, ${ly + d.offset}px) scale(${Math.min(2, 0.8 / zoom)})` }}>
              <span className="estep">{d.e.step}</span>
            </div>
          ) : (
            <div className={cx("elabel", d.hl && "hl", d.dim && "dim")} style={{ transform: `translate(-50%, -50%) translate(${lx}px, ${ly + d.offset}px)${zoom < 0.7 ? ` scale(${Math.min(2, 0.8 / zoom)})` : ""}` }}>
              <span className="estep">{d.e.step}</span>{d.e.label || d.e.op.toLowerCase()}{(d.e.count || 1) > 1 && <span className="ecount">×{d.e.count}</span>}
            </div>
          )}
        </EdgeLabelRenderer>
      )}
    </>
  );
});

const nodeTypes = { pdp: GraphNode };
const edgeTypes = { pdp: GraphEdgeView };

type Props = {
  nodes: GNode[]; edges: GEdge[];
  expanded: Set<string>; setExpanded: (f: (s: Set<string>) => Set<string>) => void;
  selected: string | null; onSelect: (id: string | null, node: VNode | null) => void;
  focus?: { id: string; nonce: number } | null;
};

export function AttackGraph(p: Props) {
  return <ReactFlowProvider><Inner {...p} /></ReactFlowProvider>;
}

function Inner({ nodes, edges, selected, onSelect, focus, expanded, setExpanded }: Props) {
  const rf = useReactFlow();
  const zoom = useStore(zoomSel);
  const path = useMemo(() => attackPath(nodes, edges), [nodes, edges]);
  const pathUseful = path.size > 0 && path.size < nodes.length;
  const [mode, setMode] = useState<Mode>(() => (pathUseful && nodes.length > 30 ? "path" : "full"));
  const [extra, setExtra] = useState<Set<string>>(new Set());   // nodes revealed from the story while in path mode
  const [hover, setHover] = useState<string | null>(null);
  const [full, setFull] = useState(false);
  const shell = useRef<HTMLDivElement>(null);

  const view = useMemo(() => {
    let ns: GNode[] = nodes, es: GEdge[] = edges;
    if (mode === "path") { const keep = new Set([...path, ...extra]); ns = nodes.filter(n => keep.has(n.id)); es = edges.filter(e => keep.has(e.source) && keep.has(e.target)); }
    const st = stackSiblings(ns, es, expanded);
    const c = clusterLeaves(st.nodes, st.edges, expanded);
    return { ...layout(c.nodes, c.edges), alias: st.alias };
  }, [nodes, edges, mode, path, expanded, extra]);

  const byId = useMemo(() => new Map(view.nodes.map(n => [n.id, n])), [view]);
  const focusId = hover || selected;
  const neigh = useMemo(() => {
    if (!focusId) return null;
    const s = new Set([focusId]);
    for (const e of view.edges) { if (e.source === focusId) s.add(e.target); if (e.target === focusId) s.add(e.source); }
    return s;
  }, [focusId, view]);

  const rfNodes: Node<NodeData>[] = useMemo(() => view.nodes.map(n => ({
    id: n.id, type: "pdp", position: { x: n.x, y: n.y }, width: n.w, height: n.h, draggable: true, selectable: true,
    data: { n, dim: !!hover && !neigh?.has(n.id), hl: !!neigh?.has(n.id) && n.id !== focusId, sel: n.id === selected, hover: n.id === hover },
  })), [view, neigh, hover, selected, focusId]);

  const rfEdges: Edge<EdgeData>[] = useMemo(() => {
    const pairCount = new Map<string, number>();
    const showAll = view.edges.length <= 70;
    return view.edges.map(e => {
      const pk = [e.source, e.target].sort().join("|"); const k = pairCount.get(pk) || 0; pairCount.set(pk, k + 1);
      const touches = !!focusId && (e.source === focusId || e.target === focusId);
      const onPath = path.has(e.source) && path.has(e.target);
      const s = byId.get(e.source), t = byId.get(e.target);
      const color = touches ? "var(--accent)" : onPath && mode === "full" ? "#7d8798" : "#a9b1be";
      return {
        id: e.id, source: e.source, target: e.target, type: "pdp",
        markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color },
        data: { e, showLabel: showAll || onPath || !!(s?.alerted || t?.alerted), hl: touches, dim: !!hover && !touches, offset: k * 20, path: onPath && mode === "full" },
      };
    });
  }, [view, focusId, hover, path, mode, byId]);

  // fit when the drawn graph changes
  // frame the drawn graph: fit it when that keeps names legible, otherwise start at the beginning of the attack
  const canvas = useRef<HTMLDivElement>(null);
  const [cropped, setCropped] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => {
      const el = canvas.current; if (!el || !view.nodes.length) return;
      const W = el.clientWidth, H = el.clientHeight;
      const minX = Math.min(...view.nodes.map(n => n.x)), maxX = Math.max(...view.nodes.map(n => n.x + n.w));
      const minY = Math.min(...view.nodes.map(n => n.y)), maxY = Math.max(...view.nodes.map(n => n.y + n.h));
      const fit = Math.min(W / (maxX - minX + 80), H / (maxY - minY + 80));
      if (fit >= MIN_READABLE) { setCropped(false); rf.fitView({ padding: 0.1, duration: 250, maxZoom: 1.1 }); return; }
      setCropped(true);
      const z = MIN_READABLE;
      const first = [...view.nodes].filter(n => n.alerted).sort((a, b) => (a.first_ns || 0) - (b.first_ns || 0))[0];
      const cy = first ? first.y + first.h / 2 : (minY + maxY) / 2;
      const y = Math.min(40 - minY * z, Math.max(H - 40 - maxY * z, H / 2 - cy * z));
      rf.setViewport({ x: 40 - minX * z, y, zoom: z }, { duration: 250 });
    }, 40);
    return () => clearTimeout(t);
  }, [view, full, rf]);

  // centre on a node requested from outside (story entry, alert row)
  const handled = useRef(-1);
  useEffect(() => {
    if (!focus || handled.current === focus.nonce) return;
    const id = focus.id;
    if (!nodes.some(n => n.id === id)) return;
    if (mode === "path" && !path.has(id) && !extra.has(id)) { setExtra(x => new Set([...x, id])); return; }
    const inCluster = view.nodes.find(n => n.cluster?.members.includes(id));
    if (inCluster) { setExpanded(x => new Set([...x, inCluster.id])); return; }
    const n = byId.get(id) || byId.get(view.alias.get(id) || "");
    handled.current = focus.nonce;
    if (n) {
      onSelect(n.id, n);
      // centre in the part of the canvas the details panel leaves visible
      const t = setTimeout(() => { const z = Math.max(rf.getZoom(), 0.9); rf.setCenter(n.x + n.w / 2 + PANEL_W / 2 / z, n.y + n.h / 2, { zoom: z, duration: 400 }); }, 80);
      return () => clearTimeout(t);
    }
  }, [focus, view]); // eslint-disable-line react-hooks/exhaustive-deps

  const onNodeClick = useCallback((_: unknown, nd: Node<NodeData>) => {
    onSelect(nd.id, nd.data.n);
    // keep the clicked node clear of the details panel
    const el = canvas.current; if (!el) return;
    const { x, y, zoom: z } = rf.getViewport(); const v = nd.data.n as VNode & { x: number; w: number };
    const right = (v.x + v.w) * z + x, limit = el.clientWidth - PANEL_W - 24;
    if (right > limit) rf.setViewport({ x: x - (right - limit), y, zoom: z }, { duration: 300 });
  }, [onSelect, rf]);
  const types = useMemo(() => [...new Set(nodes.filter(n => n.alerted && n.detection).map(n => n.detection!.type))], [nodes]);
  const hiddenCount = nodes.length - (mode === "path" ? new Set([...path, ...extra]).size : nodes.length);
  const toggleFull = () => setFull(f => !f);
  useEffect(() => {
    if (!full) return;
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") setFull(false); };
    window.addEventListener("keydown", k); return () => window.removeEventListener("keydown", k);
  }, [full]);

  return (
    <div className={cx("graph-shell", full && "fullscreen")} ref={shell}>
      <div className="graph-toolbar">
        <Segmented value={mode} onChange={m => { setMode(m); setExtra(new Set()); }} size="sm" options={[
          { id: "path", label: <><Route size={14} />Attack path</>, title: "Alerted entities and the activity that connects them" },
          { id: "full", label: <><Waypoints size={14} />Everything</>, title: "Every entity recorded around the incident" },
        ]} />
        <span className="graph-count">{mode === "path" && hiddenCount > 0 ? `${view.nodes.length} of ${nodes.length} entities · ${hiddenCount} unrelated hidden` : `${nodes.length} entities · ${edges.length} relations`}</span>
        <span className="grow" />
        <span className="graph-hint">Numbers show the order things happened · hover to trace, click for details</span>
        <button className="icon-btn" onClick={toggleFull} title={full ? "Exit full screen (Esc)" : "Full screen"}>{full ? <Minimize2 size={16} /> : <Maximize2 size={16} />}</button>
      </div>
      <div className={cx("graph-canvas", zoom < 0.7 && "far")} style={{ ["--z" as any]: zoom }} ref={canvas}>
        <ReactFlow nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
          onNodeClick={onNodeClick} onPaneClick={() => onSelect(null, null)}
          onNodeMouseEnter={(_, n) => setHover(n.id)} onNodeMouseLeave={() => setHover(null)}
          nodesConnectable={false} edgesFocusable={false} minZoom={0.08} maxZoom={2} defaultViewport={{ x: 0, y: 0, zoom: 0.6 }}
          proOptions={{ hideAttribution: false }} onlyRenderVisibleElements={view.nodes.length > 120}>
          <Controls showInteractive={false} position="bottom-right" fitViewOptions={{ padding: 0.1, maxZoom: 1.1, duration: 250 }} />
          {cropped && <MiniMap position="top-right" pannable zoomable ariaLabel="Overview of the whole graph" nodeStrokeWidth={2}
            nodeColor={n => { const v = (n.data as NodeData).n; return v.alerted && v.detection ? detection(v.detection.type).color : "#d0d5dd"; }}
            maskColor="rgba(246, 247, 249, .7)" style={{ width: 168, height: 100 }} />}
          <Panel position="bottom-left">
            <div className="legend">
              <div className="legend-row"><span className="lg-node"><NodeIcon type="process" size={12} />Process</span><span className="lg-node"><NodeIcon type="file" size={12} />File</span>
                <span className="lg-node"><NodeIcon type="network" size={12} />Network</span><span className="lg-node"><NodeIcon type="group" size={12} />Grouped files</span></div>
              {types.length > 0 && <div className="legend-row">{types.map(t => <span key={t} className="lg-det"><span style={{ background: DETECTION[t]?.color }} />{DETECTION[t]?.label}</span>)}</div>}
            </div>
          </Panel>
        </ReactFlow>
      </div>
    </div>
  );
}
