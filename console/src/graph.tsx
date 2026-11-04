import { useEffect, useRef } from "react";
import Graph from "graphology";
import forceAtlas2 from "graphology-layout-forceatlas2";
import Sigma from "sigma";
import { GraphEdge, GraphNode } from "./api";

export const TYPE_COLOR: Record<string, string> = { subject: "#4cc2ff", file: "#9aa7b8", netflow: "#c084fc" };
export const TYPE_NAME: Record<string, string> = { subject: "process", file: "file", netflow: "socket" };
const FLAG = "#ff5c5c";
const short = (l: string) => {
  const r = l.replace(/^(subject|file|netflow) /, "").trim();
  const toks = r.split(/\s+/).filter(t => t && t !== "None");   // CADETS has many null exe names; show the first real token
  const t = toks[0] || r || l;
  return (t.split("/").filter(Boolean).slice(-1)[0] || t).slice(0, 28);
};

type Props = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  cut?: number;                       // only show edges at/below this ts
  height?: number;
  onSelect?: (n: GraphNode | null) => void;
  onExpand?: (uuid: string) => void;
};

export function ProvenanceGraph({ nodes, edges, cut, height = 640, onSelect, onExpand }: Props) {
  const box = useRef<HTMLDivElement>(null);
  const state = useRef<{ cut: number; hover: string | null; neigh: Set<string> }>({ cut: cut ?? Infinity, hover: null, neigh: new Set() });
  const sigmaRef = useRef<Sigma | null>(null);

  // build graph + sigma when the node/edge set changes
  useEffect(() => {
    if (!box.current) return;
    const g = new Graph({ multi: true, type: "directed" });
    const maxF = Math.max(1, ...nodes.map(n => n.flagged?.fused || 0));
    nodes.forEach(n => {
      const f = n.flagged?.fused || 0;
      g.addNode(n.uuid, {
        label: short(n.label), x: Math.random(), y: Math.random(),
        size: n.flagged ? 7 + 9 * Math.min(1, f / maxF) : 4,
        color: n.flagged ? FLAG : TYPE_COLOR[n.ntype] || "#888",
        ntype: n.ntype, flagged: !!n.flagged, full: n.label,
      });
    });
    edges.forEach((e, i) => {
      if (g.hasNode(e.src) && g.hasNode(e.dst))
        g.addEdgeWithKey(`e${i}`, e.src, e.dst, { label: e.op, op: e.op, ts: e.ts_ns, size: 1.5 + Math.min(4, (e.loss || 0) / 3),
          color: (e.loss || 0) > 5 ? "#ffb454" : "#2f3e52", type: "arrow" });
    });
    forceAtlas2.assign(g, { iterations: 300, settings: { ...forceAtlas2.inferSettings(g), gravity: 1.2, scalingRatio: 12, barnesHutOptimize: true } });
    const s = new Sigma(g, box.current, {
      renderEdgeLabels: true, defaultEdgeType: "arrow", labelColor: { color: "#dfe7ef" }, edgeLabelColor: { color: "#7f8c9b" },
      labelSize: 12, labelRenderedSizeThreshold: 6, labelDensity: 0.7, zIndex: true,
    });
    sigmaRef.current = s;
    const st = state.current;
    s.setSetting("nodeReducer", (node, data) => {
      const d: any = { ...data };
      if (st.hover && node !== st.hover && !st.neigh.has(node)) { d.color = "#2a3340"; d.label = ""; }
      return d;
    });
    s.setSetting("edgeReducer", (edge, data) => {
      const d: any = { ...data };
      if (data.ts > st.cut) { d.hidden = true; return d; }
      const [a, b] = g.extremities(edge);
      if (st.hover && a !== st.hover && b !== st.hover) { d.color = "#1c2530"; d.label = ""; }
      return d;
    });
    const refresh = () => s.refresh({ skipIndexation: true });
    s.on("enterNode", ({ node }) => { st.hover = node; st.neigh = new Set(g.neighbors(node)); refresh(); });
    s.on("leaveNode", () => { st.hover = null; st.neigh = new Set(); refresh(); });
    s.on("clickNode", ({ node }) => onSelect?.(nodes.find(n => n.uuid === node) || null));
    s.on("doubleClickNode", ({ node }) => onExpand?.(node));
    s.on("clickStage", () => onSelect?.(null));
    return () => { s.kill(); sigmaRef.current = null; };
  }, [nodes, edges]);

  // time scrub without rebuilding the layout
  useEffect(() => {
    state.current.cut = cut ?? Infinity;
    sigmaRef.current?.refresh({ skipIndexation: true });
  }, [cut]);

  return <div className="graph" ref={box} style={{ height }} />;
}
