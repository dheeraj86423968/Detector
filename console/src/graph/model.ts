import dagre from "@dagrejs/dagre";
import type { GEdge, GNode } from "../api";

/** A node as drawn: an incident graph node, or a client-side cluster of sibling leaf files. */
export type VNode = GNode & { cluster?: { parent: string; op: string; members: string[] }; stack?: { members: string[] } };
export type VEdge = GEdge & { step: number };
export type View = { nodes: (VNode & { x: number; y: number; w: number; h: number })[]; edges: VEdge[] };

export const NODE_W = 176, NODE_H = 46, SMALL_H = 38;
const STRONG_OPS = new Set(["EXECUTE", "WRITE", "CONNECT", "SENDTO", "SENDMSG", "RECVFROM", "RECVMSG", "CLONE", "RENAME", "UNLINK", "CHMOD"]);

/**
 * The attack path: alerted entities, the shortest connections between them (process ancestry, dropped files,
 * network peers), and what alerted entities executed, wrote or talked to. Library reads are left out.
 */
export function attackPath(nodes: GNode[], edges: GEdge[]): Set<string> {
  // folded system/unnamed files are context; a bulk group (the 35 files ransomware rewrote) is part of the attack
  const type = new Map(nodes.map(n => [n.id, n.type === "group" && !n.id.startsWith("group:bulk:") ? "group" : n.type]));
  const alerted = nodes.filter(n => n.alerted).map(n => n.id);
  const keep = new Set(alerted);
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    if (type.get(e.source) === "group" || type.get(e.target) === "group") continue;
    (adj.get(e.source) || adj.set(e.source, []).get(e.source)!).push(e.target);
    (adj.get(e.target) || adj.set(e.target, []).get(e.target)!).push(e.source);
  }
  // shortest undirected connections between alerted entities
  const targets = new Set(alerted);
  for (const a of alerted) {
    const prev = new Map<string, string | null>([[a, null]]);
    const q = [a];
    for (let i = 0; i < q.length; i++) for (const nb of adj.get(q[i]) || []) if (!prev.has(nb)) { prev.set(nb, q[i]); q.push(nb); }
    for (const b of targets) {
      if (b === a || !prev.has(b)) continue;
      for (let c: string | null | undefined = b; c; c = prev.get(c)) keep.add(c);
    }
    targets.delete(a);
  }
  // direct, high-signal neighbours of alerted entities
  const al = new Set(alerted);
  for (const e of edges) {
    if (!STRONG_OPS.has(e.op)) continue;
    if (al.has(e.source) && type.get(e.target) !== "group") keep.add(e.target);
    if (al.has(e.target) && type.get(e.source) !== "group") keep.add(e.source);
  }
  // bulk groups next to anything on the path (the files a forked encryptor rewrote)
  for (const e of edges) {
    if (e.source.startsWith("group:bulk:") && keep.has(e.target)) keep.add(e.source);
    if (e.target.startsWith("group:bulk:") && keep.has(e.source)) keep.add(e.target);
  }
  return keep;
}

/** Fold >= 5 non-alerted leaf files hanging off the same process with the same operation into one cluster node. */
export function clusterLeaves(nodes: GNode[], edges: GEdge[], expanded: Set<string>) {
  const deg = new Map<string, number>();
  for (const e of edges) { deg.set(e.source, (deg.get(e.source) || 0) + 1); deg.set(e.target, (deg.get(e.target) || 0) + 1); }
  const byId = new Map(nodes.map(n => [n.id, n]));
  const buckets = new Map<string, { parent: string; op: string; out: boolean; members: GEdge[] }>();
  for (const e of edges) {
    const s = byId.get(e.source), t = byId.get(e.target);
    if (!s || !t) continue;
    const leaf = t.type === "file" && !t.alerted && deg.get(t.id) === 1 ? t : s.type === "file" && !s.alerted && deg.get(s.id) === 1 ? s : null;
    if (!leaf) continue;
    const parent = leaf === t ? s.id : t.id, out = leaf === t;
    const k = `cluster:${parent}:${e.op}:${out ? "o" : "i"}`;
    (buckets.get(k) || buckets.set(k, { parent, op: e.op, out, members: [] }).get(k)!).members.push(e);
  }
  const drop = new Set<string>(); const outN: VNode[] = []; const outE: GEdge[] = [];
  for (const [k, b] of buckets) {
    if (b.members.length < 5 || expanded.has(k)) continue;
    const mids = b.members.map(e => (b.out ? e.target : e.source));
    mids.forEach(m => drop.add(m)); b.members.forEach(e => drop.add("e:" + e.id));
    const verb = b.members[0].label || b.op.toLowerCase();
    outN.push({ id: k, type: "group", label: `${mids.length} files`, title: `${mids.length} files ${verb}`, alerted: false, detection: null,
      first_ns: Math.min(...b.members.map(e => e.first_ns || Infinity)), count: mids.length, cluster: { parent: b.parent, op: b.op, members: mids } });
    const first = b.members.reduce((a, e) => ((e.order || 0) < (a.order || 0) ? e : a));
    outE.push({ ...first, id: `${k}:e`, source: b.out ? b.parent : k, target: b.out ? k : b.parent, count: b.members.reduce((s, e) => s + (e.count || 1), 0) });
  }
  return {
    nodes: [...nodes.filter(n => !drop.has(n.id)), ...outN] as VNode[],
    edges: [...edges.filter(e => !drop.has("e:" + e.id)), ...outE],
  };
}

/**
 * Stack >= 4 processes started by the same parent that share a name and detection into one node ("sh ×12"), so a
 * fan-out of look-alike processes reads as one step. Their children are re-parented to the stack, and stacked again.
 * Returns the stacked graph and member -> stack aliases.
 */
export function stackSiblings(nodes: VNode[], edges: GEdge[], expanded: Set<string>) {
  const ns = new Map<string, VNode>(nodes.map(n => [n.id, n]));
  let es = edges;
  const alias = new Map<string, string>();
  for (let iter = 0; iter < 5; iter++) {
    const groups = new Map<string, Set<string>>();
    for (const e of es) {
      if (e.op !== "CLONE") continue;
      const p = ns.get(e.source), c = ns.get(e.target);
      if (!p || !c || c.type !== "process") continue;
      const k = `stack:${p.id}:${c.details?.Program || c.label}:${c.alerted ? c.detection?.type || "x" : ""}`;
      if (expanded.has(k)) continue;
      (groups.get(k) || groups.set(k, new Set()).get(k)!).add(c.id);
    }
    const map = new Map<string, string>();
    for (const [k, m] of groups) {
      if (m.size < 4) continue;
      const mem = [...m].map(id => ns.get(id)!);
      const al = mem.find(n => n.alerted);
      const stackMembers = mem.flatMap(n => n.stack?.members || [n.id]);
      const prog = mem[0].details?.Program || "";
      const label = mem.every(n => n.label === mem[0].label) ? mem[0].label : prog && !prog.startsWith("(") ? prog.split("/").pop()! : "unnamed process";
      ns.set(k, { id: k, type: "process", label, title: `${stackMembers.length} similar processes${prog && !prog.startsWith("(") ? ` running ${prog}` : ""}`,
        details: mem[0].details, alerted: !!al, detection: al?.detection || null, first_ns: Math.min(...mem.map(n => n.first_ns || Infinity)),
        count: stackMembers.length, stack: { members: stackMembers } });
      for (const n of mem) { ns.delete(n.id); map.set(n.id, k); for (const x of n.stack?.members || [n.id]) alias.set(x, k); }
    }
    if (!map.size) break;
    const merged = new Map<string, GEdge>();
    for (const e of es) {
      const source = map.get(e.source) || e.source, target = map.get(e.target) || e.target;
      if (source === target) continue;
      const key = `${source}|${target}|${e.op}`;
      const x = merged.get(key);
      if (!x) merged.set(key, { ...e, source, target });
      else merged.set(key, { ...x, count: (x.count || 1) + (e.count || 1), order: Math.min(x.order ?? 1e9, e.order ?? 1e9), first_ns: Math.min(x.first_ns ?? Infinity, e.first_ns ?? Infinity) });
    }
    es = [...merged.values()];
  }
  return { nodes: [...ns.values()], edges: es, alias };
}

/** Layered left-to-right layout (information flows left to right; earlier steps sit further left). */
export function layout(nodes: VNode[], edges: GEdge[]): View {
  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({ rankdir: "LR", ranksep: 58, nodesep: 12, edgesep: 10, marginx: 24, marginy: 24, ranker: "network-simplex" });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) g.setNode(n.id, { width: NODE_W, height: n.type === "group" ? SMALL_H : NODE_H });
  const ids = new Set(nodes.map(n => n.id));
  const vis = edges.filter(e => ids.has(e.source) && ids.has(e.target) && e.source !== e.target);
  for (const e of vis) g.setEdge(e.source, e.target, { minlen: 1, weight: e.op === "CLONE" || e.op === "EXECUTE" ? 3 : 1 }, e.id);
  dagre.layout(g);
  const sorted = [...vis].sort((a, b) => (a.order ?? 1e9) - (b.order ?? 1e9) || (a.first_ns || 0) - (b.first_ns || 0));
  const step = new Map(sorted.map((e, i) => [e.id, i + 1]));
  return {
    nodes: nodes.map(n => { const p = g.node(n.id); const h = n.type === "group" ? SMALL_H : NODE_H; return { ...n, x: p.x - NODE_W / 2, y: p.y - h / 2, w: NODE_W, h }; }),
    edges: vis.map(e => ({ ...e, step: step.get(e.id)! })),
  };
}
