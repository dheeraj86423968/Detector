import { createContext, useContext } from "react";

export async function api<T = any>(path: string, opts: RequestInit = {}): Promise<T> {
  const r = await fetch(path, { credentials: "same-origin", headers: { "Content-Type": "application/json", ...(opts.headers || {}) }, ...opts });
  const js = await r.json().catch(() => ({ ok: false, error: r.statusText }));
  if (r.status === 401) { window.location.hash = "#/login"; }
  if (!r.ok || js.ok === false) throw new Error(js.error || js.detail || r.statusText);
  return js;
}

const pad = (n: number) => String(n).padStart(2, "0");
// local time of the viewer, ISO-like
export const fmtTs = (ns: number) => { const d = new Date(ns / 1e6); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };

// seconds since a unix timestamp, compact ("42 s", "7 min", "3 h", "2 d")
export const ago = (at: number) => { const s = Math.max(0, Math.round(Date.now() / 1000 - at)); return s < 60 ? `${s} s` : s < 3600 ? `${Math.round(s / 60)} min` : s < 86400 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} d`; };
// heartbeat older than 5 minutes
export const isStale = (h: Health | null | undefined) => !!h && Date.now() / 1000 - h.at > 300;

export type Health = { agent_version: string; queue_depth: number; last_window_end_ns: number | null; cpu_pct: number | null; rss_mb: number | null; collector_lost?: number | null; at: number };
export type Endpoint = { id: string; name: string; hostname: string; phase: string; kind: string; baseline_days_done: number; last_seen: string | null; open_alerts: number; current_bundle: string | null; health: Health | null; config?: Record<string, any> };
export type User = { id: number; username: string; role: "admin" | "analyst"; created_at: string; auth?: "local" | "oidc"; email?: string | null; last_login?: string | null };
export type Me = { role: "admin" | "analyst"; username: string; user_id: number; auth?: "local" | "oidc"; email?: string | null };
export type AuthConfig = { sso: boolean; sso_label: string; password: boolean; password_policy: "enabled" | "admin-only" | "disabled" };
export type EnrollToken = { token: string; expires_in_hours: number; ca_sha256: string; enroll_command: string };

// the signed-in user, provided by the Shell layout (null while loading)
export const MeContext = createContext<Me | null>(null);
export const useMe = () => useContext(MeContext);
export type Alert = { id: number; endpoint_id: string; endpoint: string; window_start_ns: number; node_uuid: string; ntype: string; label: string; fused: number; r1: number; r2: number; status: string;
  layer?: Layer; rule?: string | null; reason?: string | null };
export type Layer = "novelty" | "rules" | "corroborated" | "learned";
export const LAYER_NAME: Record<string, string> = { novelty: "new program", rules: "info-flow rule", corroborated: "learned + nearby", learned: "learned only", evidence: "rule evidence" };
export type WindowRow = { start_ns: number; end_ns: number; edges: number; nodes: number; alerts: number; max_fused: number; max_r1: number; max_r2: number };
export type GraphNode = { uuid: string; ntype: string; label: string; flagged?: { fused: number; r1: number; r2: number; layer?: string; reason?: string | null } | null };
export type GraphEdge = { src: string; dst: string; op: string; ts_ns: number; loss: number | null };
export type IncidentItem = { uuid: string; label: string; ts: number; flagged?: boolean; fused?: number; op?: string };
export type IncidentSummary = {
  flagged_nodes: number; flagged_processes: IncidentItem[]; executed_files: IncidentItem[];
  written_files: IncidentItem[]; external_connections: IncidentItem[];
  first_ns: number | null; last_ns: number | null; max_fused: number; windows: number;
  by_layer?: Record<string, number>; detections?: { uuid: string; label: string; layer: string; rule: string; reason: string; ts: number }[];
};
export type Incident = { nodes: GraphNode[]; edges: GraphEdge[]; summary: IncidentSummary | null; focus_ns: number | null; windows: number[] };
