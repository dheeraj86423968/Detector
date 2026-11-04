import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

// ---------------------------------------------------------------- transport

export class ApiError extends Error {
  /** `detail` is the server's own message (null when `message` is a generic fallback). */
  constructor(message: string, public status: number, public detail: string | null = null) { super(message); }
}

/** Pages anyone can open without signing in: a 401 there must not bounce to the sign-in page. */
const PUBLIC_HASH = /^#\/(login|signup|join)(\/|\?|$)/;

const detailText = (d: unknown): string | null => {
  if (!d) return null;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map(x => (x && typeof x === "object" && "msg" in x ? String((x as any).msg) : String(x))).join("; ");
  return String(d);
};

/** Same-origin JSON call. A 401 anywhere except the sign-in call and the public pages sends the browser to the login page. */
export async function api<T = any>(path: string, opts: RequestInit = {}): Promise<T> {
  const r = await fetch(path, { credentials: "same-origin", ...opts, headers: { "Content-Type": "application/json", ...(opts.headers || {}) } });
  const js = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== "/api/login" && !PUBLIC_HASH.test(window.location.hash)) window.location.hash = "#/login";
  if (!r.ok || js.ok === false) {
    const cap = (x: string) => x.charAt(0).toUpperCase() + x.slice(1);
    const server = detailText(js.detail) || detailText(js.error);
    const msg = server || (r.status === 403 ? "You do not have permission to do this." : r.status === 404 ? "Not found." : r.statusText || "Request failed");
    throw new ApiError(cap(msg), r.status, server ? cap(server) : null);
  }
  return js as T;
}
export const post = <T = any>(path: string, body?: unknown) => api<T>(path, { method: "POST", body: body === undefined ? "{}" : JSON.stringify(body) });
export const patch = <T = any>(path: string, body: unknown) => api<T>(path, { method: "PATCH", body: JSON.stringify(body) });
export const del = <T = any>(path: string) => api<T>(path, { method: "DELETE" });

/** GET with loading/error state, optional polling. Keeps the last good data while reloading. */
export function useApi<T>(path: string | null, intervalMs = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(!!path);
  const seq = useRef(0);
  const load = useCallback(() => {
    if (!path) return Promise.resolve();
    const my = ++seq.current;
    return api<T>(path).then(d => { if (my === seq.current) { setData(d); setError(null); } })
      .catch(e => { if (my === seq.current) setError(e instanceof ApiError ? e : new ApiError(String(e), 0)); })
      .finally(() => { if (my === seq.current) setLoading(false); });
  }, [path]);
  useEffect(() => {
    setLoading(!!path); setData(null); setError(null);
    load();
  }, [path, load]);
  // polling is separate so that changing the interval keeps the data on screen
  useEffect(() => {
    if (!intervalMs || !path) return;
    const t = setInterval(() => { if (document.visibilityState === "visible") load(); }, intervalMs);
    return () => clearInterval(t);
  }, [path, intervalMs, load]);
  return { data, error, loading, reload: load };
}

// ---------------------------------------------------------------- session / access control

export type Role = "admin" | "analyst" | "viewer";
/** `manage_org`: organisation admin (rename it); `operate`: platform operator (every organisation's usage). */
export type Can = { manage_users: boolean; manage_endpoints: boolean; triage: boolean; run_checks: boolean; manage_org: boolean; operate: boolean };
export type Me = { ok: true; user_id: number; username: string; display_name?: string | null; email?: string | null; role: Role;
  auth?: "local" | "oidc"; endpoints?: string[] | null; can?: Partial<Can>;
  org?: { id: number | string; name: string } | null; operator?: boolean };
export type SignupMode = "off" | "code" | "open";
export type AuthConfig = { sso: boolean; sso_label: string; password: boolean; password_policy: "enabled" | "admin-only" | "disabled"; signup?: SignupMode };

export const MeContext = createContext<Me | null>(null);
export const useMe = () => useContext(MeContext);
/** Re-reads /api/me (e.g. after the organisation was renamed, so the sidebar follows). */
export const MeReloadContext = createContext<() => void>(() => { });
export const useReloadMe = () => useContext(MeReloadContext);
/** Permission flags from /api/me (the server decides; the UI never infers from role names). */
export const useCan = (): Can => {
  const c = useMe()?.can || {};
  return { manage_users: !!c.manage_users, manage_endpoints: !!c.manage_endpoints, triage: !!c.triage, run_checks: !!c.run_checks,
    manage_org: !!c.manage_org, operate: !!c.operate };
};

export type UserRow = { id: number; username: string; display_name?: string | null; email?: string | null; role: Role; auth: "local" | "oidc";
  endpoints: { id: string; name: string }[] | null; disabled: boolean; created_at: string; last_login: string | null };
export type UsersResp = { ok: true; sso?: { enabled: boolean; label: string; password_policy: AuthConfig["password_policy"] }; users: UserRow[] };

// ---------------------------------------------------------------- organisations (0.5)

/** `endpoints` is what counts against `max_endpoints`. */
export type Org = { id: number | string; name: string; created_at: string; max_endpoints: number; endpoints: number; users: number; pending_invites: number };
export type OrgResp = { ok: true; org: Org };
/** A pending invite (admin view). `email` null = anyone with the link; `endpoints` null = all endpoints. */
export type Invite = { id: number | string; email: string | null; role: Role; endpoints: { id: string; name: string }[] | null;
  created_at: string; expires_at: string; created_by: string | null; link: string };
export type InvitesResp = { ok: true; invites: Invite[] };
export type NewInvite = { email?: string; role: Role; endpoints: string[] | null };
/** What the person opening an invite link sees (public). */
export type PublicInvite = { ok: true; organisation: string; role: Role; email: string | null; expires_at: string; invited_by: string | null };
export type SignupBody = { organisation: string; name: string; email: string; password: string; code?: string };
export type AcceptInviteBody = { name: string; email?: string; password: string };
export type OperatorOrg = { id: number | string; name: string; created_at: string; disabled: boolean; max_endpoints: number;
  users: number; endpoints: number; endpoints_online: number; alerts_7d: number; last_activity: string | null };
export type OperatorOrgsResp = { ok: true; signup: { mode: SignupMode; code: string | null }; orgs: OperatorOrg[] };

/** Client-side checks shared by sign-up and invite acceptance (the server checks again). */
export const looksLikeEmail = (s: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim());
export const PASSWORD_MIN = 10;

// ---------------------------------------------------------------- endpoints

export type EndpointState = "learning" | "training" | "protected" | "offline" | "retired";
export type Endpoint = { id: string; name: string; hostname: string; os?: string; kind?: string; state: EndpointState; state_text?: string;
  baseline?: { done: number; needed: number }; last_seen: string | null; online?: boolean; agent_version?: string | null;
  open_incidents?: number; last_incident_ns?: number | null };

export type LifecycleStep = { step: "enrolled" | "baseline" | "model" | "protecting"; status: "done" | "active" | "pending"; at?: string | null; text: string;
  done?: number; needed?: number; days?: { date: string; events: number; complete: boolean }[];
  details?: { known_programs?: number; trusted_addresses?: number; benign_rules?: number } | null };
export type Check = { id: string; state: "queued" | "running" | "done" | "failed"; created_at: string; finished_at: string | null;
  attacks: number; detected: number; rate: number; false_alarms_on_clean_data: number;
  by_family: { family: string; label: string; attacks: number; detected: number }[]; verdict: "pass" | "warn" | "fail"; verdict_text: string };
export type EndpointOverview = { ok: true; endpoint: Endpoint; lifecycle: LifecycleStep[];
  health: { online: boolean; last_seen: string | null; agent_version?: string | null; collector?: string | null; events_dropped?: number | null;
    queue_depth?: number | null; cpu_pct?: number | null; rss_mb?: number | null; events_24h?: number | null; status: "ok" | "warning" | "error"; issues: string[] };
  detection: { incidents_open: number; incidents_total: number; alerts_7d: number; by_type_7d: Record<string, number>;
    triaged: { true_positive: number; false_positive: number; open: number }; per_day: { date: string; alerts: number; incidents: number }[] };
  check: Check | null; can_run_check: boolean; check_blocked_reason: string | null };
export type EndpointConfigResp = { ok: true; endpoint: { id: string; name: string; config?: Record<string, any> } };
/** `install_command`: one line for a Linux server (`curl -fsSL https://<host>/install.sh | sudo bash -s -- --token <token>`);
 *  `docker_command`: hosts that only run containers; `enroll_command`: an agent that is already installed. */
export type EnrollToken = { ok: true; token: string; expires_in_hours: number; ca_sha256: string; enroll_command: string;
  install_command?: string; docker_command?: string; server_url?: string; agent_url?: string };

// ---------------------------------------------------------------- incidents & alerts

export type Severity = "critical" | "high" | "medium" | "low";
export type IncidentStatus = "open" | "investigating" | "true_positive" | "false_positive" | "resolved";
export type DetectionType = "novelty" | "rules" | "corroborated" | "learned" | "evidence";
/** An attack behaviour recognised in the incident's graph (ransomware, remote shell, ...); the first one is the title. */
export type Behaviour = { kind: string; label: string; tactic: string; text: string; node?: string | null; serious?: boolean };
export type IncidentSummary = { id: number; endpoint_id: string; endpoint_name: string; first_ns: number; last_ns: number; severity: Severity;
  title: string; tactics: string[]; alerts: number; processes: number; status: IncidentStatus; behaviours?: Behaviour[] };
export type Detection = { type: DetectionType; rule?: string | null; reason?: string | null; alert_id?: number | null };
export type GNode = { id: string; type: "process" | "file" | "network" | "group"; label: string; title?: string | null; details?: Record<string, string> | null;
  alerted?: boolean; detection?: Detection | null; first_ns?: number | null; count?: number };
export type GEdge = { id: string; source: string; target: string; op: string; label?: string; first_ns?: number | null; count?: number; order?: number };
export type StoryEntry = { ts_ns: number; kind: "process" | "exec" | "write" | "read" | "network" | "detection" | string; text: string; node?: string | null;
  detection?: { type: DetectionType; reason?: string | null } | null };
export type IncidentAlert = { id: number; ts_ns: number; node: string; label: string; title?: string | null; type: DetectionType; rule?: string | null; reason?: string | null; status: string };
export type IncidentDetail = { ok: true; incident: IncidentSummary; story: StoryEntry[]; graph: { nodes: GNode[]; edges: GEdge[]; truncated?: boolean }; alerts: IncidentAlert[] };

export type RawAlert = { id: number; endpoint_id: string; endpoint: string; window_start_ns: number; node_uuid: string; ntype: string; label: string;
  layer?: DetectionType | null; rule?: string | null; reason?: string | null; status: string; created_at: string; incident_id?: number | null;
  allowed_by?: number | null };

export type Overview = { ok: true; endpoints: { total: number; protected: number; learning: number; offline: number };
  incidents: { open: number; last_7d: number; by_severity: Record<Severity, number> };
  per_day: { date: string; incidents: number }[]; recent_incidents: IncidentSummary[];
  attention: { kind: string; endpoint_id: string; endpoint_name: string; text: string }[] };

// ---------------------------------------------------------------- allow list

export type AllowKind = "program" | "address" | "detection";
export type AllowKindInfo = { id: AllowKind; label: string; text: string };
export type AllowEntry = { id: number; kind: AllowKind; value: string; rule: string | null; rule_text?: string | null;
  endpoints: { id: string; name: string }[] | null; note?: string | null; created_by?: string | null; created_at: string; alerts_allowed: number };
export type AllowListResp = { ok: true; kinds: AllowKindInfo[]; entries: AllowEntry[] };
export type AllowOption = { kind: AllowKind; value: string; rule: string | null; title: string; text: string };
export type AllowOptionsResp = { ok: true; alert_id: number; endpoint_id: string; allowed_by: number | null; options: AllowOption[] };
export type NewAllowEntry = { kind: AllowKind; value: string; rule?: string | null; endpoints: string[] | null; note?: string; resolve_open: boolean };
