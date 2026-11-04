import type { DetectionType, IncidentStatus, Severity } from "./api";

// ---------------------------------------------------------------- time (always the viewer's local time zone)

type TimeLike = number | string | Date | null | undefined;
/** ns integers (`*_ns`), ISO strings (`*_at`) or Dates -> Date */
export const toDate = (t: TimeLike): Date | null => {
  if (t == null || t === "") return null;
  if (t instanceof Date) return t;
  if (typeof t === "number") return new Date(t > 1e14 ? t / 1e6 : t > 1e11 ? t : t * 1000);
  const d = new Date(t);
  return isNaN(d.getTime()) ? null : d;
};

const sameYear = (d: Date) => d.getFullYear() === new Date().getFullYear();
export const fmtDateTime = (t: TimeLike, seconds = false) => {
  const d = toDate(t); if (!d) return "—";
  return d.toLocaleString(undefined, { day: "numeric", month: "short", ...(sameYear(d) ? {} : { year: "numeric" }), hour: "2-digit", minute: "2-digit", ...(seconds ? { second: "2-digit" } : {}) });
};
export const fmtDate = (t: TimeLike) => {
  const d = toDate(t); if (!d) return "—";
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short", ...(sameYear(d) ? {} : { year: "numeric" }) });
};
export const fmtTime = (t: TimeLike, seconds = true) => {
  const d = toDate(t); if (!d) return "—";
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", ...(seconds ? { second: "2-digit" } : {}) });
};
/** "just now", "12 min ago", "3 h ago", "2 days ago", then a date */
export const fmtRel = (t: TimeLike) => {
  const d = toDate(t); if (!d) return "never";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 0) return fmtDateTime(d);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  const days = s / 86400;
  if (days < 14) { const n = Math.round(days); return `${n} day${n === 1 ? "" : "s"} ago`; }
  if (days < 60) return `${Math.round(days / 7)} weeks ago`;
  if (days < 365 * 2) return `${Math.round(days / 30.4)} months ago`;
  return `${Math.round(days / 365)} years ago`;
};
export const fmtDuration = (ns: number) => {
  const m = Math.max(1, Math.round(ns / 6e10));
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60), r = m % 60;
  if (h < 48) return r ? `${h} h ${r} min` : `${h} h`;
  return `${Math.round(h / 24)} days`;
};
/** "4 Jan, 14:00 – 14:45" (same day) or full both ends */
export const fmtSpan = (a: TimeLike, b: TimeLike) => {
  const da = toDate(a), db = toDate(b);
  if (!da) return "—";
  if (!db || db.getTime() - da.getTime() < 60e3) return fmtDateTime(da);
  if (da.toDateString() === db.toDateString()) return `${fmtDateTime(da)} – ${fmtTime(db, false)}`;
  return `${fmtDateTime(da)} – ${fmtDateTime(db)}`;
};

export const fmtNum = (n: number | null | undefined) => (n == null ? "—" : n.toLocaleString());
export const fmtCompact = (n: number | null | undefined) =>
  n == null ? "—" : n >= 1e9 ? `${(n / 1e9).toFixed(1)} B` : n >= 1e6 ? `${(n / 1e6).toFixed(1)} M` : n >= 1e4 ? `${Math.round(n / 1e3)} k` : n.toLocaleString();

// ---------------------------------------------------------------- vocabulary

export const DETECTION: Record<DetectionType, { label: string; short: string; color: string; describe: string }> = {
  rules: { label: "Suspicious data flow", short: "Data flow", color: "#d92d20", describe: "Sensitive data or untrusted input moved in a way an attack does (e.g. secrets sent to an untrusted address)." },
  novelty: { label: "New program", short: "New program", color: "#7a3ff2", describe: "A program ran that never ran while the endpoint's normal behaviour was learned." },
  corroborated: { label: "Related activity", short: "Related", color: "#dc6803", describe: "Unusual behaviour directly connected to another detection." },
  learned: { label: "Unusual behaviour", short: "Unusual", color: "#0e7090", describe: "Behaviour unlike anything in the endpoint's learned baseline." },
  evidence: { label: "Supporting evidence", short: "Evidence", color: "#667085", describe: "Activity that supports another detection." },
};
export const detection = (t: string | null | undefined) => DETECTION[(t as DetectionType) || "learned"] || DETECTION.learned;

/** Reason sentences are shown verbatim; scores are never shown, so strip any score wording an older server may include. */
export const reasonText = (type: string | null | undefined, reason: string | null | undefined) => {
  if (!reason) return detection(type).describe;
  if (/learned score|percentile|\bscore\b/i.test(reason)) {
    return type === "corroborated" ? "Behaves unlike the learned baseline, directly connected to another detection." : "Behaves unlike anything in the learned baseline.";
  }
  return reason.charAt(0).toUpperCase() + reason.slice(1);
};

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
export const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

export const INCIDENT_STATUS: Record<IncidentStatus, string> = {
  open: "Open", investigating: "Investigating", true_positive: "Confirmed threat", false_positive: "False alarm", resolved: "Resolved",
};
export const ALERT_STATUS: Record<string, string> = {
  open: "Open", ack: "Acknowledged", closed: "Closed", true_positive: "Confirmed threat", false_positive: "False alarm",
  investigating: "Investigating", resolved: "Resolved",
};
export const ROLE_INFO: Record<string, { label: string; describe: string }> = {
  admin: { label: "Admin", describe: "Everything, including users, endpoints and their settings." },
  analyst: { label: "Analyst", describe: "Views incidents, triages them and runs detection checks." },
  viewer: { label: "Viewer", describe: "Read-only access to incidents and endpoints." },
};

/** "subject /usr/bin/python python -m x" -> parts for display of a raw alert entity */
export const entityOf = (ntype: string, label: string) => {
  const raw = label.replace(/^(subject|file|netflow) /, "");
  if (ntype === "subject") { const [exe, ...rest] = raw.split(" "); return { kind: "process" as const, name: baseName(exe), full: rest.join(" ") || exe }; }
  if (ntype === "netflow") { const [ip, port] = raw.split(" "); return { kind: "network" as const, name: port ? `${ip}:${port}` : ip, full: raw }; }
  return { kind: "file" as const, name: baseName(raw), full: raw };
};
export const baseName = (p: string) => (p || "").split("/").filter(Boolean).pop() || p;
export const initials = (s: string) => s.split(/[\s._@-]+/).filter(Boolean).slice(0, 2).map(x => x[0]!.toUpperCase()).join("") || "?";
export const plural = (n: number, one: string, many = one + "s") => `${n.toLocaleString()} ${n === 1 ? one : many}`;
