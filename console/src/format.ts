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

// ---------------------------------------------------------------- long paths, hashes and names

/** 64-hex container layer ids, hashes etc.: keep the first 8 characters ("3f2a9c1e…"). */
export const shortHex = (s: string) => (s || "").replace(/[0-9a-f]{24,}/gi, m => m.slice(0, 8) + "…");

/**
 * Character-budget middle truncation that keeps the end of a path (the file name and its nearest folders):
 * "/var/lib/docker/overlay2/3f2a…/merged/usr/bin/x" -> "/var/lib/docker/…/usr/bin/x".
 */
export function midTrunc(input: string, max: number): string {
  const s = shortHex(input);
  if (s.length <= max) return s;
  if (s.includes("/") && !/\s/.test(s)) {
    const segs = s.split("/");
    let tail = "/" + segs[segs.length - 1];
    for (let i = segs.length - 2; i > 0; i--) {
      const next = "/" + segs[i] + tail;
      if (next.length > max * 0.62) break;
      tail = next;
    }
    if (tail.length <= max - 4) {
      let head = s.slice(0, max - tail.length - 1);
      const cut = head.lastIndexOf("/");
      if (cut >= head.length / 2) head = head.slice(0, cut + 1);
      return head + "…" + tail;
    }
    if (tail.length > max) return "…" + tail.slice(tail.length - max + 1);
  }
  const h = Math.ceil((max - 1) * 0.6), t = max - 1 - h;
  return s.slice(0, h) + "…" + s.slice(s.length - t);
}

/** How many trailing characters a middle-truncated text must keep visible: a path's file name, a name's last part. */
export function tailLength(s: string): number {
  const slash = s.lastIndexOf("/");
  if (slash >= 0 && slash < s.length - 1) return Math.min(s.length - slash, 40);
  const m = /[-_.:][^-_.:]{1,8}$/.exec(s);
  if (m && m[0].length < s.length) return m[0].length;
  return Math.min(6, Math.floor(s.length / 3));
}

// ---------------------------------------------------------------- allow list vocabulary

export const ALLOW_KINDS: Record<string, { label: string; text: string }> = {
  program: { label: "Program", text: "A program path or name that may run without a 'new program' alert" },
  address: { label: "Network address", text: "An IP address or network (CIDR) that data-flow rules treat as trusted" },
  detection: { label: "Specific detection", text: "One detection (rule and subject) that should not alert again" },
};
/** Rules a "specific detection" entry can name, with what their subject (the entry's value) is. */
export const ALLOW_RULES: { id: string; label: string; subject: string; placeholder: string }[] = [
  { id: "untrusted_exec", label: "Executes a downloaded file", subject: "Downloaded file that was executed", placeholder: "/tmp/installer.sh" },
  { id: "untrusted_code_network", label: "Downloaded program contacts an untrusted address", subject: "Downloaded program", placeholder: "/opt/agent/bin/updater" },
  { id: "exfiltration", label: "Sensitive data sent to an untrusted address", subject: "Program that sent the data", placeholder: "/usr/local/bin/backup" },
  { id: "tainted_modify", label: "Untrusted modification of a file", subject: "File that was modified", placeholder: "/etc/app/config.yml" },
  { id: "tainted_spawn", label: "Untrusted data starts a program", subject: "Program that was started", placeholder: "/usr/bin/deploy" },
  { id: "novel_executable", label: "New program", subject: "Program", placeholder: "/usr/bin/links" },
  { id: "learned", label: "Unusual behaviour (or related activity) of a program", subject: "Program", placeholder: "/usr/sbin/nginx or nginx" },
];
export const ruleLabel = (r: string | null | undefined) => ALLOW_RULES.find(x => x.id === r)?.label || r || "";

const ipv4 = (s: string) => {
  const p = s.split(".");
  return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && +x <= 255);
};
const ipv6 = (s: string) => {
  if (!s.includes(":") || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
  try { new URL(`http://[${s}]/`); return true; } catch { return false; }
};

/** Client-side check of an allow-list value; null when it looks valid (the server has the final word). */
export function allowValueError(kind: string, value: string, rule?: string | null): string | null {
  const v = value.trim();
  if (!v) return null;
  if (kind === "address") {
    const [ip, pfx, extra] = v.split("/");
    if (extra !== undefined) return "Enter one address or network, e.g. 203.0.113.7 or 203.0.113.0/24.";
    const v4 = ipv4(ip), v6 = !v4 && ipv6(ip);
    if (!v4 && !v6) return "Not an IP address. Enter e.g. 203.0.113.7, 203.0.113.0/24 or 2001:db8::/48.";
    if (pfx !== undefined) {
      if (!/^\d{1,3}$/.test(pfx) || +pfx > (v4 ? 32 : 128)) return `The network size must be /0 to /${v4 ? 32 : 128}.`;
      if (+pfx < (v4 ? 16 : 48)) return `This network is too large to trust. Use at most a /${v4 ? 16 : 48}.`;
    }
    return null;
  }
  const programLike = kind === "program" || rule === "learned" || rule === "novel_executable";
  if (/\s/.test(v) && !v.startsWith("/")) return "A program name cannot contain spaces. Use its full path instead.";
  if (v.includes("/") && !v.startsWith("/")) return programLike ? "Use a full path starting with / (e.g. /usr/bin/links) or a bare name (links)." : "Use the full path, starting with /.";
  if (v.length > 1 && v.endsWith("/")) return "This looks like a folder. Enter the path of a file or program.";
  return null;
}

/** First line of a command line with a long program path middle-truncated (args stay visible) and hashes shortened. */
export function shortCmd(t: string, head = 32): string {
  const line = (t || "").split("\n")[0];
  const i = line.indexOf(" ");
  const exe = i < 0 ? line : line.slice(0, i), rest = i < 0 ? "" : line.slice(i);
  return (exe.length > head ? midTrunc(exe, head) : shortHex(exe)) + shortHex(rest);
}
