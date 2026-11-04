import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AlertCircle, Check, CheckCircle2, Copy, Globe, Info, Layers, Loader2, MoreHorizontal, SquareTerminal, FileText, X } from "lucide-react";
import type { EndpointState, IncidentStatus, Severity } from "./api";
import { detection, fmtDateTime, fmtRel, INCIDENT_STATUS, ALERT_STATUS, SEVERITY_LABEL } from "./format";

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

// ---------------------------------------------------------------- layout

export function PageHeader({ title, subtitle, actions, crumbs, children }: { title: ReactNode; subtitle?: ReactNode; actions?: ReactNode; crumbs?: ReactNode; children?: ReactNode }) {
  return (
    <header className="page-head">
      {crumbs && <div className="crumbs">{crumbs}</div>}
      <div className="page-head-row">
        <div className="page-head-text">
          <h1>{title}</h1>
          {subtitle && <div className="page-sub">{subtitle}</div>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </div>
      {children}
    </header>
  );
}

export function Card({ title, subtitle, actions, children, className, pad = true, id }: { title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children?: ReactNode; className?: string; pad?: boolean; id?: string }) {
  return (
    <section className={cx("card", className)} id={id}>
      {(title || actions) && (
        <div className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <div className="card-sub">{subtitle}</div>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </div>
      )}
      <div className={pad ? "card-body" : "card-body flush"}>{children}</div>
    </section>
  );
}

export function Tabs<T extends string>({ value, onChange, tabs }: { value: T; onChange: (v: T) => void; tabs: { id: T; label: ReactNode; count?: number | null }[] }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(t => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={cx("tab", value === t.id && "active")} onClick={() => onChange(t.id)}>
          {t.label}{t.count != null && <span className="tab-count">{t.count.toLocaleString()}</span>}
        </button>
      ))}
    </div>
  );
}

export function Segmented<T extends string>({ value, onChange, options, size }: { value: T; onChange: (v: T) => void; options: { id: T; label: ReactNode; title?: string }[]; size?: "sm" }) {
  return (
    <div className={cx("segmented", size)}>
      {options.map(o => <button key={o.id} title={o.title} className={cx(value === o.id && "on")} onClick={() => onChange(o.id)}>{o.label}</button>)}
    </div>
  );
}

// ---------------------------------------------------------------- states

export function Loading({ label = "Loading…", block }: { label?: string; block?: boolean }) {
  return <div className={cx("loading", block && "block")}><Loader2 className="spin" size={16} /> {label}</div>;
}
export function ErrorState({ error, onRetry }: { error: { message: string; status?: number } | string; onRetry?: () => void }) {
  const msg = typeof error === "string" ? error : error.message;
  const forbidden = typeof error !== "string" && error.status === 403;
  return (
    <div className="state-box error">
      <AlertCircle size={20} />
      <div>
        <div className="state-title">{forbidden ? "You do not have access to this" : "Could not load this"}</div>
        <div className="state-text">{msg}</div>
      </div>
      {onRetry && <button className="btn sm" onClick={onRetry}>Try again</button>}
    </div>
  );
}
export function Empty({ icon, title, text, action }: { icon?: ReactNode; title: ReactNode; text?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      {icon && <div className="empty-icon">{icon}</div>}
      <div className="empty-title">{title}</div>
      {text && <div className="empty-text">{text}</div>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}

// ---------------------------------------------------------------- badges

export function SeverityBadge({ severity, size }: { severity: Severity; size?: "lg" }) {
  return <span className={cx("sev", `sev-${severity}`, size)}><span className="sev-bar" />{SEVERITY_LABEL[severity] || severity}</span>;
}
export function StatusBadge({ status }: { status: IncidentStatus | string }) {
  const label = (INCIDENT_STATUS as Record<string, string>)[status] || ALERT_STATUS[status] || status;
  return <span className={cx("status", `st-${status}`)}>{label}</span>;
}
export function DetectionTag({ type, compact }: { type: string | null | undefined; compact?: boolean }) {
  const d = detection(type);
  return <span className="dtag" style={{ ["--dc" as any]: d.color }} title={d.describe}><span className="dtag-dot" />{compact ? d.short : d.label}</span>;
}
export function Chip({ children, title }: { children: ReactNode; title?: string }) {
  return <span className="chip" title={title}>{children}</span>;
}
const STATE_TONE: Record<EndpointState, string> = { protected: "ok", learning: "info", training: "info", offline: "bad", retired: "muted" };
export const STATE_LABEL: Record<EndpointState, string> = { protected: "Protected", learning: "Learning", training: "Training", offline: "Offline", retired: "Retired" };
export function EndpointStateBadge({ state, text }: { state: EndpointState; text?: string | null }) {
  return <span className={cx("estate", `tone-${STATE_TONE[state] || "muted"}`)} title={text || undefined}><span className="dot" />{STATE_LABEL[state] || state}</span>;
}
export function NodeIcon({ type, size = 14 }: { type: string; size?: number }) {
  if (type === "process" || type === "subject") return <SquareTerminal size={size} />;
  if (type === "network" || type === "netflow") return <Globe size={size} />;
  if (type === "group") return <Layers size={size} />;
  return <FileText size={size} />;
}

export function RelTime({ t, seconds }: { t: number | string | null | undefined; seconds?: boolean }) {
  return <time title={fmtDateTime(t, true)}>{seconds ? fmtDateTime(t, true) : fmtRel(t)}</time>;
}

// ---------------------------------------------------------------- inputs

export function CopyField({ value, label, multiline }: { value: string; label?: string; multiline?: boolean }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); } catch {
      const ta = document.createElement("textarea"); ta.value = value; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
    }
    setDone(true); setTimeout(() => setDone(false), 1500);
  };
  return (
    <div className="copyfield">
      {label && <div className="copyfield-label">{label}</div>}
      <div className={cx("copyfield-box", multiline && "multi")}>
        <code>{value}</code>
        <button className="btn sm ghost" onClick={copy} title="Copy to clipboard">{done ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy</>}</button>
      </div>
    </div>
  );
}

export function Field({ label, hint, children, error }: { label: ReactNode; hint?: ReactNode; children: ReactNode; error?: string | null }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && !error && <span className="field-hint">{hint}</span>}
      {error && <span className="field-error">{error}</span>}
    </label>
  );
}

export function Toggle({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} aria-label={label} disabled={disabled} className={cx("toggle", checked && "on")} onClick={() => onChange(!checked)}>
      <span className="knob" />
    </button>
  );
}

// ---------------------------------------------------------------- dialog / menu

export function Dialog({ title, subtitle, onClose, children, footer, width = 560 }: { title: ReactNode; subtitle?: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; width?: number }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", k); return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return createPortal(
    <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="dialog" role="dialog" aria-modal="true" style={{ width }}>
        <div className="dialog-head">
          <div><h2>{title}</h2>{subtitle && <div className="dialog-sub">{subtitle}</div>}</div>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </div>
        <div className="dialog-body">{children}</div>
        {footer && <div className="dialog-foot">{footer}</div>}
      </div>
    </div>, document.body);
}

/** Small confirm dialog; resolves the action and reports errors inline. */
export function Confirm({ title, text, confirmLabel, danger, onClose, onConfirm }: { title: string; text: ReactNode; confirmLabel: string; danger?: boolean; onClose: () => void; onConfirm: () => Promise<unknown> }) {
  const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const go = async () => { setBusy(true); setErr(""); try { await onConfirm(); onClose(); } catch (e: any) { setErr(e.message); setBusy(false); } };
  return (
    <Dialog title={title} onClose={onClose} width={460}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className={cx("btn", danger ? "danger" : "primary")} disabled={busy} onClick={go}>{busy && <Loader2 className="spin" size={14} />}{confirmLabel}</button></>}>
      <div className="confirm-text">{text}</div>
      {err && <div className="err">{err}</div>}
    </Dialog>
  );
}

export function Menu({ items, label = "More actions" }: { items: ({ label: string; onClick: () => void; danger?: boolean; disabled?: boolean; title?: string } | null | false)[]; label?: string }) {
  const [open, setOpen] = useState(false); const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h); return () => document.removeEventListener("mousedown", h);
  }, [open]);
  const list = items.filter(Boolean) as { label: string; onClick: () => void; danger?: boolean; disabled?: boolean; title?: string }[];
  return (
    <div className="menu-wrap" ref={ref}>
      <button className="icon-btn" aria-label={label} title={label} onClick={e => { e.stopPropagation(); setOpen(o => !o); }}><MoreHorizontal size={18} /></button>
      {open && <div className="menu">{list.map(i => (
        <button key={i.label} disabled={i.disabled} title={i.title} className={cx(i.danger && "danger")} onClick={e => { e.stopPropagation(); setOpen(false); i.onClick(); }}>{i.label}</button>
      ))}</div>}
    </div>
  );
}

// ---------------------------------------------------------------- toasts

type Toast = { id: number; text: string; tone: "ok" | "err" | "info" };
const ToastCtx = createContext<(text: string, tone?: Toast["tone"]) => void>(() => { });
export const useToast = () => useContext(ToastCtx);
export function ToastProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<Toast[]>([]);
  const push = useCallback((text: string, tone: Toast["tone"] = "ok") => {
    const id = Date.now() + Math.random();
    setList(l => [...l, { id, text, tone }]);
    setTimeout(() => setList(l => l.filter(t => t.id !== id)), tone === "err" ? 7000 : 4000);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts">{list.map(t => (
        <div key={t.id} className={cx("toast", t.tone)}>
          {t.tone === "ok" ? <CheckCircle2 size={16} /> : t.tone === "err" ? <AlertCircle size={16} /> : <Info size={16} />}
          <span>{t.text}</span>
          <button className="icon-btn" onClick={() => setList(l => l.filter(x => x.id !== t.id))} aria-label="Dismiss"><X size={14} /></button>
        </div>))}
      </div>
    </ToastCtx.Provider>
  );
}
