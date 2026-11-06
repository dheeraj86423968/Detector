import { useEffect, useMemo, useState } from "react";
import { Loader2 } from "lucide-react";
import { AllowKind, AllowKindInfo, AllowOption, AllowOptionsResp, Endpoint, NewAllowEntry, post, useApi } from "./api";
import { ALLOW_KINDS, ALLOW_RULES, allowValueError, plural } from "./format";
import { AllowKindIcon, cx, Dialog, Empty, EndpointPicker, ErrorState, Field, Loading, PathText } from "./ui";

/** keep a server error (400/409) in view: it sits at the end of a dialog that may scroll */
const useErrInView = (err: string) => useEffect(() => { if (err) document.querySelector(".dialog .err")?.scrollIntoView({ block: "nearest", behavior: "smooth" }); }, [err]);

/** "Added to the allow list · 18 open alerts allowed" */
export const allowedText = (n: number) => (n > 0 ? `Added to the allow list · ${plural(n, "open alert")} allowed` : "Added to the allow list");

const RULE_ORDER = ["novel_executable", "untrusted_exec", "untrusted_code_network", "exfiltration", "tainted_modify", "tainted_spawn", "learned"];
const RULES = RULE_ORDER.map(id => ALLOW_RULES.find(r => r.id === id)!).filter(Boolean);
const KIND_IDS: AllowKind[] = ["program", "address", "detection"];

const VALUE_UI: Record<AllowKind, { label: string; placeholder: string; hint: string }> = {
  program: { label: "Program", placeholder: "/usr/bin/links", hint: "The program's full path; it matches only that program (as the agent compares programs). No wildcards or folders." },
  address: { label: "IP address or network", placeholder: "203.0.113.7 or 203.0.113.0/24", hint: "One address, or a network in CIDR notation of at most a /16 (IPv4) or /48 (IPv6)." },
  detection: { label: "Subject", placeholder: "", hint: "Exactly as the alert shows it." },
};

type Initial = { kind?: AllowKind; value?: string; rule?: string | null; endpoints?: string[] | null };

/** The "Add to allow list" dialog (Allow list page, endpoint settings). */
export function AddAllowDialog({ kinds, initial, onClose, onDone }: { kinds?: AllowKindInfo[]; initial?: Initial; onClose: () => void; onDone: (id: number, allowed: number) => void }) {
  const eps = useApi<{ endpoints: Endpoint[] }>("/api/endpoints");
  const [kind, setKind] = useState<AllowKind>(initial?.kind || "program");
  const [value, setValue] = useState(initial?.value || "");
  const [rule, setRule] = useState<string>(initial?.rule || "untrusted_exec");
  const [scope, setScope] = useState<"all" | "some">(initial?.endpoints ? "some" : "all");
  const [picked, setPicked] = useState<Set<string>>(new Set(initial?.endpoints || []));
  const [note, setNote] = useState(""); const [resolve, setResolve] = useState(true); const [force, setForce] = useState(false);
  const [touched, setTouched] = useState(false); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  useErrInView(err);
  const info = (k: AllowKind) => kinds?.find(x => x.id === k) || { id: k, ...ALLOW_KINDS[k] };
  const r = RULES.find(x => x.id === rule);
  const vui = kind === "detection" ? { label: r?.subject || "Subject", placeholder: r?.placeholder || "", hint: rule === "learned" ? VALUE_UI.program.hint : "Exactly as the alert shows it, e.g. the full path of the file or program." } : VALUE_UI[kind];
  const vErr = allowValueError(kind, value, kind === "detection" ? rule : null);
  const valid = !!value.trim() && !vErr && (scope === "all" || picked.size > 0) && !!note.trim();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setTouched(true); setErr("");
    if (!valid) return;
    setBusy(true);
    const body: NewAllowEntry = { kind, value: value.trim(), rule: kind === "detection" ? rule : null, endpoints: scope === "all" ? null : [...picked], note: note.trim() || undefined, resolve_open: resolve, force };
    try { const res = await post<{ id: number; alerts_allowed: number }>("/api/allowlist", body); onDone(res.id, res.alerts_allowed || 0); onClose(); }
    catch (ex: any) { setErr(ex.message); setBusy(false); }
  };
  return (
    <Dialog title="Add to allow list" width={640} onClose={onClose}
      subtitle="Activity you have reviewed and accept as normal. It stops alerting from the agent's next check-in; no retraining needed."
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="allow-form" disabled={busy || (touched && !valid)}>{busy && <Loader2 size={14} className="spin" />}Add to allow list</button></>}>
      <form id="allow-form" className="form" onSubmit={submit}>
        <div className="field">
          <span className="field-label">What to allow</span>
          <div className="role-pick">{KIND_IDS.map(k => (
            <label key={k} className={cx("role-opt kind-opt", kind === k && "on")}>
              <input type="radio" name="kind" checked={kind === k} onChange={() => { setKind(k); setErr(""); }} />
              <span><b className="kind-opt-title"><AllowKindIcon kind={k} size={13} />{info(k).label}</b><span className="muted sm">{info(k).text}</span></span>
            </label>
          ))}</div>
        </div>
        {kind === "detection" && <Field label="Detection" hint={rule === "learned" ? "Unusual-behaviour and related-activity alerts of one program. Its other detections still alert." : "Only this rule on the subject below stops alerting; the rule still alerts for anything else."}>
          <select value={rule} onChange={e => setRule(e.target.value)}>
            {RULES.map(x => <option key={x.id} value={x.id}>{x.label}</option>)}
          </select>
        </Field>}
        <Field label={vui.label} hint={vui.hint} error={(touched || value.length > 3) && vErr ? vErr : touched && !value.trim() ? "Enter a value." : null}>
          <input className="mono" value={value} onChange={e => setValue(e.target.value)} onBlur={() => value && setTouched(true)} placeholder={vui.placeholder} autoFocus spellCheck={false} autoComplete="off" />
        </Field>
        <div className="field">
          <span className="field-label">Applies to</span>
          <div className="role-pick two">
            <label className={cx("role-opt", scope === "all" && "on")}><input type="radio" checked={scope === "all"} onChange={() => setScope("all")} /><span><b>All endpoints</b><span className="muted sm">Including endpoints added later</span></span></label>
            <label className={cx("role-opt", scope === "some" && "on")}><input type="radio" checked={scope === "some"} onChange={() => setScope("some")} /><span><b>Selected endpoints</b><span className="muted sm">Only on the endpoints you choose</span></span></label>
          </div>
          {scope === "some" && (eps.loading && !eps.data ? <Loading /> : <EndpointPicker eps={eps.data?.endpoints || []} picked={picked} setPicked={setPicked} />)}
          {scope === "some" && touched && picked.size === 0 && <span className="field-error">Choose at least one endpoint.</span>}
        </div>
        <Field label="Reason" hint="Required: why this is normal. Recorded in the activity log; your organisation's admins are notified." error={touched && !note.trim() ? "Enter a reason." : null}>
          <input value={note} onChange={e => setNote(e.target.value)} maxLength={500} placeholder="e.g. Text browser used by the ops team" />
        </Field>
        <ResolveBox checked={resolve} onChange={setResolve} />
        <ForceBox err={err} checked={force} onChange={setForce} />
        {err && <div className="err">{err}</div>}
      </form>
    </Dialog>
  );
}

/** Shown once the server asked for confirmation (an interpreter, shell or loader): allow it anyway. */
function ForceBox({ err, checked, onChange }: { err: string; checked: boolean; onChange: (v: boolean) => void }) {
  if (!/^Confirmation required/i.test(err) && !checked) return null;
  return (
    <label className="check-row">
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} />
      <span><b>Allow it anyway</b><span className="muted sm">Anything run through this program is then trusted as normal. Recorded with your reason.</span></span>
    </label>
  );
}

function ResolveBox({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="check-row">
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} />
      <span><b>Also resolve matching open alerts</b><span className="muted sm">They are marked as false alarms and leave their incidents. They stay in the alert list for the record.</span></span>
    </label>
  );
}

/** An IPv4 address' /24, offered next to "trust this address" for services that use several addresses. */
const net24 = (ip: string) => {
  const p = ip.split(".");
  if (p.length !== 4 || ip.includes("/") || p[0] === "127") return null;
  return `${p[0]}.${p[1]}.${p[2]}.0/24`;
};
export const addressOptions = (ip: string): AllowOption[] => {
  const out: AllowOption[] = [{ kind: "address", value: ip, rule: null, title: `Trust the address ${ip}`, text: "Data-flow rules treat this address as trusted, so sending data to it or running code from it no longer alerts." }];
  const n = net24(ip);
  if (n) out.push({ kind: "address", value: n, rule: null, title: `Trust the network ${n}`, text: `All 256 addresses ${n.replace(/\.0\/24$/, ".0")} to ${n.replace(/\.0\/24$/, ".255")}, for a service that uses several addresses.` });
  return out;
};

/**
 * "Allow…" from an alert (incident graph node, alert row): the server's ready-made options as radio cards, or a
 * preset list (trust a network peer that has no alert of its own).
 */
export function AllowAlertDialog({ alertId, preset, endpoint, subject, onClose, onDone }: {
  alertId?: number | null; preset?: AllowOption[]; endpoint: { id: string; name: string }; subject?: string;
  onClose: () => void; onDone: (allowed: number) => void;
}) {
  const opts = useApi<AllowOptionsResp>(alertId != null && !preset ? `/api/alerts/${alertId}/allow-options` : null);
  const options = useMemo(() => {
    if (preset) return preset;
    const out: AllowOption[] = [];
    for (const o of opts.data?.options || []) {
      out.push(o);
      if (o.kind === "address") for (const x of addressOptions(o.value).slice(1)) if (!out.some(y => y.value === x.value)) out.push(x);
    }
    return out;
  }, [preset, opts.data]);
  const [pick, setPick] = useState(0);
  const [scope, setScope] = useState<"this" | "all">("this");
  const [note, setNote] = useState(""); const [resolve, setResolve] = useState(true); const [force, setForce] = useState(false);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const sel = options[pick];
  useErrInView(err);
  const submit = async () => {
    if (!sel || !note.trim()) return;
    setBusy(true); setErr("");
    const body: NewAllowEntry = { kind: sel.kind, value: sel.value, rule: sel.rule, endpoints: scope === "this" ? [endpoint.id] : null, note: note.trim() || undefined, resolve_open: resolve, force };
    try { const r = await post<{ alerts_allowed: number }>("/api/allowlist", body); onClose(); onDone(r.alerts_allowed || 0); }
    catch (ex: any) { setErr(ex.message); setBusy(false); }
  };
  const loading = !preset && opts.loading && !opts.data;
  const already = opts.data?.allowed_by != null;
  return (
    <Dialog title={preset ? "Trust this address" : "Allow this activity"} width={620} onClose={onClose}
      subtitle={subject ? <>Stop alerting on <span className="mono subject-inline" title={subject}><PathText text={subject} max={56} /></span> when it is normal for you.</> : "Choose what to accept as normal. It stops alerting from the agent's next check-in."}
      footer={<><button className="btn" onClick={onClose}>Cancel</button>
        {(loading || options.length > 0) && <button className="btn primary" disabled={!sel || busy || loading || !note.trim()} onClick={submit}>{busy && <Loader2 size={14} className="spin" />}Add to allow list</button>}</>}>
      {loading ? <Loading block /> : opts.error && !preset ? <ErrorState error={opts.error} onRetry={opts.reload} /> : options.length === 0 ? (
        <Empty title="Nothing to allow for this alert"
          text={already ? "This alert is already covered by an allow-list entry." : "This alert was raised because it is closely connected to other detections in this incident. Allow those detections instead; this one usually goes away with them."} />
      ) : (
        <div className="form">
          {already && <div className="note">This alert is already covered by an allow-list entry.</div>}
          <div className="field">
            <span className="field-label">What to allow</span>
            <div className="opt-cards">{options.map((o, i) => (
              <label key={`${o.kind}|${o.value}|${o.rule}`} className={cx("role-opt opt-card", pick === i && "on")}>
                <input type="radio" name="allow-opt" checked={pick === i} onChange={() => setPick(i)} />
                <AllowKindIcon kind={o.kind} />
                <span className="min0"><b className="opt-title" title={o.title}><PathText text={o.title} max={60} /></b><span className="muted sm">{o.text}</span></span>
              </label>
            ))}</div>
          </div>
          <div className="field">
            <span className="field-label">Applies to</span>
            <div className="role-pick two">
              <label className={cx("role-opt", scope === "this" && "on")}><input type="radio" checked={scope === "this"} onChange={() => setScope("this")} /><span className="min0"><b>This endpoint</b><span className="muted sm ellipsis" title={endpoint.name}>Only {endpoint.name}</span></span></label>
              <label className={cx("role-opt", scope === "all" && "on")}><input type="radio" checked={scope === "all"} onChange={() => setScope("all")} /><span><b>All endpoints</b><span className="muted sm">Including endpoints added later</span></span></label>
            </div>
          </div>
          <Field label="Reason" hint="Required: why this is normal. Recorded in the activity log; your organisation's admins are notified.">
            <input value={note} onChange={e => setNote(e.target.value)} maxLength={500} placeholder="e.g. Nightly backup job" />
          </Field>
          <ResolveBox checked={resolve} onChange={setResolve} />
          <ForceBox err={err} checked={force} onChange={setForce} />
          {err && <div className="err">{err}</div>}
        </div>
      )}
    </Dialog>
  );
}
