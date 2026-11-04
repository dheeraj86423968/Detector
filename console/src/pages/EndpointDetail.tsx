import { useEffect, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { AlertTriangle, ArrowLeft, Check, CheckCircle2, ChevronRight, FlaskConical, Loader2, Plus, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { Check as CheckT, EndpointConfigResp, EndpointOverview, IncidentSummary, LifecycleStep, post, useApi, useCan } from "../api";
import { DailyBars } from "../chart";
import { DETECTION, fmtCompact, fmtDate, fmtDateTime, fmtNum, fmtRel, plural } from "../format";
import { IncidentTable } from "../incidents";
import { Card, Confirm, cx, DetectionTag, Empty, EndpointStateBadge, ErrorState, Loading, PageHeader, Tabs, Toggle, useToast } from "../ui";

type Tab = "overview" | "incidents" | "settings";

export default function EndpointDetail() {
  const { id } = useParams();
  const can = useCan();
  const [sp, setSp] = useSearchParams();
  const tab = (["incidents", "settings"].includes(sp.get("tab") || "") ? sp.get("tab") : "overview") as Tab;
  const [fast, setFast] = useState(false);
  const ov = useApi<EndpointOverview>(`/api/endpoints/${id}/overview`, fast ? 4000 : 30000);
  const running = !!ov.data?.check && ["queued", "running"].includes(ov.data.check.state);
  useEffect(() => { setFast(running); }, [running]);

  if (ov.loading && !ov.data) return <div className="page"><PageHeader title="Endpoint" crumbs={<Crumbs />} /><Loading block /></div>;
  if (ov.error && !ov.data) return <div className="page"><PageHeader title="Endpoint" crumbs={<Crumbs />} /><ErrorState error={ov.error.status === 404 ? "This endpoint does not exist or you do not have access to it." : ov.error} onRetry={ov.reload} /></div>;
  const d = ov.data!; const ep = d.endpoint;
  const retired = ep.state === "retired";
  return (
    <div className="page">
      <PageHeader crumbs={<Crumbs name={ep.name} />}
        title={<span className="ep-title">{ep.name}<EndpointStateBadge state={ep.state} text={ep.state_text} /></span>}
        subtitle={<div className="inc-meta">
          {ep.state_text && (!/^(offline|retired|protected)\b/i.test(ep.state_text) || /\d/.test(ep.state_text)) && <span className="meta-item">{ep.state_text}</span>}
          <span className="meta-item muted">{ep.hostname}{ep.os ? ` · ${ep.os === "linux" ? "Linux" : ep.os}` : ""}</span>
          {ep.agent_version && <span className="meta-item muted">Agent {ep.agent_version}</span>}
          <span className="meta-item muted">Last seen {fmtRel(ep.last_seen)}</span>
        </div>} />
      <Tabs value={tab} onChange={v => setSp(v === "overview" ? {} : { tab: v }, { replace: true })} tabs={[
        { id: "overview", label: "Overview" }, { id: "incidents", label: "Incidents", count: d.detection.incidents_total },
        ...(can.manage_endpoints && !retired ? [{ id: "settings" as Tab, label: "Settings" }] : []),
      ]} />
      {tab === "overview" && <OverviewTab d={d} reload={ov.reload} />}
      {tab === "incidents" && <IncidentsTab id={id!} />}
      {tab === "settings" && can.manage_endpoints && <SettingsTab id={id!} name={ep.name} />}
    </div>
  );
}

function Crumbs({ name }: { name?: string }) {
  return <><Link to="/endpoints"><ArrowLeft size={14} />Endpoints</Link>{name && <><ChevronRight size={14} className="muted" /><span>{name}</span></>}</>;
}

// ---------------------------------------------------------------- overview

const STEP_TITLE: Record<string, string> = { enrolled: "Enrolled", baseline: "Learning baseline", model: "Model trained", protecting: "Protecting" };

function OverviewTab({ d, reload }: { d: EndpointOverview; reload: () => void }) {
  const base = d.lifecycle.find(s => s.step === "baseline");
  const days = base?.days || [];
  return (
    <>
      <Card title="Is detection working on this endpoint?" subtitle="PDP learns what is normal on each endpoint, trains a model on it, then alerts on what departs from it.">
        <Stepper steps={d.lifecycle} />
        {days.length > 0 && <div className="baseline-days">
          <div className="sub-title">Activity recorded per baseline day</div>
          <DailyBars data={days.map(x => ({ date: x.date, value: x.events }))} unit={["event", "events"]} height={110} tick={fmtCompact} />
        </div>}
      </Card>
      <div className="grid grid-2">
        <HealthCard h={d.health} />
        <DetectionCard d={d} />
      </div>
      <CheckCard d={d} reload={reload} />
    </>
  );
}

function Stepper({ steps }: { steps: LifecycleStep[] }) {
  return (
    <ol className="stepper">
      {steps.map((s, i) => (
        <li key={s.step} className={cx("step", `s-${s.status}`)}>
          <div className="step-mark">{s.status === "done" ? <Check size={14} strokeWidth={3} /> : s.status === "active" ? (s.step === "protecting" ? <ShieldCheck size={14} /> : <Loader2 size={14} className="spin-slow" />) : <span>{i + 1}</span>}</div>
          <div className="step-body">
            <div className="step-title">{STEP_TITLE[s.step] || s.step}</div>
            <div className="step-text">{s.text}</div>
            {s.step === "baseline" && s.needed ? (
              <div className="step-progress">
                <div className="bar"><span style={{ width: `${Math.min(100, (100 * (s.done || 0)) / s.needed)}%` }} /></div>
                <span>{s.status === "done" ? `${s.needed} of ${s.needed} days` : `${s.done || 0} of ${s.needed} days complete`}</span>
              </div>
            ) : null}
            {s.step === "model" && s.details && Object.keys(s.details).length > 0 && s.status === "done" && (
              <div className="step-facts">
                {s.details.known_programs != null && <span>{plural(s.details.known_programs, "known program")}</span>}
                {s.details.trusted_addresses != null && <span>{plural(s.details.trusted_addresses, "trusted address", "trusted addresses")}</span>}
                {s.details.benign_rules != null && s.details.benign_rules > 0 && <span>{plural(s.details.benign_rules, "benign pattern")}</span>}
              </div>
            )}
            {s.at && <div className="step-at" title={fmtDateTime(s.at, true)}>{fmtDate(s.at)}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}

function HealthCard({ h }: { h: EndpointOverview["health"] }) {
  const tone = h.status === "ok" ? "ok" : h.status === "warning" ? "warn" : "bad";
  const head = h.status === "ok" ? "Agent healthy" : h.status === "warning" ? "Agent needs attention" : h.online ? "Agent has a problem" : "Agent is not reporting";
  return (
    <Card title="Agent health">
      <div className={cx("health-head", `tone-${tone}`)}>
        {h.status === "ok" ? <CheckCircle2 size={18} /> : h.status === "warning" ? <AlertTriangle size={18} /> : <XCircle size={18} />}
        <div><div className="health-title">{head}</div><div className="muted sm">Last report {fmtRel(h.last_seen)}</div></div>
      </div>
      {h.issues.filter(x => x.toLowerCase() !== head.toLowerCase()).length > 0 && <ul className="issues">{h.issues.filter(x => x.toLowerCase() !== head.toLowerCase()).map(x => <li key={x}>{x}</li>)}</ul>}
      <dl className="facts">
        <div><dt>Collector</dt><dd>{h.collector || "—"}</dd></div>
        <div><dt>Agent version</dt><dd className="mono">{h.agent_version || "—"}</dd></div>
        <div><dt>Events, last 24 h</dt><dd>{fmtCompact(h.events_24h)}</dd></div>
        <div><dt>Events dropped</dt><dd className={cx((h.events_dropped || 0) > 0 && "warn-text")}>{h.events_dropped == null ? "—" : fmtNum(h.events_dropped)}</dd></div>
        <div><dt>Upload queue</dt><dd>{h.queue_depth == null ? "—" : fmtNum(h.queue_depth)}</dd></div>
        <div><dt>CPU / memory</dt><dd>{h.cpu_pct == null ? "—" : `${h.cpu_pct.toFixed(1)} %`} · {h.rss_mb == null ? "—" : `${Math.round(h.rss_mb)} MB`}</dd></div>
      </dl>
    </Card>
  );
}

function DetectionCard({ d }: { d: EndpointOverview }) {
  const x = d.detection;
  const types = (["rules", "novelty", "corroborated", "learned"] as const).map(t => [t, x.by_type_7d[t] || 0] as const);
  const learning = d.endpoint.state === "learning" || d.endpoint.state === "training";
  return (
    <Card title="Detections" actions={<Link className="card-link" to={`?tab=incidents`}>Incidents <ChevronRight size={14} /></Link>}>
      <div className="det-top">
        <div><div className="big-num sm">{x.incidents_open}</div><div className="muted sm">open incidents</div></div>
        <div><div className="big-num sm">{x.incidents_total}</div><div className="muted sm">incidents in total</div></div>
        <div><div className="big-num sm">{x.alerts_7d}</div><div className="muted sm">alerts, last 7 days</div></div>
      </div>
      {learning && x.incidents_total === 0 ? <div className="note">Detection starts once the baseline is complete and the model is trained.</div> : <>
        <div className="sub-title">Alerts in the last 7 days, by kind</div>
        <ul className="type-list">{types.map(([t, n]) => (
          <li key={t} className={cx(n === 0 && "zero")}><DetectionTag type={t} /><span className="type-desc">{DETECTION[t].describe}</span><b>{n}</b></li>
        ))}</ul>
        <div className="sub-title">Review outcomes (all alerts)</div>
        <div className="triage-sum">
          <span><b>{fmtNum(x.triaged.true_positive)}</b> confirmed threats</span>
          <span><b>{fmtNum(x.triaged.false_positive)}</b> false alarms</span>
          <span><b>{fmtNum(x.triaged.open)}</b> awaiting review</span>
        </div>
      </>}
    </Card>
  );
}

function CheckCard({ d, reload }: { d: EndpointOverview; reload: () => void }) {
  const can = useCan(); const toast = useToast();
  const hist = useApi<{ checks: CheckT[] }>(`/api/endpoints/${d.endpoint.id}/checks`);
  const [busy, setBusy] = useState(false);
  const c = d.check;
  const running = !!c && (c.state === "queued" || c.state === "running");
  useEffect(() => { if (!running) hist.reload(); }, [running]); // eslint-disable-line react-hooks/exhaustive-deps
  const run = async () => {
    setBusy(true);
    try { await post(`/api/endpoints/${d.endpoint.id}/checks`, {}); toast("Detection check started"); reload(); hist.reload(); }
    catch (e: any) { toast(e.message, "err"); }
    setBusy(false);
  };
  const allowed = can.run_checks && d.can_run_check && !running && d.endpoint.state !== "retired";
  const blocked = !can.run_checks ? "Your role cannot run detection checks." : d.check_blocked_reason ? `Not available: ${d.check_blocked_reason}.` : running ? "A check is already running." : null;
  const past = (hist.data?.checks || []).filter(h => h.id !== c?.id || !running);
  return (
    <Card title="Detection check" subtitle="Replays realistic simulated attacks into this endpoint's own recorded activity and checks that its model catches them. Nothing runs on the host."
      actions={can.run_checks && d.endpoint.state !== "retired" && <button className="btn primary" disabled={!allowed || busy} onClick={run} title={blocked || undefined}>
        {busy || running ? <Loader2 size={15} className="spin" /> : <FlaskConical size={15} />}{running ? "Check running…" : "Run detection check"}</button>}>
      {!c ? (
        <Empty icon={<FlaskConical size={22} />} title="No detection check yet"
          text={d.check_blocked_reason ? `A check can run once the model is trained — ${d.check_blocked_reason}.` : "Run a check to see which attack types this endpoint's model detects."} />
      ) : running ? (
        <div className="verdict v-running"><Loader2 size={20} className="spin" /><div><div className="verdict-title">{c.state === "queued" ? "Check queued" : "Check running"}</div><div className="muted sm">Started {fmtRel(c.created_at)}. This usually takes a few minutes.</div></div></div>
      ) : c.state === "failed" ? (
        <div className="verdict v-fail"><XCircle size={20} /><div><div className="verdict-title">The check could not complete</div><div className="muted sm">{c.verdict_text || "Try again later."} · {fmtDateTime(c.created_at)}</div></div></div>
      ) : <>
        <div className={cx("verdict", `v-${c.verdict}`)}>
          {c.verdict === "pass" ? <ShieldCheck size={22} /> : c.verdict === "warn" ? <AlertTriangle size={22} /> : <XCircle size={22} />}
          <div><div className="verdict-title">{c.verdict_text}</div><div className="muted sm">Checked {fmtRel(c.finished_at || c.created_at)} · {fmtDateTime(c.finished_at || c.created_at)}</div></div>
          <div className="verdict-num"><b>{c.detected}</b>/{c.attacks}<span>detected</span></div>
        </div>
        {c.by_family.length > 0 && <div className="families">
          {c.by_family.map(f => {
            const ok = f.detected >= f.attacks;
            return (
              <div key={f.family} className="family">
                <span className={cx("fam-icon", ok ? "ok" : f.detected ? "warn" : "bad")}>{ok ? <Check size={13} strokeWidth={3} /> : f.detected ? <AlertTriangle size={13} /> : <XCircle size={13} />}</span>
                <span className="fam-label" title={f.label}>{f.label}</span>
                <span className="fam-bar"><span className={ok ? "ok" : "warn"} style={{ width: `${(100 * f.detected) / Math.max(1, f.attacks)}%` }} /></span>
                <span className="fam-n">{f.detected} of {f.attacks}</span>
              </div>
            );
          })}
        </div>}
      </>}
      {blocked && !allowed && !running && can.run_checks && d.check_blocked_reason && c && <div className="note">{blocked}</div>}
      {past.length > 1 && <details className="history">
        <summary>Earlier checks ({past.length - (c && !running ? 1 : 0)})</summary>
        <table className="table compact">
          <thead><tr><th>Date</th><th>Simulated attacks detected</th><th>False alarms on clean data</th><th>Result</th></tr></thead>
          <tbody>{past.filter(h => h.id !== c?.id).map(h => (
            <tr key={h.id}><td>{fmtDateTime(h.created_at)}</td><td>{h.state === "done" ? `${h.detected} of ${h.attacks}` : h.state}</td><td>{h.state === "done" ? h.false_alarms_on_clean_data : "—"}</td>
              <td>{h.state === "done" ? <span className={cx("verdict-pill", `v-${h.verdict}`)}>{h.verdict === "pass" ? "Pass" : h.verdict === "warn" ? "Partial" : "Fail"}</span> : <span className="muted">{h.state}</span>}</td></tr>
          ))}</tbody>
        </table>
      </details>}
    </Card>
  );
}

// ---------------------------------------------------------------- incidents

function IncidentsTab({ id }: { id: string }) {
  const { data, error, loading, reload } = useApi<{ incidents: IncidentSummary[] }>(`/api/incidents?endpoint_id=${id}&status=all&limit=500`, 30000);
  return (
    <Card pad={false}>
      {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
        !data!.incidents.length ? <Empty icon={<ShieldCheck size={22} />} title="No incidents on this endpoint" text="Incidents appear here when the endpoint's detection finds something." /> :
          <IncidentTable rows={data!.incidents} showEndpoint={false} />}
    </Card>
  );
}

// ---------------------------------------------------------------- settings (admin)

function SettingsTab({ id, name }: { id: string; name: string }) {
  const toast = useToast();
  const { data, error, loading, reload } = useApi<EndpointConfigResp>(`/api/endpoints/${id}`);
  const [prog, setProg] = useState(""); const [budget, setBudget] = useState<string>(""); const [retire, setRetire] = useState(false);
  const cfg = data?.endpoint.config || {};
  useEffect(() => { if (data) setBudget(String(cfg.learned_daily_budget ?? 20)); }, [data]); // eslint-disable-line react-hooks/exhaustive-deps
  if (loading && !data) return <Loading block />;
  if (error && !data) return <ErrorState error={error} onRetry={reload} />;
  const approved: string[] = cfg.approved_executables || [];
  const act = async (fn: () => Promise<unknown>, ok: string) => { try { await fn(); toast(ok); reload(); } catch (e: any) { toast(e.message, "err"); } };
  const setApproved = (x: string, approve: boolean) => act(() => post(`/api/endpoints/${id}/approved-executables`, { executables: [x], approve }), approve ? `${x} approved` : `Approval of ${x} revoked`);
  const learnedOn = cfg.learned_alerts ?? true;
  return (
    <div className="settings">
      <Card title="Approved programs" subtitle="Programs that never ran during the baseline raise a “New program” alert. Approve the ones you trust; this takes effect on the agent's next check-in without retraining.">
        <form className="inline-form" onSubmit={e => { e.preventDefault(); if (prog.trim()) setApproved(prog.trim(), true).then(() => setProg("")); }}>
          <input className="mono" placeholder="/opt/app/bin/tool" value={prog} onChange={e => setProg(e.target.value)} aria-label="Program path" />
          <button className="btn" disabled={!prog.trim().startsWith("/")}><Plus size={15} />Approve program</button>
        </form>
        {approved.length === 0 ? <div className="muted sm pad-y">No programs approved yet.</div> : (
          <ul className="prog-list">{approved.map(x => (
            <li key={x}><span className="mono ellipsis" title={x}>{x}</span><button className="btn sm ghost" onClick={() => setApproved(x, false)}><Trash2 size={14} />Revoke</button></li>
          ))}</ul>
        )}
      </Card>
      <Card title="Unusual-behaviour alerts" subtitle="Besides new programs and suspicious data flows, the learned model can raise alerts on its own for behaviour unlike the baseline.">
        <div className="setting-row">
          <div><div className="setting-name">Raise unusual-behaviour alerts</div><div className="muted sm">When off, the model only adds context to the other detections.</div></div>
          <Toggle checked={learnedOn} label="Raise unusual-behaviour alerts" onChange={v => act(() => post(`/api/endpoints/${id}/config`, { config: { learned_alerts: v } }), v ? "Unusual-behaviour alerts turned on" : "Unusual-behaviour alerts turned off")} />
        </div>
        <div className="setting-row">
          <div><div className="setting-name">Daily limit</div><div className="muted sm">At most this many unusual-behaviour alerts per day; the most unusual come first.</div></div>
          <form className="inline-form" onSubmit={e => { e.preventDefault(); const v = parseInt(budget, 10); if (!isNaN(v) && v >= 0) act(() => post(`/api/endpoints/${id}/config`, { config: { learned_daily_budget: v } }), `Daily limit set to ${v}`); }}>
            <input type="number" min={0} max={10000} value={budget} disabled={!learnedOn} onChange={e => setBudget(e.target.value)} style={{ width: 96 }} aria-label="Daily limit" />
            <button className="btn" disabled={!learnedOn || budget === String(cfg.learned_daily_budget ?? 20)}>Save</button>
          </form>
        </div>
      </Card>
      <Card title="Retire endpoint" className="danger-card">
        <div className="setting-row">
          <div><div className="setting-name">Retire {name}</div><div className="muted sm">The agent is no longer accepted and the endpoint's raw activity is deleted. This cannot be undone.</div></div>
          <button className="btn danger" onClick={() => setRetire(true)}>Retire endpoint</button>
        </div>
      </Card>
      {retire && <Confirm danger title={`Retire ${name}?`} confirmLabel="Retire endpoint" onClose={() => setRetire(false)}
        text={<p>The agent on <b>{name}</b> will no longer be accepted and its raw activity is deleted. This cannot be undone.</p>}
        onConfirm={async () => { await post(`/api/endpoints/${id}/retire`); toast(`${name} retired`); window.location.hash = `#/endpoints/${id}`; window.location.reload(); }} />}
    </div>
  );
}

