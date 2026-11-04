import { useMemo, useState } from "react";
import { Loader2, Lock, Search, UserPlus } from "lucide-react";
import { OperatorOrg, OperatorOrgsResp, patch, useApi, useCan, useMe } from "../api";
import { fmtDate, fmtDateTime, fmtRel, plural } from "../format";
import { Card, Confirm, CopyField, cx, Dialog, Empty, ErrorState, Field, Loading, Menu, PageHeader, useToast } from "../ui";

const MODE: Record<string, { label: string; tone: string; text: string }> = {
  open: { label: "Open", tone: "ok", text: "Anyone can create an organisation from the sign-in page." },
  code: { label: "Code required", tone: "info", text: "Clients need the sign-up code below to create an organisation. Give it only to clients you have agreed to host." },
  off: { label: "Closed", tone: "", text: "Nobody can create a new organisation. Existing organisations keep working and can still invite their own team." },
};

export default function Operator() {
  const me = useMe(); const can = useCan(); const toast = useToast();
  const allowed = !!me?.operator || can.operate;
  const { data, error, loading, reload } = useApi<OperatorOrgsResp>(allowed ? "/api/operator/orgs" : null, 60000);
  const [q, setQ] = useState("");
  const [toggling, setToggling] = useState<OperatorOrg | null>(null); const [limiting, setLimiting] = useState<OperatorOrg | null>(null);
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (data?.orgs || []).filter(o => !t || o.name.toLowerCase().includes(t))
      .sort((a, b) => Number(a.disabled) - Number(b.disabled) || a.name.localeCompare(b.name));
  }, [data, q]);
  if (!allowed) return <div className="page"><PageHeader title="Organisations" /><ErrorState error={{ message: "Only the platform operator can see this page.", status: 403 }} /></div>;
  const signup = data?.signup;
  const mode = MODE[signup?.mode || "off"] || MODE.off;
  const signupUrl = `${window.location.origin}/#/signup`;
  const total = data?.orgs.length || 0;
  return (
    <div className="page">
      <PageHeader title="Organisations" subtitle="Client organisations on this server and how much they use. You see their usage, never their incidents, alerts or activity." />
      {signup && <Card title="How clients sign up" subtitle={<>Sign-up: <span className={cx("pill", mode.tone)}>{mode.label}</span></>}>
        <p className="op-text">
          {mode.text}{signup.mode !== "off" && <> A client opens the sign-up page, creates their organisation and becomes its admin. They then install agents and invite their team themselves.</>}
          {" "}The sign-up mode and code are set in the server configuration.
        </p>
        {signup.mode !== "off" && <div className={cx("op-copy", signup.mode === "code" && signup.code && "two")}>
          <CopyField label="Sign-up page" value={signupUrl} />
          {signup.mode === "code" && signup.code && <CopyField label="Sign-up code" value={signup.code} />}
        </div>}
      </Card>}
      <Card pad={false}>
        <div className="filters">
          <div className="search"><Search size={15} /><input placeholder="Search organisations" value={q} onChange={e => setQ(e.target.value)} /></div>
          <div className="filters-end muted">{data ? plural(rows.length, "organisation") : ""}</div>
        </div>
        {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
          rows.length === 0 ? <Empty icon={total ? <Search size={22} /> : <UserPlus size={22} />} title={total ? "No organisations match" : "No organisations yet"}
            text={total ? "Try another search." : "Organisations appear here once clients sign up."} /> : (
            <div className="table-wrap">
              <table className="table middle op-table">
                <thead><tr>
                  <th>Organisation</th><th className="hide-narrow" style={{ width: 110 }}>Created</th><th className="num" style={{ width: 76 }}>Users</th>
                  <th style={{ width: 144 }}>Endpoints</th><th className="num" style={{ width: 116 }}>Alerts, 7 d</th>
                  <th style={{ width: 124 }}>Last activity</th><th style={{ width: 104 }}>Status</th><th style={{ width: 52 }}></th>
                </tr></thead>
                <tbody>{rows.map(o => {
                  const own = me?.org?.id != null && String(me.org.id) === String(o.id);
                  const full = o.max_endpoints > 0 && o.endpoints >= o.max_endpoints;
                  return (
                    <tr key={o.id} className={cx(o.disabled && "row-muted")}>
                      <td className="cell-main">
                        <div className="row-title plain wrap2" title={o.name}>{o.name}{own && <span className="muted"> (yours)</span>}</div>
                      </td>
                      <td className="hide-narrow" title={fmtDateTime(o.created_at, true)}>{fmtDate(o.created_at)}</td>
                      <td className="num">{o.users.toLocaleString()}</td>
                      <td>
                        <div><b>{o.endpoints_online.toLocaleString()}</b> <span className="muted">of {o.endpoints.toLocaleString()} online</span></div>
                        <div className={cx("sm", full ? "warn-text" : "muted")}>{full ? "at its limit of " : "limit "}{o.max_endpoints.toLocaleString()}</div>
                      </td>
                      <td className="num">{o.alerts_7d ? o.alerts_7d.toLocaleString() : <span className="muted">0</span>}</td>
                      <td title={o.last_activity ? fmtDateTime(o.last_activity, true) : ""}>{o.last_activity ? fmtRel(o.last_activity) : <span className="muted">None yet</span>}</td>
                      <td>{o.disabled ? <span className="pill bad"><Lock size={12} />Disabled</span> : <span className="pill ok">Active</span>}</td>
                      <td className="row-actions">
                        {can.operate && <Menu items={[
                          { label: "Change endpoint limit", onClick: () => setLimiting(o) },
                          o.disabled ? { label: "Enable", onClick: () => setToggling(o) }
                            : { label: "Disable", danger: true, onClick: () => setToggling(o), disabled: own, title: own ? "You cannot disable your own organisation" : undefined },
                        ]} />}
                      </td>
                    </tr>
                  );
                })}</tbody>
              </table>
            </div>
          )}
      </Card>
      {toggling && (toggling.disabled
        ? <Confirm title={`Enable ${toggling.name}?`} confirmLabel="Enable organisation" onClose={() => setToggling(null)}
          text={<p>Its users can sign in again.</p>}
          onConfirm={async () => { await patch(`/api/operator/orgs/${toggling.id}`, { disabled: false }); toast(`${toggling.name} enabled`); reload(); }} />
        : <Confirm danger title={`Disable ${toggling.name}?`} confirmLabel="Disable organisation" onClose={() => setToggling(null)}
          text={<><p>Its {plural(toggling.users, "user")} can no longer sign in to the console.</p><p>Its agents keep running and its data is kept. You can enable it again at any time.</p></>}
          onConfirm={async () => { await patch(`/api/operator/orgs/${toggling.id}`, { disabled: true }); toast(`${toggling.name} disabled`); reload(); }} />)}
      {limiting && <LimitDialog org={limiting} onClose={() => setLimiting(null)} onDone={reload} />}
    </div>
  );
}

function LimitDialog({ org, onClose, onDone }: { org: OperatorOrg; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [v, setV] = useState(String(org.max_endpoints)); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const n = Number(v);
  const valid = v.trim() !== "" && Number.isInteger(n) && n >= 0;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); if (!valid) return;
    setErr(""); setBusy(true);
    try { await patch(`/api/operator/orgs/${org.id}`, { max_endpoints: n }); toast(`${org.name} can now have up to ${plural(n, "endpoint")}`); onDone(); onClose(); }
    catch (ex: any) { setErr(ex.message); setBusy(false); }
  };
  return (
    <Dialog title={`Endpoint limit of ${org.name}`} width={460} onClose={onClose}
      subtitle={`Uses ${plural(org.endpoints, "endpoint")} now.`}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="limit-form" disabled={!valid || n === org.max_endpoints || busy}>{busy && <Loader2 size={14} className="spin" />}Save</button></>}>
      <form id="limit-form" onSubmit={submit} className="form">
        <Field label="Maximum number of endpoints" hint="Counts active endpoints and install commands not used yet. Lowering it below current use does not remove endpoints; it only stops new ones."
          error={v.trim() !== "" && !valid ? "Enter a whole number, 0 or more." : null}>
          <input type="number" min={0} step={1} value={v} onChange={e => setV(e.target.value)} autoFocus className="num-input" />
        </Field>
        {err && <div className="err">{err}</div>}
      </form>
    </Dialog>
  );
}
