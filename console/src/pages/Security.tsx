import { useEffect, useState } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { api, del, useApi, useCan } from "../api";
import { fmtDateTime, fmtRel } from "../format";
import { Card, Field, Loading, PageHeader, Toggle, useToast } from "../ui";

type Org = { retention_days: number; require_mfa: boolean; sso: null | { provider: string; tenant?: string; issuer?: string; client_id: string;
  has_secret: boolean; domains: string[]; default_role: string; admin_emails: string[]; enabled: boolean } };
type Entry = { id: number; at: string; who: string | null; action: string; target: string | null; status: number | null; ip: string | null };

export default function Security() {
  const can = useCan(); const toast = useToast();
  const org = useApi<{ org: Org }>("/api/org");
  const log = useApi<{ entries: Entry[] }>("/api/audit?limit=300");
  const [ret, setRet] = useState<number | "">("");
  useEffect(() => { if (org.data) setRet(org.data.org.retention_days); }, [org.data]);
  if (!can.manage_org) return <div className="page"><PageHeader title="Security" /><Card><p className="muted">Only administrators manage security settings.</p></Card></div>;
  if (!org.data) return <div className="page"><Loading block /></div>;
  const o = org.data.org;
  const patch = async (body: any, done: string) => {
    try { await api("/api/org", { method: "PATCH", body: JSON.stringify(body) }); toast(done); org.reload(); } catch (e: any) { toast(e.message, "err"); }
  };
  return (
    <div className="page">
      <PageHeader title="Security" subtitle="Sign-in rules, single sign-on, how long data is kept, and who changed what." />
      <div className="grid grid-2">
        <Card title="Sign-in">
          <label className="inline-toggle"><Toggle checked={o.require_mfa} onChange={v => patch({ require_mfa: v }, v ? "Two-factor sign-in required" : "Two-factor sign-in optional")} label="Require two-factor sign-in" />
            Require two-factor sign-in for password accounts</label>
          <p className="muted sm">Users without it are asked to set it up at their next sign-in. Single sign-on accounts use your identity provider's.</p>
        </Card>
        <Card title="Data retention">
          <Field label="Keep alerts, incidents and the activity log for" hint="30 to 3650 days; older data is deleted every night.">
            <div className="row-gap"><input type="number" min={30} max={3650} value={ret} onChange={e => setRet(e.target.value ? Number(e.target.value) : "")} style={{ width: 110 }} /> days
              <button className="btn sm" disabled={ret === "" || ret === o.retention_days} onClick={() => patch({ retention_days: ret }, "Retention saved")}>Save</button></div>
          </Field>
        </Card>
      </div>
      <SSOCard sso={o.sso} reload={org.reload} />
      <Card title="Activity log" subtitle="Changes made in the console and sign-ins, newest first" pad={false}>
        {!log.data ? <Loading block /> : log.data.entries.length === 0 ? <p className="pad muted">Nothing yet.</p> : (
          <div className="table-wrap"><table className="table middle"><thead><tr><th style={{ width: 150 }}>When</th><th style={{ width: "18%" }}>Who</th><th>What</th><th style={{ width: 70 }}>Result</th><th style={{ width: 130 }}>From</th></tr></thead>
            <tbody>{log.data.entries.map(e => (
              <tr key={e.id}><td className="sm" title={fmtDateTime(e.at, true)}>{fmtRel(e.at)}</td><td className="ellipsis">{e.who || "—"}</td>
                <td className="sm"><span className="mono">{e.action}</span>{e.target && <div className="muted ellipsis">{e.target}</div>}</td>
                <td className={e.status && e.status >= 400 ? "err-text" : ""}>{e.status ?? ""}</td><td className="sm mono">{e.ip || ""}</td></tr>))}</tbody></table></div>
        )}
      </Card>
    </div>
  );
}

function SSOCard({ sso, reload }: { sso: Org["sso"]; reload: () => void }) {
  const toast = useToast();
  const [f, setF] = useState({ provider: sso?.provider || "google", tenant: sso?.tenant || "", issuer: sso?.issuer || "", client_id: sso?.client_id || "",
    client_secret: "", domains: (sso?.domains || []).join(", "), default_role: sso?.default_role || "viewer", admin_emails: (sso?.admin_emails || []).join(", "), enabled: sso?.enabled ?? true });
  const [err, setErr] = useState("");
  const save = async () => {
    setErr("");
    try {
      await api("/api/org/sso", { method: "PUT", body: JSON.stringify({ ...f, tenant: f.tenant || null, issuer: f.issuer || null, client_secret: f.client_secret || null,
        domains: f.domains.split(/[\s,;]+/).filter(Boolean), admin_emails: f.admin_emails.split(/[\s,;]+/).filter(Boolean) }) });
      toast("Single sign-on saved"); reload();
    } catch (e: any) { setErr(e.message); }
  };
  const callback = `${window.location.origin}/api/sso/callback`;
  return (
    <Card title={<><KeyRound size={16} /> Single sign-on</>} subtitle={sso?.enabled ? `On for ${sso.domains.join(", ")}` : "Your team signs in with its Google Workspace or Microsoft account"}>
      <div className="form">
        <Field label="Provider"><select value={f.provider} onChange={e => setF({ ...f, provider: e.target.value })}>
          <option value="google">Google Workspace</option><option value="microsoft">Microsoft Entra ID</option><option value="oidc">Other (OpenID Connect)</option></select></Field>
        {f.provider === "microsoft" && <Field label="Tenant id or primary domain"><input value={f.tenant} onChange={e => setF({ ...f, tenant: e.target.value })} placeholder="contoso.onmicrosoft.com" /></Field>}
        {f.provider === "oidc" && <Field label="Issuer URL"><input value={f.issuer} onChange={e => setF({ ...f, issuer: e.target.value })} placeholder="https://login.example.com" /></Field>}
        <Field label="Client id"><input value={f.client_id} onChange={e => setF({ ...f, client_id: e.target.value })} /></Field>
        <Field label="Client secret" hint={sso?.has_secret ? "Set. Enter a new one to replace it." : undefined}><input type="password" value={f.client_secret} onChange={e => setF({ ...f, client_secret: e.target.value })} autoComplete="new-password" /></Field>
        <Field label="Email domains" hint="Addresses in these domains sign in to your organisation through this provider."><input value={f.domains} onChange={e => setF({ ...f, domains: e.target.value })} placeholder="company.com" /></Field>
        <Field label="Role of new users"><select value={f.default_role} onChange={e => setF({ ...f, default_role: e.target.value })}><option value="viewer">Viewer</option><option value="analyst">Analyst</option></select></Field>
        <Field label="Administrators (emails)" hint="These people get the admin role on their first sign-in."><input value={f.admin_emails} onChange={e => setF({ ...f, admin_emails: e.target.value })} /></Field>
        <label className="inline-toggle"><Toggle checked={f.enabled} onChange={v => setF({ ...f, enabled: v })} label="Enabled" />Enabled</label>
        <p className="muted sm">Register this redirect address at your provider: <code className="code-inline">{callback}</code></p>
        {err && <div className="err">{err}</div>}
        <div className="row-gap"><button className="btn primary" onClick={save}><ShieldCheck size={15} />Save</button>
          {sso && <button className="btn ghost" onClick={async () => { await del("/api/org/sso"); toast("Single sign-on removed"); reload(); }}>Remove</button>}</div>
      </div>
    </Card>
  );
}
