import { useMemo, useState } from "react";
import { KeyRound, Loader2, Lock, Mail, Pencil, Search, ShieldCheck, UserPlus } from "lucide-react";
import { del, Endpoint, Invite, InvitesResp, looksLikeEmail, NewInvite, Org, OrgResp, patch, post, Role, UserRow, UsersResp, useApi, useCan, useMe, useReloadMe } from "../api";
import { fmtDate, fmtDateTime, fmtIn, fmtRel, initials, plural, ROLE_INFO } from "../format";
import { Card, Confirm, CopyButton, CopyField, cx, Dialog, Empty, EndpointPicker, ErrorState, Field, Loading, Menu, PageHeader, useToast } from "../ui";

type UsersWithRoles = UsersResp & { roles?: { id: Role; text: string }[] };
const ROLES: Role[] = ["admin", "analyst", "viewer"];
const POLICY: Record<string, string> = {
  enabled: "Everyone can sign in with a password",
  "admin-only": "Only administrators can sign in with a password (break-glass)",
  disabled: "Password sign-in is turned off",
};

export default function Team() {
  const can = useCan(); const me = useMe(); const toast = useToast();
  const { data, error, loading, reload: reloadUsers } = useApi<UsersWithRoles>(can.manage_users ? "/api/users" : null);
  const eps = useApi<{ endpoints: Endpoint[] }>(can.manage_users ? "/api/endpoints" : null);
  const org = useApi<OrgResp>(can.manage_users || can.manage_org ? "/api/org" : null);
  const invites = useApi<InvitesResp>(can.manage_users ? "/api/invites" : null);
  const [adding, setAdding] = useState(false); const [editing, setEditing] = useState<UserRow | null>(null);
  const [resetting, setResetting] = useState<UserRow | null>(null); const [removing, setRemoving] = useState<UserRow | null>(null);
  const [inviting, setInviting] = useState(false); const [revoking, setRevoking] = useState<Invite | null>(null);
  const [q, setQ] = useState("");
  const roleText = (r: Role) => data?.roles?.find(x => x.id === r)?.text || ROLE_INFO[r]?.describe || "";
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (data?.users || []).filter(u => !t || [u.username, u.display_name, u.email].some(x => (x || "").toLowerCase().includes(t)));
  }, [data, q]);
  if (!can.manage_users && !can.manage_org) return <div className="page"><PageHeader title="Team" /><ErrorState error={{ message: "Only administrators can manage the team.", status: 403 }} /></div>;
  const sso = data?.sso;
  // the organisation card counts users and invites, so it follows every change
  const reload = () => { reloadUsers(); org.reload(); };
  const reloadInvites = () => { invites.reload(); org.reload(); };
  const setDisabled = async (u: UserRow, disabled: boolean) => {
    try { await patch(`/api/users/${u.id}`, { disabled }); toast(disabled ? `${name(u)} can no longer sign in` : `${name(u)} can sign in again`); reload(); }
    catch (e: any) { toast(e.message, "err"); }
  };
  const pending = invites.data?.invites || [];
  return (
    <div className="page">
      <PageHeader title="Team" subtitle="Who can use the console, what they can do, and which endpoints they see."
        actions={can.manage_users && <>
          <button className="btn" onClick={() => setAdding(true)}><UserPlus size={16} />Add user</button>
          <button className="btn primary" onClick={() => setInviting(true)}><Mail size={16} />Invite people</button>
        </>} />
      <OrgCard org={org.data?.org || null} loading={org.loading} error={org.error} reload={org.reload} canEdit={can.manage_org} />
      {sso && <div className="grid grid-2 auth-cards">
        <div className="auth-card">
          <span className={cx("auth-icon", sso.enabled ? "ok" : "muted")}><ShieldCheck size={18} /></span>
          <div><div className="auth-title">Single sign-on {sso.enabled ? <span className="pill ok">Enabled</span> : <span className="pill">Not configured</span>}</div>
            <div className="muted sm">{sso.enabled ? <>Users click “{sso.label}”. Their account is created at first sign-in and their role comes from their identity-provider groups.</> : "Configure an OpenID Connect identity provider on the server to let users sign in with their company account."}</div></div>
        </div>
        <div className="auth-card">
          <span className={cx("auth-icon", sso.password_policy === "disabled" ? "muted" : "info")}><KeyRound size={18} /></span>
          <div><div className="auth-title">Password sign-in</div><div className="muted sm">{POLICY[sso.password_policy] || sso.password_policy}. Passwords need at least 10 characters.</div></div>
        </div>
      </div>}
      {can.manage_users && <Card pad={false}>
        <div className="filters">
          <div className="search"><Search size={15} /><input placeholder="Search users" value={q} onChange={e => setQ(e.target.value)} /></div>
          <div className="filters-end muted">{data ? plural(rows.length, "user") : ""}</div>
        </div>
        {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
          rows.length === 0 ? <Empty title="No users match" /> : (
            <div className="table-wrap">
              <table className="table middle">
                <thead><tr><th>User</th><th style={{ width: 120 }}>Role</th><th style={{ width: "22%" }}>Endpoint access</th><th className="hide-narrow" style={{ width: 110 }}>Sign-in</th><th style={{ width: 140 }}>Last sign-in</th><th style={{ width: 100 }}>Status</th><th style={{ width: 52 }}></th></tr></thead>
                <tbody>{rows.map(u => {
                  const self = me?.user_id === u.id;
                  return (
                    <tr key={u.id} className={cx(u.disabled && "row-muted")}>
                      <td className="cell-main">
                        <div className="user-cell"><span className="avatar sm">{initials(name(u))}</span>
                          <div className="min0"><div className="row-title plain ellipsis">{name(u)}{self && <span className="muted"> (you)</span>}</div>
                            {meta(u) && <div className="muted sm ellipsis">{meta(u)}</div>}</div></div>
                      </td>
                      <td><span className={`role role-${u.role}`} title={roleText(u.role)}>{ROLE_INFO[u.role]?.label || u.role}</span></td>
                      <td><EndpointScope role={u.role} endpoints={u.endpoints} /></td>
                      <td className="hide-narrow">{u.auth === "oidc" ? <span className="pill info">SSO</span> : <span className="pill">Password</span>}</td>
                      <td title={u.last_login ? fmtDateTime(u.last_login, true) : ""}>{u.last_login ? fmtRel(u.last_login) : <span className="muted">Never</span>}</td>
                      <td>{u.disabled ? <span className="pill bad"><Lock size={12} />Disabled</span> : <span className="pill ok">Active</span>}</td>
                      <td className="row-actions">
                        <Menu items={[
                          { label: "Edit", onClick: () => setEditing(u) },
                          u.auth === "local" && { label: "Reset password", onClick: () => setResetting(u) },
                          u.disabled ? { label: "Enable", onClick: () => setDisabled(u, false) } : { label: "Disable", onClick: () => setDisabled(u, true), disabled: self, title: self ? "You cannot disable yourself" : undefined },
                          { label: "Remove", danger: true, onClick: () => setRemoving(u), disabled: self, title: self ? "You cannot remove yourself" : undefined },
                        ]} />
                      </td>
                    </tr>
                  );
                })}</tbody>
              </table>
            </div>
          )}
      </Card>}
      {can.manage_users && <Card title="Pending invites" pad={false}
        subtitle="Invite links work once and are valid for 7 days. PDP does not send e-mail: you pass the link on yourself."
        actions={pending.length > 0 && <button className="btn sm" onClick={() => setInviting(true)}><Mail size={14} />Invite people</button>}>
        {invites.loading && !invites.data ? <Loading block /> : invites.error && !invites.data ? <div className="pad"><ErrorState error={invites.error} onRetry={invites.reload} /></div> :
          pending.length === 0 ? <Empty icon={<Mail size={22} />} title="No pending invites"
            text="Create an invite link for each person who should use the console. They choose their own name and password."
            action={<button className="btn primary" onClick={() => setInviting(true)}><Mail size={16} />Invite people</button>} /> : (
            <div className="table-wrap">
              <table className="table middle min-wide">
                <thead><tr><th>Invite for</th><th style={{ width: 120 }}>Role</th><th style={{ width: "18%" }}>Endpoint access</th><th className="hide-narrow" style={{ width: 150 }}>Created</th><th style={{ width: 110 }}>Expires</th><th style={{ width: 210 }}></th></tr></thead>
                <tbody>{pending.map(i => (
                  <tr key={i.id}>
                    <td className="cell-main">{i.email ? <span className="row-title plain ellipsis" title={i.email}>{i.email}</span> : <span className="muted">Anyone with the link</span>}</td>
                    <td><span className={`role role-${i.role}`} title={roleText(i.role)}>{ROLE_INFO[i.role]?.label || i.role}</span></td>
                    <td><EndpointScope role={i.role} endpoints={i.endpoints} /></td>
                    <td className="hide-narrow" title={fmtDateTime(i.created_at, true)}><div>{fmtRel(i.created_at)}</div>{i.created_by && <div className="muted sm ellipsis">by {i.created_by}</div>}</td>
                    <td title={fmtDateTime(i.expires_at, true)}>{fmtIn(i.expires_at)}</td>
                    <td className="row-actions">
                      <CopyButton value={i.link} label="Copy link" title={i.link} />
                      <button className="btn sm ghost danger-text" onClick={() => setRevoking(i)}>Revoke</button>
                    </td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
      </Card>}
      {inviting && <InviteDialog roleText={roleText} eps={eps.data?.endpoints || []} onClose={() => setInviting(false)} onDone={reloadInvites} />}
      {revoking && <Confirm danger title="Revoke this invite?" confirmLabel="Revoke invite" onClose={() => setRevoking(null)}
        text={<p>The link {revoking.email ? <>for {revoking.email} </> : null}stops working immediately. You can create a new invite at any time.</p>}
        onConfirm={async () => { await del(`/api/invites/${revoking.id}`); toast("Invite revoked"); reloadInvites(); }} />}
      {adding && <UserDialog roleText={roleText} eps={eps.data?.endpoints || []} sso={!!sso?.enabled} onClose={() => setAdding(false)} onDone={reload} />}
      {editing && <UserDialog user={editing} self={me?.user_id === editing.id} roleText={roleText} eps={eps.data?.endpoints || []} sso={!!sso?.enabled} onClose={() => setEditing(null)} onDone={reload} />}
      {resetting && <ResetDialog user={resetting} onClose={() => setResetting(null)} />}
      {removing && <Confirm danger title={`Remove ${name(removing)}?`} confirmLabel="Remove user" onClose={() => setRemoving(null)}
        text={<p>{name(removing)} will lose access to the console immediately.{removing.auth === "oidc" ? " Because they use single sign-on, they get a new account the next time they sign in unless they are also removed from the identity provider's PDP groups." : ""}</p>}
        onConfirm={async () => { await del(`/api/users/${removing.id}`); toast(`${name(removing)} removed`); reload(); }} />}
    </div>
  );
}

const name = (u: UserRow) => u.display_name || u.username;
/** Second line under the name: the username and email, each once (self-service accounts use the email as username). */
const meta = (u: UserRow) => [...new Set([u.display_name && u.display_name !== u.username ? u.username : null, u.email].filter(Boolean))].join(" · ");

function EndpointScope({ role, endpoints }: { role: Role; endpoints: { id: string; name: string }[] | null }) {
  if (role === "admin" || !endpoints) return <span>All endpoints</span>;
  return <span className="ellipsis" title={endpoints.map(e => e.name).join(", ")}>{endpoints.length === 0 ? <span className="muted">None</span> : endpoints.map(e => e.name).join(", ")}</span>;
}

/** "All endpoints" or a picked list; shared by the user and invite dialogs. */
function ScopeField({ scope, setScope, picked, setPicked, eps }: { scope: "all" | "some"; setScope: (s: "all" | "some") => void; picked: Set<string>; setPicked: (s: Set<string>) => void; eps: Endpoint[] }) {
  return (
    <div className="field">
      <span className="field-label">Endpoint access</span>
      <div className="role-pick two">
        <label className={cx("role-opt", scope === "all" && "on")}><input type="radio" checked={scope === "all"} onChange={() => setScope("all")} /><span><b>All endpoints</b><span className="muted sm">Including endpoints added later</span></span></label>
        <label className={cx("role-opt", scope === "some" && "on")}><input type="radio" checked={scope === "some"} onChange={() => setScope("some")} /><span><b>Selected endpoints</b><span className="muted sm">Only these; others stay invisible</span></span></label>
      </div>
      {scope === "some" && <EndpointPicker eps={eps} picked={picked} setPicked={setPicked} />}
    </div>
  );
}

// ---------------------------------------------------------------- organisation

function OrgCard({ org, loading, error, reload, canEdit }: { org: Org | null; loading: boolean; error: { message: string; status?: number } | null; reload: () => void; canEdit: boolean }) {
  const [renaming, setRenaming] = useState(false);
  if (loading && !org) return <Card title="Organisation"><Loading /></Card>;
  if (error && !org) return <Card title="Organisation"><ErrorState error={error} onRetry={reload} /></Card>;
  if (!org) return null;
  const max = org.max_endpoints || 0;
  const pct = max > 0 ? Math.min(100, (100 * org.endpoints) / max) : 0;
  const full = max > 0 && (org.endpoint_usage ?? org.endpoints) >= max;   // the limit also counts unused install tokens
  return (
    <Card title="Organisation" actions={canEdit && <button className="btn sm" onClick={() => setRenaming(true)}><Pencil size={14} />Rename</button>}>
      <dl className="org-facts">
        <div className="org-fact-name"><dt>Name</dt><dd className="org-title" title={org.name}>{org.name}</dd></div>
        <div>
          <dt>Endpoints</dt>
          <dd>{max > 0 ? <>{org.endpoints.toLocaleString()} of {plural(max, "endpoint")}</> : plural(org.endpoints, "endpoint")}</dd>
          {max > 0 && <div className={cx("bar usage", full ? "full" : pct >= 80 && "near")}><span style={{ width: `${pct}%` }} /></div>}
          {full && <div className="muted sm">Limit reached. Contact PDP support to add more.</div>}
        </div>
        <div><dt>Users</dt><dd>{plural(org.users, "user")}</dd>{org.pending_invites > 0 && <div className="muted sm">{plural(org.pending_invites, "invite")} pending</div>}</div>
        <div><dt>Created</dt><dd title={fmtDateTime(org.created_at, true)}>{fmtDate(org.created_at)}</dd></div>
      </dl>
      {renaming && <RenameOrgDialog org={org} onClose={() => setRenaming(false)} onDone={reload} />}
    </Card>
  );
}

function RenameOrgDialog({ org, onClose, onDone }: { org: Org; onClose: () => void; onDone: () => void }) {
  const toast = useToast(); const reloadMe = useReloadMe();
  const [v, setV] = useState(org.name); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try { await patch<OrgResp>("/api/org", { name: v.trim() }); toast("Organisation renamed"); onDone(); reloadMe(); onClose(); }
    catch (ex: any) { setErr(ex.message); setBusy(false); }
  };
  return (
    <Dialog title="Rename organisation" width={460} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="org-form" disabled={!v.trim() || v.trim() === org.name || busy}>{busy && <Loader2 size={14} className="spin" />}Save</button></>}>
      <form id="org-form" onSubmit={submit} className="form">
        <Field label="Organisation name" hint="Everyone in your organisation sees this name."><input value={v} onChange={e => setV(e.target.value)} maxLength={128} autoFocus /></Field>
        {err && <div className="err">{err}</div>}
      </form>
    </Dialog>
  );
}

// ---------------------------------------------------------------- invites

function InviteDialog({ roleText, eps, onClose, onDone }: { roleText: (r: Role) => string; eps: Endpoint[]; onClose: () => void; onDone: () => void }) {
  const [email, setEmail] = useState(""); const [role, setRole] = useState<Role>("analyst");
  const [scope, setScope] = useState<"all" | "some">("all"); const [picked, setPicked] = useState<Set<string>>(new Set());
  const [made, setMade] = useState<Invite | null>(null);
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const emailBad = !!email.trim() && !looksLikeEmail(email);
  const valid = !emailBad && (role === "admin" || scope === "all" || picked.size > 0);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); if (!valid) return;
    setErr(""); setBusy(true);
    const body: NewInvite = { role, endpoints: role === "admin" || scope === "all" ? null : [...picked] };
    if (email.trim()) body.email = email.trim();
    try { const r = await post<{ ok: true; invite: Invite }>("/api/invites", body); setMade(r.invite); onDone(); }
    catch (ex: any) { setErr(ex.message); }
    setBusy(false);
  };
  const again = () => { setMade(null); setEmail(""); setErr(""); };
  if (made) return (
    <Dialog title="Invite link created" width={600} onClose={onClose}
      subtitle={made.email ? `Send this link to ${made.email}.` : "Send this link to the person you are inviting."}
      footer={<><button className="btn" onClick={again}>Invite someone else</button><button className="btn primary" onClick={onClose}>Done</button></>}>
      <CopyField label="Invite link" value={made.link} multiline />
      <div className="install-note">
        The link is valid for 7 days (until {fmtDateTime(made.expires_at)}) and works once. Whoever opens it joins as {ROLE_INFO[made.role]?.label.toLowerCase() || made.role}
        {made.email ? <> with the address {made.email}</> : null}. PDP does not send e-mail; share the link the way you normally would.
      </div>
    </Dialog>
  );
  return (
    <Dialog title="Invite people" width={600} onClose={onClose}
      subtitle="Creates a link to join your organisation. The person chooses their own name and password."
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="invite-form" disabled={!valid || busy}>{busy && <Loader2 size={14} className="spin" />}Create invite link</button></>}>
      <form id="invite-form" onSubmit={submit} className="form">
        <Field label="Email" hint="Optional. With an address, only that person can use the link. Leave empty for a link anyone can use once."
          error={emailBad ? "This does not look like an email address." : null}>
          <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="name@company.com" autoComplete="off" autoFocus />
        </Field>
        <div className="field">
          <span className="field-label">Role</span>
          <div className="role-pick">{ROLES.map(r => (
            <label key={r} className={cx("role-opt", role === r && "on")}>
              <input type="radio" name="invite-role" checked={role === r} onChange={() => setRole(r)} />
              <span><b>{ROLE_INFO[r].label}</b><span className="muted sm">{roleText(r)}</span></span>
            </label>
          ))}</div>
        </div>
        {role !== "admin" ? <ScopeField scope={scope} setScope={setScope} picked={picked} setPicked={setPicked} eps={eps} /> : <div className="note">Admins always see all endpoints.</div>}
        {err && <div className="err">{err}</div>}
      </form>
    </Dialog>
  );
}

function UserDialog({ user, self, roleText, eps, sso, onClose, onDone }: { user?: UserRow; self?: boolean; roleText: (r: Role) => string; eps: Endpoint[]; sso: boolean; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const edit = !!user; const isSso = user?.auth === "oidc";
  const [f, setF] = useState({ username: user?.username || "", display_name: user?.display_name || "", email: user?.email || "", role: (user?.role || "analyst") as Role, password: "" });
  const [scope, setScope] = useState<"all" | "some">(user?.endpoints ? "some" : "all");
  const [picked, setPicked] = useState<Set<string>>(new Set((user?.endpoints || []).map(e => e.id)));
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const valid = (edit || (/^[A-Za-z0-9_.@-]{2,64}$/.test(f.username) && f.password.length >= 10)) && (f.role === "admin" || scope === "all" || picked.size > 0);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    const endpoints = f.role === "admin" || scope === "all" ? null : [...picked];
    try {
      if (edit) {
        const body: Record<string, unknown> = { display_name: f.display_name || null, email: f.email || null, endpoints };
        if (!isSso && f.role !== user!.role) body.role = f.role;
        await patch(`/api/users/${user!.id}`, body); toast(`${f.display_name || f.username} updated`);
      } else {
        await post("/api/users", { username: f.username, password: f.password, role: f.role, display_name: f.display_name || undefined, email: f.email || undefined, endpoints });
        toast(`${f.display_name || f.username} added`);
      }
      onDone(); onClose();
    } catch (ex: any) { setErr(ex.message); setBusy(false); }
  };
  return (
    <Dialog title={edit ? `Edit ${user!.display_name || user!.username}` : "Add user"} width={600} onClose={onClose}
      subtitle={edit ? (isSso ? "Signs in with single sign-on." : "Signs in with a password.") : sso ? "Creates a password account. People who use single sign-on do not need to be added: their account is created at their first sign-in, with the role from their identity-provider groups." : "Creates a password account."}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="user-form" disabled={!valid || busy}>{busy && <Loader2 size={14} className="spin" />}{edit ? "Save changes" : "Add user"}</button></>}>
      <form id="user-form" onSubmit={submit} className="form">
        <div className="form-row">
          <Field label="Username" hint={edit ? undefined : "Letters, digits and . _ @ -"}>
            <input value={f.username} disabled={edit} onChange={e => setF({ ...f, username: e.target.value })} autoComplete="off" autoFocus={!edit} />
          </Field>
          <Field label="Display name"><input value={f.display_name} onChange={e => setF({ ...f, display_name: e.target.value })} placeholder="Optional" /></Field>
        </div>
        <Field label="Email"><input type="email" value={f.email} onChange={e => setF({ ...f, email: e.target.value })} placeholder="Optional" /></Field>
        {!edit && <Field label="Initial password" hint="At least 10 characters. Ask the user to change it after their first sign-in.">
          <input type="password" value={f.password} onChange={e => setF({ ...f, password: e.target.value })} autoComplete="new-password" />
        </Field>}
        <div className="field">
          <span className="field-label">Role{isSso && <span className="muted"> — from the identity provider</span>}</span>
          <div className="role-pick">{ROLES.map(r => (
            <label key={r} className={cx("role-opt", f.role === r && "on", (isSso || (self && r !== "admin")) && "disabled")}>
              <input type="radio" name="role" checked={f.role === r} disabled={isSso || (self && r !== "admin")} onChange={() => setF({ ...f, role: r })} />
              <span><b>{ROLE_INFO[r].label}</b><span className="muted sm">{roleText(r)}</span></span>
            </label>
          ))}</div>
          {isSso && <span className="field-hint">SSO users get their role from their identity-provider groups at every sign-in.</span>}
          {self && !isSso && <span className="field-hint">You cannot change your own role.</span>}
        </div>
        {f.role !== "admin" && <ScopeField scope={scope} setScope={setScope} picked={picked} setPicked={setPicked} eps={eps} />}
        {f.role === "admin" && <div className="note">Admins always see all endpoints.</div>}
        {err && <div className="err">{err}</div>}
      </form>
    </Dialog>
  );
}

function ResetDialog({ user, onClose }: { user: UserRow; onClose: () => void }) {
  const toast = useToast();
  const [pw, setPw] = useState(""); const [pw2, setPw2] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr("");
    if (pw !== pw2) return setErr("The passwords do not match.");
    setBusy(true);
    try { await patch(`/api/users/${user.id}`, { password: pw }); toast(`Password of ${name(user)} reset`); onClose(); } catch (ex: any) { setErr(ex.message); setBusy(false); }
  };
  return (
    <Dialog title={`Reset password of ${name(user)}`} width={460} onClose={onClose}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" form="reset-form" disabled={pw.length < 10 || !pw2 || busy}>{busy && <Loader2 size={14} className="spin" />}Reset password</button></>}>
      <form id="reset-form" onSubmit={submit} className="form">
        <Field label="New password" hint="At least 10 characters."><input type="password" value={pw} onChange={e => setPw(e.target.value)} autoComplete="new-password" autoFocus /></Field>
        <Field label="Repeat new password"><input type="password" value={pw2} onChange={e => setPw2(e.target.value)} autoComplete="new-password" /></Field>
        {err && <div className="err">{err}</div>}
      </form>
    </Dialog>
  );
}

