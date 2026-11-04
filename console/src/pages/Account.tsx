import { useState } from "react";
import { Loader2 } from "lucide-react";
import { post, useMe } from "../api";
import { initials, ROLE_INFO } from "../format";
import { Card, Field, PageHeader, useToast } from "../ui";

export default function Account() {
  const me = useMe(); const toast = useToast();
  const [f, setF] = useState({ old: "", next: "", repeat: "" }); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  if (!me) return null;
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr("");
    if (f.next.length < 10) return setErr("The new password must be at least 10 characters.");
    if (f.next !== f.repeat) return setErr("The new passwords do not match.");
    setBusy(true);
    try { await post("/api/me/password", { old_password: f.old, new_password: f.next }); toast("Password changed"); setF({ old: "", next: "", repeat: "" }); }
    catch (ex: any) { setErr(ex.message); }
    setBusy(false);
  };
  const name = me.display_name || me.username;
  const role = ROLE_INFO[me.role];
  return (
    <div className="page narrow">
      <PageHeader title="Your account" />
      <Card>
        <div className="profile">
          <span className="avatar lg">{initials(name)}</span>
          <div><div className="profile-name">{name}</div><div className="muted">{me.username}{me.email ? ` · ${me.email}` : ""}</div></div>
        </div>
        <dl className="facts two">
          <div><dt>Role</dt><dd><b>{role?.label || me.role}</b> — {role?.describe}</dd></div>
          <div><dt>Endpoint access</dt><dd>{me.endpoints == null ? "All endpoints" : `${me.endpoints.length} selected endpoint${me.endpoints.length === 1 ? "" : "s"}`}</dd></div>
          <div><dt>Sign-in method</dt><dd>{me.auth === "oidc" ? "Single sign-on" : "Password"}</dd></div>
        </dl>
      </Card>
      {me.auth === "oidc" ? (
        <Card title="Password"><p className="muted">You sign in with single sign-on. Your password and role are managed by your identity provider.</p></Card>
      ) : (
        <Card title="Change password">
          <form className="form narrow-form" onSubmit={submit}>
            <Field label="Current password"><input value={f.old} onChange={e => setF({ ...f, old: e.target.value })} type="password" autoComplete="current-password" /></Field>
            <Field label="New password" hint="At least 10 characters."><input value={f.next} onChange={e => setF({ ...f, next: e.target.value })} type="password" autoComplete="new-password" /></Field>
            <Field label="Repeat new password"><input value={f.repeat} onChange={e => setF({ ...f, repeat: e.target.value })} type="password" autoComplete="new-password" /></Field>
            {err && <div className="err">{err}</div>}
            <div><button className="btn primary" disabled={!f.old || !f.next || !f.repeat || busy}>{busy && <Loader2 size={14} className="spin" />}Change password</button></div>
          </form>
        </Card>
      )}
    </div>
  );
}
