import { useState } from "react";
import { Loader2 } from "lucide-react";
import { post, useMe, useReloadMe } from "../api";
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
    try { await post("/api/me/password", { old_password: f.old, new_password: f.next }); toast("Password changed; your other sessions were signed out"); setF({ old: "", next: "", repeat: "" }); }
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
      {me.auth !== "oidc" && <TwoFactor enabled={!!(me as any).mfa_enabled} required={!!(me as any).mfa_setup_required} />}
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
      <Sessions />
    </div>
  );
}

function Sessions() {
  const toast = useToast(); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const end = async () => {
    setErr(""); setBusy(true);
    try { await post("/api/me/sessions/end"); toast("Signed out everywhere else"); }
    catch (e: any) { setErr(e.message); }
    setBusy(false);
  };
  return (
    <Card title="Sessions">
      <p className="muted">Signed in on a computer you no longer use, or lost a device? End every other session of your account; this browser stays signed in. Changing your password does this too.</p>
      {err && <div className="err">{err}</div>}
      <div><button className="btn" onClick={end} disabled={busy}>{busy && <Loader2 size={14} className="spin" />}Sign out everywhere else</button></div>
    </Card>
  );
}

function TwoFactor({ enabled, required }: { enabled: boolean; required: boolean }) {
  const toast = useToast(); const reload = useReloadMe();
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState(""); const [codes, setCodes] = useState<string[] | null>(null);
  const [off, setOff] = useState({ password: "", code: "" }); const [err, setErr] = useState("");
  const start = async () => { setErr(""); try { setSetup(await post("/api/me/mfa/setup")); } catch (e: any) { setErr(e.message); } };
  const enable = async () => {
    setErr("");
    try { const r = await post<{ recovery_codes: string[] }>("/api/me/mfa/enable", { code }); setCodes(r.recovery_codes); setSetup(null); toast("Two-factor sign-in is on"); reload?.(); }
    catch (e: any) { setErr(e.message); }
  };
  const disable = async () => {
    setErr("");
    try { await post("/api/me/mfa/disable", off); toast("Two-factor sign-in is off"); setOff({ password: "", code: "" }); reload?.(); }
    catch (e: any) { setErr(e.message); }
  };
  return (
    <Card title="Two-factor sign-in">
      {required && !enabled && <div className="banner warn">Your organisation requires two-factor sign-in. Set it up to continue using the console.</div>}
      {codes ? (<>
        <p>Keep these recovery codes somewhere safe (a password manager). Each works once if you lose your phone; they are not shown again.</p>
        <pre className="codes">{codes.join("\n")}</pre>
        <button className="btn" onClick={() => setCodes(null)}>I have saved them</button>
      </>) : enabled ? (<>
        <p className="muted">On: after your password, the console asks for a code from your authenticator app.</p>
        <div className="form narrow-form">
          <Field label="Password"><input type="password" value={off.password} onChange={e => setOff({ ...off, password: e.target.value })} autoComplete="current-password" /></Field>
          <Field label="Current code"><input value={off.code} onChange={e => setOff({ ...off, code: e.target.value })} autoComplete="one-time-code" /></Field>
          <div><button className="btn" disabled={!off.password || off.code.length < 6} onClick={disable}>Turn off</button></div>
        </div>
      </>) : setup ? (<>
        <p>Add M.D Lab Detector to your authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, ...): open <a href={setup.otpauth_uri}>this link</a> on your phone, or enter the key by hand.</p>
        <Field label="Key"><code className="code-inline mono">{setup.secret.match(/.{1,4}/g)!.join(" ")}</code></Field>
        <div className="form narrow-form">
          <Field label="Code shown by the app"><input value={code} onChange={e => setCode(e.target.value)} autoComplete="one-time-code" placeholder="123456" /></Field>
          <div><button className="btn primary" disabled={code.trim().length !== 6} onClick={enable}>Turn on</button></div>
        </div>
      </>) : (<>
        <p className="muted">Off. With two-factor sign-in a stolen password alone does not open your account.</p>
        <button className="btn primary" onClick={start}>Set up two-factor sign-in</button>
      </>)}
      {err && <div className="err">{err}</div>}
    </Card>
  );
}
