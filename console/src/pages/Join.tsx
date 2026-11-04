import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Loader2, Link2Off } from "lucide-react";
import { AcceptInviteBody, ApiError, post, PublicInvite, useApi } from "../api";
import { fmtDate, ROLE_INFO } from "../format";
import { Field, Loading } from "../ui";
import { accountErrors, AuthFrame, enterConsole } from "./Login";

export default function Join() {
  const { token = "" } = useParams();
  const nav = useNavigate();
  const { data: inv, error, loading, reload } = useApi<PublicInvite>(token ? `/api/invites/${encodeURIComponent(token)}` : null);
  const [f, setF] = useState({ name: "", email: "", password: "", confirm: "" });
  const [tried, setTried] = useState(false);
  const [err, setErr] = useState<{ text: string; status: number } | null>(null); const [busy, setBusy] = useState(false);
  const [gone, setGone] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  if (loading && !inv) return <AuthFrame><Loading block /></AuthFrame>;
  if (!token || gone || (error && (error.status === 404 || error.status === 410))) return (
    <AuthFrame foot={<Link to="/login">Go to sign in</Link>}>
      <div className="login-state"><span className="login-state-icon"><Link2Off size={20} /></span>
        <div><h1 className="login-title">This invite link does not work</h1>
          <p className="login-text">It may have expired, been used already, or been withdrawn. Ask the person who invited you for a new link.</p></div></div>
    </AuthFrame>
  );
  if (error || !inv) return (
    <AuthFrame foot={<Link to="/login">Go to sign in</Link>}>
      <h1 className="login-title">Could not open this invite</h1>
      <p className="login-text">{error?.message || "Something went wrong."}</p>
      <button className="btn block" onClick={reload}>Try again</button>
    </AuthFrame>
  );

  const fixedEmail = inv.email || null;
  const fields = { ...f, email: fixedEmail || f.email };
  const errs: Record<string, string | undefined> = accountErrors(fields);
  const show = (k: string) => (tried ? errs[k] : undefined);
  const role = ROLE_INFO[inv.role];
  const label = (role?.label || inv.role).toLowerCase();
  const roleName = `${/^[aeiou]/.test(label) ? "an" : "a"} ${label}`;   // "an admin", "an analyst", "a viewer"
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setTried(true); setErr(null);
    if (Object.values(errs).some(Boolean)) return;
    setBusy(true);
    const body: AcceptInviteBody = { name: fields.name.trim(), email: fields.email.trim(), password: fields.password };
    try { await post(`/api/invites/${encodeURIComponent(token)}/accept`, body); }
    catch (ex: any) {
      const status = ex instanceof ApiError ? ex.status : 0;
      if (status === 404) { setGone(true); return; }
      setErr({ text: (ex instanceof ApiError && ex.detail) || (status === 409 ? "An account with this email address already exists." : ex.message), status });
      setBusy(false); return;
    }
    try { await enterConsole(nav); }
    catch { setErr({ text: "Your account was created, but you could not be signed in automatically. Sign in with your email and password.", status: 401 }); setBusy(false); }
  };
  return (
    <AuthFrame wide foot={<>Already have an account? <Link to="/login">Sign in</Link></>}>
      <h1 className="login-title">Join {inv.organisation} as {roleName}</h1>
      <p className="login-text">
        {inv.invited_by ? <>{inv.invited_by} invited you. </> : null}{role?.describe}
        <span className="muted"> This invite expires on {fmtDate(inv.expires_at)}.</span>
      </p>
      <form onSubmit={submit} className="login-form" noValidate>
        <Field label="Your name" error={show("name")}>
          <input value={f.name} onChange={set("name")} autoComplete="name" autoFocus maxLength={128} />
        </Field>
        <Field label="Email" hint={fixedEmail ? "The invite is for this address. You sign in with it." : "You sign in with this address."} error={show("email")}>
          {fixedEmail
            ? <input type="email" value={fixedEmail} readOnly disabled autoComplete="email" />
            : <input type="email" value={f.email} onChange={set("email")} autoComplete="email" maxLength={254} />}
        </Field>
        <div className="form-row">
          <Field label="Password" hint="At least 10 characters." error={show("password")}>
            <input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" />
          </Field>
          <Field label="Repeat password" error={show("confirm")}>
            <input type="password" value={f.confirm} onChange={set("confirm")} autoComplete="new-password" />
          </Field>
        </div>
        <button className="btn primary block lg" disabled={busy}>{busy && <Loader2 size={16} className="spin" />}Create account and join</button>
      </form>
      {err && <div className="err">{err.text}{(err.status === 409 || err.status === 401) && <> <Link to="/login">Sign in</Link></>}</div>}
    </AuthFrame>
  );
}
