import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { api, ApiError, AuthConfig, post, SignupBody } from "../api";
import { Field, Loading } from "../ui";
import { accountErrors, AuthFrame, enterConsole } from "./Login";

/** Used when the server gives no message of its own. */
const FALLBACK: Record<number, string> = {
  403: "Sign-up is not open, or the sign-up code is not correct.",
  409: "An account with this email address already exists.",
  429: "Too many sign-ups from your network. Try again later.",
};

export default function Signup() {
  const nav = useNavigate();
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const [f, setF] = useState({ organisation: "", name: "", email: "", password: "", confirm: "", code: "" });
  const [tried, setTried] = useState(false);
  const [err, setErr] = useState<{ text: string; status: number } | null>(null); const [busy, setBusy] = useState(false);
  useEffect(() => {
    api<AuthConfig>("/api/auth/config").then(setCfg).catch(() => setCfg({ sso: false, sso_label: "", password: true, password_policy: "enabled", signup: "off" }));
  }, []);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  if (!cfg) return <AuthFrame><Loading block /></AuthFrame>;
  const mode = cfg.signup || "off";
  if (mode === "off") return (
    <AuthFrame foot={<Link to="/login">Back to sign in</Link>}>
      <h1 className="login-title">Sign-up is closed</h1>
      <p className="login-text">New organisations cannot sign up on this server. If your team already uses M.D Lab Detector, ask your administrator for an invite link.</p>
    </AuthFrame>
  );

  const errs: Record<string, string | undefined> = {
    ...accountErrors(f),
    organisation: f.organisation.trim() ? undefined : "Enter the name of your organisation.",
    code: mode === "code" && !f.code.trim() ? "Enter the sign-up code you received." : undefined,
  };
  const show = (k: string) => (tried ? errs[k] : undefined);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setTried(true); setErr(null);
    if (Object.values(errs).some(Boolean)) return;
    setBusy(true);
    const body: SignupBody = { organisation: f.organisation.trim(), name: f.name.trim(), email: f.email.trim(), password: f.password };
    if (mode === "code") body.code = f.code.trim();
    try { await post("/api/signup", body); }
    catch (ex: any) {
      const status = ex instanceof ApiError ? ex.status : 0;
      setErr({ text: (ex instanceof ApiError && ex.detail) || FALLBACK[status] || ex.message, status }); setBusy(false); return;
    }
    try { await enterConsole(nav); }
    catch { setErr({ text: "Your organisation was created, but you could not be signed in automatically. Sign in with your email and password.", status: 401 }); setBusy(false); }
  };
  return (
    <AuthFrame wide foot={<>Already have an account? <Link to="/login">Sign in</Link></>}>
      <h1 className="login-title">Create an organisation</h1>
      <p className="login-text">You become its administrator. Next you install the agent on your servers and invite your team.</p>
      <form onSubmit={submit} className="login-form" noValidate>
        <Field label="Organisation name" error={show("organisation")}>
          <input value={f.organisation} onChange={set("organisation")} autoComplete="organization" autoFocus maxLength={128} placeholder="Acme Ltd" />
        </Field>
        <Field label="Your name" error={show("name")}>
          <input value={f.name} onChange={set("name")} autoComplete="name" maxLength={128} />
        </Field>
        <Field label="Work email" hint="You sign in with this address." error={show("email")}>
          <input type="email" value={f.email} onChange={set("email")} autoComplete="email" maxLength={254} />
        </Field>
        <div className="form-row">
          <Field label="Password" hint="At least 10 characters." error={show("password")}>
            <input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" />
          </Field>
          <Field label="Repeat password" error={show("confirm")}>
            <input type="password" value={f.confirm} onChange={set("confirm")} autoComplete="new-password" />
          </Field>
        </div>
        {mode === "code" && <Field label="Sign-up code" hint="You received this code from us." error={show("code")}>
          <input value={f.code} onChange={set("code")} autoComplete="off" spellCheck={false} />
        </Field>}
        <button className="btn primary block lg" disabled={busy}>{busy && <Loader2 size={16} className="spin" />}Create organisation</button>
      </form>
      {err && <div className="err">{err.text}{(err.status === 409 || err.status === 401) && <> <Link to="/login">Sign in</Link></>}</div>}
    </AuthFrame>
  );
}
