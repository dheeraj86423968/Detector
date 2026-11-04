import { ReactNode, useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { api, AuthConfig, looksLikeEmail, PASSWORD_MIN } from "../api";
import { cx } from "../ui";

export function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg className="logo" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="8" fill="var(--accent)" />
      <circle cx="10" cy="11" r="3" fill="#fff" />
      <circle cx="22" cy="11" r="3" fill="#fff" opacity=".7" />
      <circle cx="16" cy="22" r="3.4" fill="#fff" />
      <path d="M11.8 13.3 14.6 19M20.2 13.3 17.4 19M13 11h6" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" opacity=".85" />
    </svg>
  );
}

/** The frame of the public pages (sign in, sign up, join): brand, one card, a line underneath. */
export function AuthFrame({ children, foot, wide }: { children: ReactNode; foot?: ReactNode; wide?: boolean }) {
  return (
    <div className="login-page">
      <div className={cx("login-card", wide && "wide")}>
        <div className="login-brand"><Logo size={40} /><div><div className="login-name">PDP</div><div className="login-tag">Provenance-based intrusion detection</div></div></div>
        {children}
      </div>
      {foot && <div className="login-foot">{foot}</div>}
    </div>
  );
}

/** Name, email and password checks shared by sign-up and joining (the server checks again). */
export type AccountFields = { name: string; email: string; password: string; confirm: string };
export function accountErrors(f: AccountFields): Partial<Record<keyof AccountFields, string>> {
  const e: Partial<Record<keyof AccountFields, string>> = {};
  if (!f.name.trim()) e.name = "Enter your name.";
  if (!f.email.trim()) e.email = "Enter your email address.";
  else if (!looksLikeEmail(f.email)) e.email = "This does not look like an email address.";
  if (f.password.length < PASSWORD_MIN) e.password = `Use at least ${PASSWORD_MIN} characters.`;
  if (!e.password && f.confirm !== f.password) e.confirm = "The passwords do not match.";
  return e;
}

/** After sign-up or joining the server has set the session: check it works, then open the console. */
export async function enterConsole(nav: (to: string) => void) {
  await api("/api/me");
  nav("/overview");
}

export default function Login() {
  const [u, setU] = useState(""); const [p, setP] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const [mfa, setMfa] = useState(false); const [code, setCode] = useState("");
  const [orgEmail, setOrgEmail] = useState("");
  const nav = useNavigate(); const loc = useLocation();
  useEffect(() => {
    api<AuthConfig>("/api/auth/config").then(setCfg).catch(() => setCfg({ sso: false, sso_label: "", password: true, password_policy: "enabled" }));
    const q = new URLSearchParams(loc.search);
    const e = q.get("sso_error") || q.get("error");
    if (e) setErr(e);
  }, [loc.search]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try {
      const r = await api<{ mfa_required?: boolean }>("/api/login", { method: "POST", body: JSON.stringify({ username: u, password: p }) });
      if (r.mfa_required) { setMfa(true); setBusy(false); return; }
      nav("/overview");
    }
    catch (ex: any) { setErr(ex.status === 401 ? "Incorrect email or password." : ex.message); setBusy(false); }
  };
  const submitCode = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try { await api("/api/login/mfa", { method: "POST", body: JSON.stringify({ code }) }); nav("/overview"); }
    catch (ex: any) { setErr(ex.message); setBusy(false); setCode(""); }
  };
  if (mfa) return (
    <AuthFrame foot="Lost your phone? Enter one of your recovery codes instead.">
      <h1 className="login-title">Two-factor sign-in</h1>
      <form onSubmit={submitCode} className="login-form">
        <label className="field"><span className="field-label">Code from your authenticator app</span>
          <input value={code} onChange={e => setCode(e.target.value)} autoComplete="one-time-code" inputMode="text" autoFocus placeholder="123456" /></label>
        <button className="btn primary block lg" disabled={busy || code.trim().length < 6}>{busy && <Loader2 size={16} className="spin" />}Verify</button>
      </form>
      {err && <div className="err">{err}</div>}
    </AuthFrame>
  );
  const showPw = !cfg || cfg.password;
  const signup = !!cfg?.signup && cfg.signup !== "off";
  return (
    <AuthFrame foot={signup ? <>New to PDP? <Link to="/signup">Create an organisation</Link></> : "Trouble signing in? Contact your PDP administrator."}>
      <h1 className="login-title">Sign in to the console</h1>
      {cfg?.sso && <a className="btn primary block lg sso" href="/api/oidc/login">{cfg.sso_label || "Sign in with SSO"}</a>}
      {(cfg as any)?.org_sso && <form className="login-form" onSubmit={e => { e.preventDefault(); window.location.href = `/api/sso/start?email=${encodeURIComponent(orgEmail.trim())}`; }}>
        <label className="field"><span className="field-label">Work email (single sign-on)</span>
          <input value={orgEmail} onChange={e => setOrgEmail(e.target.value)} type="email" autoComplete="email" placeholder="you@company.com" /></label>
        <button className="btn block lg" disabled={!orgEmail.includes("@")}>Continue with your company account</button>
        <div className="login-or"><span>or with a password</span></div>
      </form>}
      {cfg?.sso && showPw && <div className="login-or"><span>{cfg.password_policy === "admin-only" ? "Administrator sign-in" : "or sign in with a password"}</span></div>}
      {showPw && <form onSubmit={submit} className="login-form">
        <label className="field"><span className="field-label">Email or username</span>
          <input value={u} onChange={e => setU(e.target.value)} autoComplete="username" autoFocus={!cfg?.sso} /></label>
        <label className="field"><span className="field-label">Password</span>
          <input value={p} onChange={e => setP(e.target.value)} type="password" autoComplete="current-password" /></label>
        <button className={cfg?.sso ? "btn block lg" : "btn primary block lg"} disabled={busy || !u || !p}>{busy && <Loader2 size={16} className="spin" />}Sign in</button>
      </form>}
      {err && <div className="err">{err}</div>}
    </AuthFrame>
  );
}
