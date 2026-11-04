import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { api, AuthConfig } from "../api";

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

export default function Login() {
  const [u, setU] = useState(""); const [p, setP] = useState(""); const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const nav = useNavigate(); const loc = useLocation();
  useEffect(() => {
    api<AuthConfig>("/api/auth/config").then(setCfg).catch(() => setCfg({ sso: false, sso_label: "", password: true, password_policy: "enabled" }));
    const e = new URLSearchParams(loc.search).get("sso_error");
    if (e) setErr(e);
  }, [loc.search]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try { await api("/api/login", { method: "POST", body: JSON.stringify({ username: u, password: p }) }); nav("/overview"); }
    catch (ex: any) { setErr(ex.status === 401 ? "Incorrect username or password." : ex.message); setBusy(false); }
  };
  const showPw = !cfg || cfg.password;
  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand"><Logo size={40} /><div><div className="login-name">PDP</div><div className="login-tag">Provenance-based intrusion detection</div></div></div>
        <h1 className="login-title">Sign in to the console</h1>
        {cfg?.sso && <a className="btn primary block lg sso" href="/api/oidc/login">{cfg.sso_label || "Sign in with SSO"}</a>}
        {cfg?.sso && showPw && <div className="login-or"><span>{cfg.password_policy === "admin-only" ? "Administrator sign-in" : "or sign in with a password"}</span></div>}
        {showPw && <form onSubmit={submit} className="login-form">
          <label className="field"><span className="field-label">Username</span>
            <input value={u} onChange={e => setU(e.target.value)} autoComplete="username" autoFocus={!cfg?.sso} /></label>
          <label className="field"><span className="field-label">Password</span>
            <input value={p} onChange={e => setP(e.target.value)} type="password" autoComplete="current-password" /></label>
          <button className={cfg?.sso ? "btn block lg" : "btn primary block lg"} disabled={busy || !u || !p}>{busy && <Loader2 size={16} className="spin" />}Sign in</button>
        </form>}
        {err && <div className="err">{err}</div>}
      </div>
      <div className="login-foot">Trouble signing in? Contact your PDP administrator.</div>
    </div>
  );
}
