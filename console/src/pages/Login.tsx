import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, AuthConfig } from "../api";

export default function Login() {
  const [u, setU] = useState("admin"); const [p, setP] = useState(""); const [err, setErr] = useState("");
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const nav = useNavigate(); const loc = useLocation();
  useEffect(() => {
    api<AuthConfig>("/api/auth/config").then(setCfg).catch(() => setCfg({ sso: false, sso_label: "", password: true, password_policy: "enabled" }));
    const e = new URLSearchParams(loc.search).get("sso_error");
    if (e) setErr(e);
  }, [loc.search]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    try { await api("/api/login", { method: "POST", body: JSON.stringify({ username: u, password: p }) }); nav("/endpoints"); }
    catch (ex: any) { setErr(ex.message); }
  };
  return (
    <div className="login card">
      <h1>PDP Console</h1>
      {cfg?.sso && <a className="button primary sso" href="/api/oidc/login">{cfg.sso_label || "Sign in with SSO"}</a>}
      {cfg?.sso && cfg.password && <div className="muted sm or">{cfg.password_policy === "admin-only" ? "break-glass administrator sign-in" : "or"}</div>}
      {(!cfg || cfg.password) && <form onSubmit={submit}>
        <input value={u} onChange={e => setU(e.target.value)} placeholder="username" autoComplete="username" />
        <input value={p} onChange={e => setP(e.target.value)} placeholder="password" type="password" autoComplete="current-password" />
        <button className={cfg?.sso ? "" : "primary"}>Sign in</button>
      </form>}
      {err && <div className="err">{err}</div>}
    </div>
  );
}
