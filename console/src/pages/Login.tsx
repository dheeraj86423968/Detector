import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export default function Login() {
  const [u, setU] = useState("admin"); const [p, setP] = useState(""); const [err, setErr] = useState("");
  const nav = useNavigate();
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    try { await api("/api/login", { method: "POST", body: JSON.stringify({ username: u, password: p }) }); nav("/endpoints"); }
    catch (ex: any) { setErr(ex.message); }
  };
  return (
    <div className="login card">
      <h1>PDP Console</h1>
      <form onSubmit={submit}>
        <input value={u} onChange={e => setU(e.target.value)} placeholder="username" autoComplete="username" />
        <input value={p} onChange={e => setP(e.target.value)} placeholder="password" type="password" autoComplete="current-password" />
        <button className="primary">Sign in</button>
        {err && <div className="err">{err}</div>}
      </form>
    </div>
  );
}
