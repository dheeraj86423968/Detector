import { useState } from "react";
import { api, useMe } from "../api";

export default function Account() {
  const me = useMe();
  const [f, setF] = useState({ old: "", next: "", repeat: "" }); const [err, setErr] = useState(""); const [msg, setMsg] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(""); setMsg("");
    if (f.next.length < 10) return setErr("new password must be at least 10 characters");
    if (f.next !== f.repeat) return setErr("new passwords do not match");
    try { await api("/api/me/password", { method: "POST", body: JSON.stringify({ old_password: f.old, new_password: f.next }) }); setMsg("password changed"); setF({ old: "", next: "", repeat: "" }); }
    catch (ex: any) { setErr(ex.message); }
  };
  return (
    <div>
      <h1>Account</h1>
      {me && <p className="muted">Signed in as <b>{me.username}</b> <span className="pill">{me.role}</span></p>}
      <div className="card">
        <h2 style={{ marginTop: 0 }}>Change password</h2>
        <form className="form" onSubmit={submit}>
          <input value={f.old} onChange={e => setF({ ...f, old: e.target.value })} placeholder="current password" type="password" autoComplete="current-password" />
          <input value={f.next} onChange={e => setF({ ...f, next: e.target.value })} placeholder="new password (min 10 chars)" type="password" autoComplete="new-password" />
          <input value={f.repeat} onChange={e => setF({ ...f, repeat: e.target.value })} placeholder="repeat new password" type="password" autoComplete="new-password" />
          <button className="primary" disabled={!f.old || !f.next || !f.repeat}>Change password</button>
          {err && <div className="err">{err}</div>}{msg && <div className="ok">{msg}</div>}
        </form>
      </div>
    </div>
  );
}
