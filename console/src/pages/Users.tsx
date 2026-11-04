import { useEffect, useState } from "react";
import { api, useMe, User } from "../api";

export default function Users() {
  const me = useMe();
  const [rows, setRows] = useState<User[]>([]); const [err, setErr] = useState(""); const [msg, setMsg] = useState("");
  const [form, setForm] = useState({ username: "", password: "", role: "analyst" });
  const load = () => api("/api/users").then(r => { setRows(r.users); setErr(""); }).catch((e: Error) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const add = async () => {
    setMsg(""); setErr("");
    if (form.password.length < 10) return setErr("password must be at least 10 characters");
    try { await api("/api/users", { method: "POST", body: JSON.stringify(form) }); setMsg(`created ${form.username}`); setForm({ username: "", password: "", role: "analyst" }); load(); }
    catch (e: any) { setErr(e.message); }
  };
  const del = async (u: User) => {
    if (!confirm(`Delete user ${u.username}? This cannot be undone.`)) return;
    setMsg(""); setErr("");
    try { await api(`/api/users/${u.id}`, { method: "DELETE" }); setMsg(`deleted ${u.username}`); load(); } catch (e: any) { setErr(e.message); }
  };
  return (
    <div>
      <h1>Users</h1>
      <div className="card">
        <b>Add user</b>{" "}
        <input value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} placeholder="username" autoComplete="off" />{" "}
        <input value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} placeholder="password (min 10 chars)" type="password" autoComplete="new-password" />{" "}
        <select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}><option value="analyst">analyst</option><option value="admin">admin</option></select>{" "}
        <button className="primary" onClick={add} disabled={!form.username || !form.password}>Create user</button>{" "}
        {msg && <span className="ok">{msg}</span>} {err && <span className="err">{err}</span>}
      </div>
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead>
        <tbody>{rows.map(u => {
          const self = me != null && String(u.id) === String(me.user_id);
          return <tr key={u.id}><td>{u.username} {self && <span className="muted">(you)</span>}</td><td><span className="pill">{u.role}</span></td>
            <td className="muted">{u.created_at ? new Date(u.created_at).toLocaleString() : ""}</td>
            <td><button className="ghost" disabled={self} title={self ? "you cannot delete yourself" : ""} onClick={() => del(u)}>delete</button></td></tr>;
        })}</tbody>
      </table>
    </div>
  );
}
