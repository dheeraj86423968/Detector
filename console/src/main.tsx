import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { HashRouter, Link, Navigate, Outlet, Route, Routes, useNavigate } from "react-router-dom";
import { api, Me, MeContext } from "./api";
import "./styles.css";
import Login from "./pages/Login";
import Endpoints from "./pages/Endpoints";
import EndpointDetail from "./pages/EndpointDetail";
import Alerts from "./pages/Alerts";
import AlertGraph from "./pages/AlertGraph";
import Jobs from "./pages/Jobs";
import Simulation from "./pages/Simulation";
import Incident from "./pages/Incident";
import Users from "./pages/Users";
import Account from "./pages/Account";

// layout route: mounted once per sign-in, so /api/me is fetched once
function Shell() {
  const nav = useNavigate();
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => { api<Me>("/api/me").then(setMe).catch(() => setMe(null)); }, []);
  const logout = async () => {
    const r = await api<{ end_session_url?: string | null }>("/api/logout", { method: "POST" }).catch(() => null);
    if (r?.end_session_url) window.location.href = r.end_session_url;   // also end the IdP session
    else nav("/login");
  };
  return (
    <MeContext.Provider value={me}>
      <div className="shell">
        <nav>
          <div className="brand">PDP</div>
          <Link to="/endpoints">Endpoints</Link>
          <Link to="/alerts">Alerts</Link>
          <Link to="/jobs">Jobs</Link>
          <Link to="/simulation">Simulation</Link>
          {me?.role === "admin" && <Link to="/users">Users</Link>}
          <div className="navfoot">
            {me && <div className="muted sm who">{me.username} <span className="pill">{me.role}</span></div>}
            <Link to="/account">Account</Link>
            <button className="link" onClick={logout}>Log out</button>
          </div>
        </nav>
        <main><Outlet /></main>
      </div>
    </MeContext.Provider>
  );
}

function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<Shell />}>
          <Route path="/endpoints" element={<Endpoints />} />
          <Route path="/endpoints/:id" element={<EndpointDetail />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:id" element={<AlertGraph />} />
          <Route path="/incident/:id" element={<Incident />} />
          <Route path="/jobs" element={<Jobs />} />
          <Route path="/simulation" element={<Simulation />} />
          <Route path="/users" element={<Users />} />
          <Route path="/account" element={<Account />} />
        </Route>
        <Route path="*" element={<Navigate to="/endpoints" replace />} />
      </Routes>
    </HashRouter>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
