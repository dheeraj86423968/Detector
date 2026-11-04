import React, { lazy, Suspense, useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { HashRouter, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { LayoutDashboard, LogOut, Server, ShieldAlert, UserCog, Users } from "lucide-react";
import "@fontsource-variable/inter";
import "./styles.css";
import { api, Me, MeContext, Overview, post, useApi } from "./api";
import { initials, ROLE_INFO } from "./format";
import { Loading, ToastProvider } from "./ui";
import Login from "./pages/Login";
import OverviewPage from "./pages/Overview";
import Incidents from "./pages/Incidents";
import Endpoints from "./pages/Endpoints";
import EndpointDetail from "./pages/EndpointDetail";
import Access from "./pages/Access";
import Account from "./pages/Account";
import { Logo } from "./pages/Login";

// the incident page carries the graph libraries; load it on demand
const IncidentDetail = lazy(() => import("./pages/IncidentDetail"));

function Shell() {
  const nav = useNavigate();
  const loc = useLocation();
  const [me, setMe] = useState<Me | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => { api<Me>("/api/me").then(setMe).catch(() => setFailed(true)); }, []);
  const counts = useApi<Overview>(me ? "/api/overview" : null, 60000);
  useEffect(() => { window.scrollTo(0, 0); }, [loc.pathname]);
  if (failed) return <Navigate to="/login" replace />;
  if (!me) return <div className="boot"><Loading label="Loading console…" /></div>;
  const logout = async () => {
    const r = await post<{ end_session_url?: string | null }>("/api/logout").catch(() => null);
    if (r?.end_session_url) window.location.href = r.end_session_url;   // also end the identity-provider session
    else nav("/login");
  };
  const name = me.display_name || me.username;
  const open = counts.data?.incidents.open;
  return (
    <MeContext.Provider value={me}>
      <div className="shell">
        <aside className="sidebar">
          <div className="brand"><Logo /><div><div className="brand-name">PDP</div><div className="brand-sub">Provenance detection</div></div></div>
          <nav className="nav">
            <NavLink to="/overview"><LayoutDashboard size={18} />Overview</NavLink>
            <NavLink to="/incidents"><ShieldAlert size={18} />Incidents{open ? <span className="nav-count">{open > 999 ? "999+" : open}</span> : null}</NavLink>
            <NavLink to="/endpoints"><Server size={18} />Endpoints</NavLink>
            {me.can?.manage_users && <NavLink to="/access"><Users size={18} />Access</NavLink>}
          </nav>
          <div className="sidebar-foot">
            <NavLink to="/account" className="user-card" title="Your account">
              <span className="avatar">{initials(name)}</span>
              <span className="user-text"><span className="user-name">{name}</span><span className="user-role">{ROLE_INFO[me.role]?.label || me.role}{me.auth === "oidc" ? " · SSO" : ""}</span></span>
              <UserCog size={16} className="user-gear" />
            </NavLink>
            <button className="logout" onClick={logout}><LogOut size={16} />Log out</button>
          </div>
        </aside>
        <main className="main">
          <Suspense fallback={<Loading block />}><Outlet /></Suspense>
        </main>
      </div>
    </MeContext.Provider>
  );
}

function App() {
  return (
    <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <ToastProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<Shell />}>
            <Route path="/overview" element={<OverviewPage />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/endpoints" element={<Endpoints />} />
            <Route path="/endpoints/:id" element={<EndpointDetail />} />
            <Route path="/access" element={<Access />} />
            <Route path="/account" element={<Account />} />
            {/* links from older consoles / notifications */}
            <Route path="/alerts" element={<Navigate to="/incidents?tab=alerts" replace />} />
            <Route path="/users" element={<Navigate to="/access" replace />} />
          </Route>
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Routes>
      </ToastProvider>
    </HashRouter>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
