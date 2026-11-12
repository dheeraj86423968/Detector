import React, { lazy, Suspense, useCallback, useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { HashRouter, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { Bell, Building2, KeyRound, LayoutDashboard, ListChecks, LogOut, Search, Server, ShieldAlert, UserCog, Users } from "lucide-react";
import "@fontsource-variable/inter";
import "./styles.css";
import { api, Me, MeContext, MeReloadContext, Overview, post, useApi } from "./api";
import { initials, ROLE_INFO } from "./format";
import { Loading, ToastProvider } from "./ui";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Join from "./pages/Join";
import OverviewPage from "./pages/Overview";
import Incidents from "./pages/Incidents";
import Endpoints from "./pages/Endpoints";
import EndpointDetail from "./pages/EndpointDetail";
import Team from "./pages/Team";
import AllowList from "./pages/AllowList";
import Account from "./pages/Account";
import Notifications from "./pages/Notifications";
import WeeklyReport from "./pages/WeeklyReport";
import Security from "./pages/Security";
import Hunt from "./pages/Hunt";
import { Logo } from "./pages/Login";

// the incident page carries the graph libraries; load it on demand
const IncidentDetail = lazy(() => import("./pages/IncidentDetail"));
// only the platform operator ever opens this one
const Operator = lazy(() => import("./pages/Operator"));

function Shell() {
  const nav = useNavigate();
  const loc = useLocation();
  const [me, setMe] = useState<Me | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => { api<Me>("/api/me").then(setMe).catch(() => setFailed(true)); }, []);
  const reloadMe = useCallback(() => { api<Me>("/api/me").then(setMe).catch(() => { }); }, []);
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
  const team = me.can?.manage_users || me.can?.manage_org || me.can?.view_admin;
  const settings = me.can?.manage_org || me.can?.view_admin;     // auditors see them read-only
  return (
    <MeContext.Provider value={me}>
      <MeReloadContext.Provider value={reloadMe}>
        <div className="shell">
          <aside className="sidebar">
            <div className="brand"><Logo /><div><div className="brand-name">M.D Lab</div><div className="brand-sub">Detector</div></div></div>
            {me.org?.name && <div className="org-name" title={me.org.name}><Building2 size={14} /><span>{me.org.name}</span></div>}
            <nav className="nav">
              <NavLink to="/overview"><LayoutDashboard size={18} />Overview</NavLink>
              <NavLink to="/incidents"><ShieldAlert size={18} />Incidents{open ? <span className="nav-count">{open > 999 ? "999+" : open}</span> : null}</NavLink>
              <NavLink to="/endpoints"><Server size={18} />Endpoints</NavLink>
              <NavLink to="/hunt"><Search size={18} />Search activity</NavLink>
              <NavLink to="/allowlist"><ListChecks size={18} />Allow list</NavLink>
              {team && <NavLink to="/team"><Users size={18} />Team</NavLink>}
              {settings && <NavLink to="/settings/notifications"><Bell size={18} />Notifications</NavLink>}
              {settings && <NavLink to="/settings/security"><KeyRound size={18} />Security</NavLink>}
              {me.operator && <>
                <div className="nav-section">Platform</div>
                <NavLink to="/operator"><Building2 size={18} />Organisations</NavLink>
              </>}
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
            <Suspense fallback={<Loading block />}>{(me as any).mfa_setup_required && loc.pathname !== "/account" ? <Navigate to="/account" replace /> : <Outlet />}</Suspense>
          </main>
        </div>
      </MeReloadContext.Provider>
    </MeContext.Provider>
  );
}

function App() {
  return (
    <HashRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <ToastProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/join/:token" element={<Join />} />
          <Route element={<Shell />}>
            <Route path="/overview" element={<OverviewPage />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/endpoints" element={<Endpoints />} />
            <Route path="/endpoints/:id" element={<EndpointDetail />} />
            <Route path="/hunt" element={<Hunt />} />
            <Route path="/allowlist" element={<AllowList />} />
            <Route path="/team" element={<Team />} />
            <Route path="/operator" element={<Operator />} />
            <Route path="/account" element={<Account />} />
            <Route path="/settings/notifications" element={<Notifications />} />
            <Route path="/reports/weekly" element={<WeeklyReport />} />
            <Route path="/settings/security" element={<Security />} />
            <Route path="/notifications" element={<Navigate to="/settings/notifications" replace />} />
            {/* links from older consoles / notifications */}
            <Route path="/access" element={<Navigate to="/team" replace />} />
            <Route path="/alerts" element={<Navigate to="/incidents?tab=alerts" replace />} />
            <Route path="/users" element={<Navigate to="/team" replace />} />
          </Route>
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Routes>
      </ToastProvider>
    </HashRouter>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
