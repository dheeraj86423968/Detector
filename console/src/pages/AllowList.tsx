import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ListChecks, Plus, Search, Trash2 } from "lucide-react";
import { AllowEntry, AllowListResp, del, Endpoint, useApi, useCan } from "../api";
import { AddAllowDialog, allowedText } from "../allowlist";
import { ALLOW_KINDS, fmtDateTime, fmtRel, plural } from "../format";
import { AllowKindIcon, Card, Confirm, Empty, ErrorState, Loading, Mid, PageHeader, ShowMore, useShowMore, useToast } from "../ui";

export default function AllowList() {
  const can = useCan(); const toast = useToast();
  const [sp, setSp] = useSearchParams();
  const kind = sp.get("kind") || "", ep = sp.get("endpoint_id") || "";
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n, { replace: true }); };
  const [q, setQ] = useState("");
  const [adding, setAdding] = useState(false); const [removing, setRemoving] = useState<AllowEntry | null>(null);
  const { data, error, loading, reload } = useApi<AllowListResp>(`/api/allowlist${ep ? `?endpoint_id=${encodeURIComponent(ep)}` : ""}`);
  const eps = useApi<{ endpoints: Endpoint[] }>("/api/endpoints");
  const all = data?.entries || [];
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return all.filter(e => (!kind || e.kind === kind) && (!t || [e.value, e.note, e.rule_text, e.created_by, ...(e.endpoints || []).map(x => x.name)].some(x => (x || "").toLowerCase().includes(t))));
  }, [all, kind, q]);
  const page = useShowMore(rows, 50, `${kind}|${ep}|${q}`);
  const kindLabel = (k: string) => data?.kinds.find(x => x.id === k)?.label || ALLOW_KINDS[k]?.label || k;
  const filtered = !!(kind || ep || q);
  const epList = (eps.data?.endpoints || []).filter(e => e.state !== "retired" || e.id === ep);
  return (
    <div className="page">
      <PageHeader title="Allow list" subtitle="Activity you have reviewed and accept as normal. Matching activity no longer raises alerts, on all endpoints or only on the ones you choose."
        actions={can.manage_endpoints && <button className="btn primary" onClick={() => setAdding(true)}><Plus size={16} />Add to allow list</button>} />
      <Card pad={false}>
        {(all.length > 0 || filtered) && <div className="filters">
          <div className="search"><Search size={15} /><input placeholder="Search values, notes, endpoints" value={q} onChange={e => setQ(e.target.value)} /></div>
          <select value={kind} onChange={e => set("kind", e.target.value)} aria-label="Kind">
            <option value="">All kinds</option>
            {["program", "address", "detection"].map(k => <option key={k} value={k}>{kindLabel(k)}</option>)}
          </select>
          <select value={ep} onChange={e => set("endpoint_id", e.target.value)} aria-label="Endpoint">
            <option value="">Any endpoint</option>
            {epList.map(e => <option key={e.id} value={e.id}>Applies to {e.name}</option>)}
          </select>
          <div className="filters-end muted">{data ? plural(rows.length, "entry", "entries") : ""}</div>
        </div>}
        {loading && !data ? <Loading block /> : error && !data ? <div className="pad"><ErrorState error={error} onRetry={reload} /></div> :
          all.length === 0 && !filtered ? (
            <Empty icon={<ListChecks size={22} />} title="Nothing on the allow list yet"
              text={<>When an alert turns out to be normal activity, such as a tool your team uses, a backup server or a deployment script, add it here so M.D Lab Detector stops alerting on it.
                {can.manage_endpoints ? <> You can also use <b>Allow…</b> on an alert in an incident.</> : " Administrators can add entries."}</>}
              action={can.manage_endpoints ? <button className="btn primary" onClick={() => setAdding(true)}><Plus size={16} />Add to allow list</button> : undefined} />
          ) : rows.length === 0 ? (
            <Empty title="No entries match these filters" text="Try another kind, endpoint or search."
              action={<button className="btn sm" onClick={() => { setQ(""); setSp({}, { replace: true }); }}>Clear filters</button>} />
          ) : <>
            <div className="table-wrap">
              <table className="table middle allow-table">
                <thead><tr><th>Entry</th><th style={{ width: "19%" }}>Applies to</th><th style={{ width: "18%" }}>Note</th><th style={{ width: 150 }}>Added</th>
                  <th className="num" style={{ width: 104 }} title="Alerts this entry has allowed">Allowed</th>{can.manage_endpoints && <th style={{ width: 104 }}></th>}</tr></thead>
                <tbody>{page.visible.map(e => (
                  <tr key={e.id}>
                    <td className="cell-main">
                      <div className="allow-entry">
                        <AllowKindIcon kind={e.kind} />
                        <div className="min0">
                          <Mid text={e.value} className="mono allow-value" />
                          <div className="muted sm ellipsis">{e.kind === "detection" ? <span title={`Specific detection: ${e.rule_text || e.rule}`}>Detection · {e.rule_text || e.rule}</span> : kindLabel(e.kind)}
                            {e.kind === "program" && !e.value.includes("/") ? " · any folder" : ""}</div>
                        </div>
                      </div>
                    </td>
                    <td><AppliesTo e={e} /></td>
                    <td>{e.note ? <span className="clamp2" title={e.note}>{e.note}</span> : <span className="faint">—</span>}</td>
                    <td><div className="ellipsis" title={e.created_by || ""}>{e.created_by || <span className="muted">—</span>}</div><div className="muted sm" title={fmtDateTime(e.created_at, true)}>{fmtRel(e.created_at)}</div></td>
                    <td className="num">{e.alerts_allowed ? <b>{e.alerts_allowed.toLocaleString()}</b> : <span className="muted">0</span>}</td>
                    {can.manage_endpoints && <td className="row-actions"><button className="btn sm ghost" onClick={() => setRemoving(e)}><Trash2 size={14} />Remove</button></td>}
                  </tr>
                ))}</tbody>
              </table>
            </div>
            <ShowMore s={page} noun={["entry", "entries"]} />
          </>}
      </Card>
      {adding && <AddAllowDialog kinds={data?.kinds} initial={ep ? { endpoints: [ep] } : undefined} onClose={() => setAdding(false)}
        onDone={(_, n) => { toast(allowedText(n)); reload(); }} />}
      {removing && <Confirm danger title="Remove from the allow list?" confirmLabel="Remove entry" onClose={() => setRemoving(null)}
        text={<>
          <p>M.D Lab Detector will alert on <code className="code-inline">{removing.value}</code>{removing.kind === "detection" ? <> ({removing.rule_text || removing.rule})</> : null} again{removing.endpoints ? <> on {removing.endpoints.map(x => x.name).join(", ")}</> : " on all endpoints"}, from the agents' next check-in.</p>
          {removing.alerts_allowed > 0 && <p className="muted">The {plural(removing.alerts_allowed, "alert")} it allowed stay marked as false alarms.</p>}
        </>}
        onConfirm={async () => { await del(`/api/allowlist/${removing.id}`); toast("Removed from the allow list"); reload(); }} />}
    </div>
  );
}

export function AppliesTo({ e, here }: { e: AllowEntry; here?: string }) {
  if (!e.endpoints) return <span className="pill">All endpoints</span>;
  if (here && e.endpoints.length === 1 && e.endpoints[0].id === here) return <span className="muted">This endpoint only</span>;
  const names = e.endpoints.map(x => x.name);
  if (here) return <span className="muted">{plural(names.length, "endpoint")}</span>;
  return (
    <div className="applies" title={names.join(", ")}>
      {e.endpoints.slice(0, 2).map(x => <Link key={x.id} to={`/endpoints/${x.id}`} className="subtle-link min0"><Mid text={x.name} /></Link>)}
      {names.length > 2 && <span className="muted sm nowrap">+{names.length - 2} more</span>}
    </div>
  );
}
