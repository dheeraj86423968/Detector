import { useState } from "react";
import { Search } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { post, useApi, useCan } from "../api";
import { fmtDateTime, fmtNum, fmtRel, plural } from "../format";
import { Card, Empty, ErrorState, Loading, PageHeader, useToast } from "../ui";

type HuntRow = { id: string; q: string; kind: string | null; created_at: string; by: string | null; asked: number; answered: number; matches: number };
type Match = { kind: "exec" | "net" | "write"; program: string; object: string; first_ns: number; last_ns: number; count: number };
type HuntResult = { hunt: { id: string; q: string; kind: string | null; created_at: string };
  endpoints: { id: string; name: string; answered: boolean; at: string | null; rows: Match[] }[] };

const KIND: Record<string, string> = { exec: "Program run", net: "Network address", write: "File written" };
const ns = (n: number) => fmtDateTime(new Date(n / 1e6));

/** Search past activity on every endpoint: each agent keeps 30 days of de-duplicated activity (programs run, addresses
 *  contacted, files written) and answers from it. Endpoints must be reporting and on agent 0.3.17 or later. */
export default function Hunt() {
  const can = useCan(); const toast = useToast();
  const [params, setParams] = useSearchParams();
  const id = params.get("id");
  const [q, setQ] = useState(""); const [kind, setKind] = useState("");
  const [busy, setBusy] = useState(false);
  const list = useApi<{ hunts: HuntRow[] }>("/api/hunts", 10000);
  const cur = useApi<HuntResult>(id ? `/api/hunts/${id}` : null, 3000);

  const start = async () => {
    setBusy(true);
    try {
      const r = await post<{ id: string; endpoints: number; skipped: number }>("/api/hunts", { q: q.trim(), kind: kind || null });
      toast(r.endpoints ? `Asked ${plural(r.endpoints, "endpoint")}` + (r.skipped ? ` (${r.skipped} skipped: older agent)` : "")
        : "No endpoint can answer: none is reporting with agent 0.3.17 or later", r.endpoints ? "ok" : "err");
      setParams({ id: r.id }); list.reload();
    } catch (e: any) { toast(e.message, "err"); } finally { setBusy(false); }
  };

  return (
    <div className="page">
      <PageHeader title="Search activity" subtitle="Where did this happen? Search the last 30 days of programs run, network addresses and files written on all your endpoints." />
      {can.triage && <Card>
        <form className="filters" style={{ padding: 0, border: 0 }} onSubmit={e => { e.preventDefault(); if (q.trim().length >= 2) start(); }}>
          <div className="search" style={{ flex: 1 }}><Search size={15} />
            <input placeholder="A program, command line, IP address or file path, e.g. curl, 203.0.113.9 or /tmp/x.sh" value={q} onChange={e => setQ(e.target.value)} maxLength={200} /></div>
          <select value={kind} onChange={e => setKind(e.target.value)} aria-label="Kind">
            <option value="">All activity</option>
            {Object.entries(KIND).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <button className="btn primary" disabled={busy || q.trim().length < 2}>Search</button>
        </form>
      </Card>}
      {id && <HuntView r={cur} />}
      <Card title="Recent searches" pad={false}>
        {list.loading && !list.data ? <Loading block /> : !list.data?.hunts.length ? <p className="pad muted">No searches yet.</p> : (
          <table className="table middle"><tbody>{list.data.hunts.map(h => (
            <tr key={h.id} className={h.id === id ? "selected" : ""}>
              <td><Link to={`/hunt?id=${h.id}`}><code>{h.q}</code></Link>{h.kind && <span className="muted sm"> · {KIND[h.kind]}</span>}</td>
              <td className="muted sm">{h.answered}/{h.asked} answered · {plural(Number(h.matches), "match", "matches")}</td>
              <td className="muted sm" style={{ width: 200 }}>{h.by || ""} {fmtRel(h.created_at)}</td></tr>))}</tbody></table>
        )}
      </Card>
    </div>
  );
}

function HuntView({ r }: { r: ReturnType<typeof useApi<HuntResult>> }) {
  if (r.loading && !r.data) return <Card><Loading block /></Card>;
  if (r.error && !r.data) return <Card><ErrorState error={r.error} onRetry={r.reload} /></Card>;
  const h = r.data!;
  const waiting = h.endpoints.filter(e => !e.answered).length;
  const hits = h.endpoints.filter(e => e.rows.length);
  return (
    <Card title={<>Results for <code>{h.hunt.q}</code></>}
      subtitle={`${plural(hits.length, "endpoint")} with matches` + (waiting ? ` · waiting for ${plural(waiting, "endpoint")}` : " · all endpoints answered")} pad={false}>
      {h.endpoints.length === 0 ? <Empty title="No endpoint was asked" text="Endpoints answer when they are reporting and run agent 0.3.17 or later." /> :
        hits.length === 0 ? <p className="pad muted">{waiting ? "No matches so far." : "Not seen on any endpoint in the last 30 days."}</p> : (
          <table className="table"><thead><tr><th>Endpoint</th><th>Activity</th><th>Program</th><th>Seen</th><th style={{ textAlign: "right" }}>Times</th></tr></thead>
            <tbody>{hits.flatMap(e => e.rows.map((m, i) => (
              <tr key={e.id + i}>
                <td>{i === 0 && <Link to={`/endpoints/${e.id}`}>{e.name}</Link>}</td>
                <td><div className="muted sm">{KIND[m.kind]}</div><code className="wrap">{m.kind === "exec" ? m.object || m.program : m.object}</code></td>
                <td><code className="wrap">{m.program}</code></td>
                <td className="sm">{ns(m.last_ns)}{m.first_ns !== m.last_ns && <div className="muted">first {ns(m.first_ns)}</div>}</td>
                <td style={{ textAlign: "right" }}>{fmtNum(m.count)}</td></tr>)))}</tbody></table>
        )}
    </Card>
  );
}
