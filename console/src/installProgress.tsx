import { Link } from "react-router-dom";
import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import { useApi } from "./api";
import { fmtRel } from "./format";

type Ev = { stage: string; detail: string | null; host: string | null; at: string };
type Resp = { ok: true; name: string; installer: Ev[]; endpoint: null | {
  id: string; name: string; hostname: string | null; phase: string; agent_version: string | null; enrolled_at: string | null; last_seen: string | null;
  reporting: boolean; collector: "running" | "error" | null; collector_error: string | null; first_data_at: string | null; first_model_at: string | null } };

type Step = { key: string; title: string; state: "done" | "active" | "todo" | "failed"; detail?: string | null };

// installer stages in order; a later one implies the earlier ones (docker_install is optional)
const ORDER = ["started", "checks_ok", "docker_install", "docker_ready", "downloading", "downloaded", "configured", "starting", "enrolled"];

/** Live checklist under the install command: the installer's stages (reported with the enrolment token) and then
 *  the endpoint's own (reporting, collecting activity, first model). Polls every 3 s until the first model. */
export function InstallProgress({ progressKey }: { progressKey: string }) {
  const { data } = useApi<Resp>(`/api/install-progress/${progressKey}`, 3000);
  const ev = data?.installer || [];
  const ep = data?.endpoint;
  const last = (s: string) => [...ev].reverse().find(e => e.stage === s);
  const reached = Math.max(-1, ...ev.map(e => ORDER.indexOf(e.stage)), ep ? ORDER.indexOf("enrolled") : -1);
  const failed = ev.length > 0 && ev[ev.length - 1].stage === "failed" && !ep ? ev[ev.length - 1] : null;
  const at = (s: string) => ORDER.indexOf(s) <= reached;
  const st = (s: string, next: string): Step["state"] => at(next) ? "done" : at(s) ? (failed ? "failed" : "active") : "todo";
  const host = ev.find(e => e.host)?.host;

  const steps: Step[] = [
    { key: "run", title: ev.length || ep ? `Installer running${host ? ` on ${host}` : ""}` : "Waiting for you to run the command",
      state: ev.length || ep ? "done" : "active", detail: ev.length || ep ? null : "Run it on the server as root; this list follows along." },
    { key: "checks", title: "Host checks", state: at("checks_ok") ? "done" : at("started") ? (failed ? "failed" : "active") : "todo", detail: last("checks_ok")?.detail },
    { key: "docker", title: last("docker_install") && !at("docker_ready") ? "Installing Docker" : "Docker ready", state: st("checks_ok", "docker_ready") === "done" ? "done" : at("checks_ok") ? (failed ? "failed" : "active") : "todo",
      detail: last("docker_ready")?.detail },
    { key: "download", title: at("downloaded") ? "Agent downloaded" : "Downloading the agent", state: at("downloaded") ? "done" : at("docker_ready") ? (failed ? "failed" : "active") : "todo",
      detail: at("downloaded") ? last("downloaded")?.detail : last("downloading")?.detail },
    { key: "start", title: "Agent configured and started", state: at("enrolled") ? "done" : at("downloaded") ? (failed ? "failed" : "active") : "todo",
      detail: at("starting") && !at("enrolled") ? "waiting for the agent to enrol" : null },
    { key: "enrolled", title: "Enrolled", state: ep ? "done" : at("enrolled") ? "active" : "todo",
      detail: ep ? `${ep.name}${ep.hostname ? ` (${ep.hostname})` : ""}${ep.agent_version ? `, agent ${ep.agent_version}` : ""}` : null },
    { key: "reporting", title: "Agent reporting", state: ep?.reporting ? "done" : ep ? "active" : "todo",
      detail: ep?.last_seen ? `last check-in ${fmtRel(ep.last_seen)}` : null },
    { key: "collecting", title: "Collecting activity", state: ep?.collector === "error" ? "failed" : ep?.first_data_at ? "done" : ep?.reporting ? "active" : "todo",
      detail: ep?.collector === "error" ? ep.collector_error : ep?.first_data_at ? `first data ${fmtRel(ep.first_data_at)}` : ep?.reporting ? "the first activity arrives within a few minutes" : null },
    { key: "model", title: "First detection model", state: ep?.first_model_at ? "done" : ep?.first_data_at ? "active" : "todo",
      detail: ep?.first_model_at ? `ready ${fmtRel(ep.first_model_at)}: detection is on` : ep?.first_data_at ? "after about one hour of activity" : null },
  ];
  return (
    <div className="install-progress">
      <div className="install-step">Progress</div>
      <ol>{steps.map(s => (
        <li key={s.key} className={`ip-${s.state}`}>
          {s.state === "done" ? <CheckCircle2 size={16} /> : s.state === "failed" ? <XCircle size={16} /> : s.state === "active" ? <Loader2 size={16} className="spin" /> : <Circle size={16} />}
          <div><div className="ip-title">{s.title}</div>{s.detail && <div className="ip-detail">{s.detail}</div>}</div>
        </li>
      ))}</ol>
      {failed && <div className="err">The installation stopped: {failed.detail}. Fix the cause and run the same command again (the token stays valid for 24 hours).</div>}
      {ep && <Link className="card-link" to={`/endpoints/${ep.id}`}>Open {ep.name}</Link>}
    </div>
  );
}
