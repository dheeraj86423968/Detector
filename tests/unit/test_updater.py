"""The host-side agent updater written by install.sh: carries out a requested update, keeps it once the new agent
confirms, rolls back after repeated failed starts, backs off when the pull fails. A fake `docker` stands in."""
import os
import re
import subprocess
import sys
import tempfile

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


tpl = open(os.path.join(os.path.dirname(__file__), "../../server/pdp_server/install.sh.tmpl")).read()
m = re.search(r"cat > \"\$LIB/pdp-agent-update\" <<'UPD'\n(.*?)\nUPD\n", tpl, re.S)
script = m.group(1)
root = tempfile.mkdtemp()
etc, data, binp = (os.path.join(root, d) for d in ("etc", "data", "bin"))
for d in (etc, data, binp):
    os.makedirs(d)
up = os.path.join(root, "pdp-agent-update")
open(up, "w").write(script); os.chmod(up, 0o755)
calls = os.path.join(root, "calls")
open(os.path.join(binp, "docker"), "w").write(f"""#!/bin/sh
echo "$@" >> {calls}
case "$*" in *login*) cat >/dev/null; exit 0 ;; *pull*bad-registry*) exit 1 ;;
  images*) printf '%s\n' srv.example/pdp/agent:0.3.7 srv.example/pdp/agent:0.3.8 srv.example/pdp/agent:0.3.9 srv.example/pdp/agent:0.3.10 ;; esac
exit 0
""")
os.chmod(os.path.join(binp, "docker"), 0o755)
env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}", PDP_ETC_DIR=etc, PDP_DATA_DIR=data)


def run():
    return subprocess.run(["sh", up], env=env, capture_output=True, text=True).stdout


def image():
    return [l for l in open(os.path.join(etc, "agent.env")) if l.startswith("PDP_AGENT_IMAGE=")][-1].strip().split("=", 1)[1]


D = "@sha256:" + "a" * 64        # image references are pinned to a manifest digest (security review F2)


def request(v, img, reg="srv.example", digest=True):
    open(os.path.join(data, "update-request.env"), "w").write(f"VERSION={v}\nIMAGE={img}{D if digest else ''}\nREGISTRY={reg}\nTOKEN=tok-{v}\n")


open(os.path.join(etc, "agent.env"), "w").write("PDP_CA_SHA256=abc\nPDP_AGENT_IMAGE=srv.example/pdp/agent:0.3.7\n")
out = run()
check(image().endswith(":0.3.7") and not os.path.exists(os.path.join(data, "update-trial.env")), "nothing requested: nothing changes")

# 1. update requested -> pull with the token, switch, trial; agent confirms -> kept
request("0.3.8", "srv.example/pdp/agent:0.3.8")
out = run()
log = open(calls).read()
check("login -u pdp --password-stdin srv.example" in log and "pull -q srv.example/pdp/agent:0.3.8" + D in log, "pulls the new image (by digest) with the short-lived credential")
check(image() == "srv.example/pdp/agent:0.3.8" + D and os.path.exists(os.path.join(data, "update-trial.env")) and "PDP_CA_SHA256=abc" in open(os.path.join(etc, "agent.env")).read(),
      "switches the image, keeps the rest of agent.env, starts a trial")
check(not os.path.exists(os.path.join(data, "update-request.env")), "the request (with its token) is removed")
open(os.path.join(data, "update-ok"), "w").write("0.3.8\n")
out = run()
check("confirmed" in out and image().endswith(":0.3.8" + D) and not os.path.exists(os.path.join(data, "update-trial.env")), "the agent confirmed: update complete")
# security review F2: a reference without a digest, or from another registry, is never pulled
open(calls, "w").close()
request("0.3.11", "srv.example/pdp/agent:0.3.11", digest=False); out = run()
check("not pinned to a digest" in out and image().endswith(":0.3.8" + D) and "pull" not in open(calls).read(), "a tag-only image reference is refused")
request("0.3.12", "evil.example/pdp/agent:0.3.12"); out = run()
check("not from the registry" in out and image().endswith(":0.3.8" + D) and "pull" not in open(calls).read(), "an image outside the named registry is refused")

# 2. a version that never comes up: rolled back after more than three starts, recorded as failed
request("0.3.9", "srv.example/pdp/agent:0.3.9")
run()
check(image().endswith(":0.3.9" + D), "switched to 0.3.9 (trial)")
for _ in range(3):
    run()
check(image().endswith(":0.3.9" + D), "three unconfirmed starts: still trying")
out = run()
check("rolling back" in out and image().endswith(":0.3.8" + D) and "0.3.9" in open(os.path.join(data, "update-failed")).read(),
      "fourth start without confirmation: rolled back to 0.3.8, 0.3.9 recorded as failed")

# 3. pull fails: stays, backs off
request("0.4.0", "bad-registry/pdp/agent:0.4.0", reg="bad-registry")
out = run()
check(image().endswith(":0.3.8" + D) and os.path.exists(os.path.join(data, "update-backoff")) and not os.path.exists(os.path.join(data, "update-trial.env")),
      "pull failure: stays on the running version and backs off")

# 4. hostile request content is neutralised (only image-name characters survive)
request("0.4.1", "srv.example/pdp/agent:0.4.1;touch /tmp/pwned$(id)", digest=False)
run()
check(not os.path.exists("/tmp/pwned") and ";" not in image() and "$" not in image(), "shell metacharacters in a request are stripped")

# disk: earlier images are removed once no update is on trial; never the one in use, never during a trial
for f in ("update-request.env", "update-trial.env", "update-ok", "update-failed", "update-backoff"):
    if os.path.exists(os.path.join(data, f)):
        os.remove(os.path.join(data, f))
open(os.path.join(etc, "agent.env"), "w").write("PDP_CA_SHA256=abc\nPDP_AGENT_IMAGE=srv.example/pdp/agent:0.3.8\n")
open(calls, "w").close()
cur_img = image()
run()
rm = [l.split()[-1] for l in open(calls).read().splitlines() if l.startswith("rmi")]
check(rm and cur_img not in rm and all(x.startswith("srv.example/pdp/agent:") for x in rm),
      f"earlier agent images are removed, the current one ({cur_img.split(':')[-1]}) kept: {[x.split(':')[-1] for x in rm]}")
open(os.path.join(etc, "agent.env"), "w").write("PDP_CA_SHA256=abc\nPDP_AGENT_IMAGE=srv.example/pdp/agent:0.3.8" + D + "\n")
open(calls, "w").close(); run()
rm = [l.split()[-1] for l in open(calls).read().splitlines() if l.startswith("rmi")]
check(rm and "srv.example/pdp/agent:0.3.8" not in rm and "images --format {{.Repository}}:{{.Tag}} srv.example/pdp/agent" in open(calls).read(),
      "with a digest-pinned current image the repository is still recognised and the current tag kept")
open(os.path.join(etc, "agent.env"), "w").write("PDP_CA_SHA256=abc\nPDP_AGENT_IMAGE=srv.example/pdp/agent:0.3.8\n")
cur_img = image()
request("0.3.10", "srv.example/pdp/agent:0.3.10"); run(); open(calls, "w").close(); run()
check(not [l for l in open(calls).read().splitlines() if l.startswith("rmi")], "nothing is removed while an update is on trial (rollback needs the previous image)")
for _ in range(5):
    run()                                    # never confirmed: rolled back
rm = [l.split()[-1] for l in open(calls).read().splitlines() if l.startswith("rmi")]
check(image() == cur_img and cur_img not in rm, f"after a rollback the image rolled back to is kept ({image().split(':')[-1]})")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
