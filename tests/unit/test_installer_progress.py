"""The one-line installer's progress reports: docker pull's plain output becomes a layer count, the download meter
reports bytes against the image size, failures (die, or any unexpected stop) are reported with their reason, a new
host without a previous install does not stop the installer, and nothing is reported without a token. A fake `curl`
records what would be sent."""
import json
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
funcs = re.search(r"\n(json_str\(\) .*?\n)say\(\)", tpl, re.S).group(1)
die = re.search(r"\n(die\(\) .*?\n)", tpl).group(1)
trap = re.search(r"\n(trap 'rc=.*? ERR\n)", tpl).group(1)
blocks = "".join(re.search(rf"\n({name}\(\) \{{.*?\n\}}\n)", tpl, re.S).group(1) for name in ("pull_progress", "rx_bytes", "download_meter"))
old_image_line = re.search(r"\n(old_image=\$\(.*?\n)", tpl).group(1)
root = tempfile.mkdtemp()
binp = os.path.join(root, "bin"); os.makedirs(binp)
sent = os.path.join(root, "sent")
open(os.path.join(binp, "curl"), "w").write(f"""#!/bin/bash
while [ $# -gt 0 ]; do [ "$1" = -d ] && {{ printf '%s\\n' "$2" >> {sent}; }}; shift; done
exit 0
""")
os.chmod(os.path.join(binp, "curl"), 0o755)
netdev = os.path.join(root, "netdev")
open(netdev, "w").write("""Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 999999999    100    0    0    0     0          0         0  999999999     100    0    0    0     0       0          0
  eth0: 1000000    2000    0    0    0     0          0         0   500000    1000    0    0    0     0       0          0
enp0s31f6:2000000 3000    0    0    0     0          0         0   500000    1000    0    0    0     0       0          0
docker0: 777777777  10    0    0    0     0          0         0       0       0    0    0    0     0       0          0
""")
env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}", PDP_NET_DEV=netdev)

PULL = """0.3.18: Pulling from pdp/agent
a1: Already exists
b2: Pulling fs layer
c3: Pulling fs layer
d4: Pulling fs layer
c3: Waiting
b2: Download complete
b2: Pull complete
c3: Pull complete
d4: Download complete
d4: Pull complete
Digest: sha256:abc
"""


def bash(body, token="tok-123456789", stdin="", head=""):
    script = f'set -euo pipefail\nSERVER=https://srv.example\nETC={root}/no-etc\nLAYERS={root}/layers\ntoken="{token}"\n{funcs}{die}{head}{blocks}\n{body}\n'
    if os.path.exists(sent):
        os.remove(sent)
    r = subprocess.run(["bash", "-c", script], input=stdin, env=env, capture_output=True, text=True, timeout=60)
    msgs = [json.loads(x) for x in open(sent).read().splitlines()] if os.path.exists(sent) else []
    return r, msgs


r, msgs = bash("pull_progress; cat $LAYERS", stdin=PULL)
check(r.returncode == 0 and r.stdout.strip() == "4 4", f"layer count from docker's plain output ({r.stdout.strip()})")
r, msgs = bash("pull_progress", stdin="0.3.18: Pulling from pdp/agent\nError response from daemon: unauthorized: authentication required\n")
check("unauthorized" in r.stderr and msgs == [], "a pull error is shown to the user")

r, _ = bash("rx_bytes")
check(r.stdout == "3000000", f"received bytes: physical interfaces only, long names included ({r.stdout})")

r, msgs = bash("IMAGE_SIZE=245000000; echo '2 12' > $LAYERS; sleep 4 & download_meter $!")
check(r.returncode == 0 and "0 of 245 MB (0.0 MB/s), 2 of 12 layers" in r.stdout, f"meter line ({r.stdout.strip()})")
check(msgs and msgs[0]["stage"] == "downloading" and msgs[0]["done_bytes"] == 0 and msgs[0]["total_bytes"] == 245000000,
      "the console gets bytes done and the image size")

r, msgs = bash(old_image_line + 'echo "continued [$old_image]"')
check(r.returncode == 0 and "continued []" in r.stdout, "a host without a previous install continues (was a silent stop)")

r, msgs = bash("echo start\nfalse\necho never", head=trap)
check(r.returncode == 1 and "never" not in r.stdout and "stopped unexpectedly" in r.stderr and msgs and msgs[-1]["stage"] == "failed"
      and "line" in msgs[-1]["detail"], f"an unexpected stop is reported, never silent ({msgs[-1]['detail'] if msgs else None})")

r, msgs = bash("set -o pipefail; if ! (exit 1) | pull_progress; then die 'could not download x'; fi")
check(r.returncode == 1 and msgs and msgs[-1] == {**msgs[-1], "stage": "failed", "detail": "could not download x"}, "a failed pull reports why")

r, msgs = bash('report checks_ok "kernel \\"6.8\\" \\\\ ok"')
check(msgs and msgs[0]["detail"] == 'kernel "6.8" \\ ok' and "done_bytes" not in msgs[0], "quotes and backslashes in details stay valid JSON")

r, msgs = bash("report started x; die 'no token here'", token="")
check(r.returncode == 1 and msgs == [], "without a token (upgrade, uninstall) nothing is reported")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
