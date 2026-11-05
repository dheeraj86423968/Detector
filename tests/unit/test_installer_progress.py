"""The one-line installer's progress reports: docker pull's plain output becomes "n of m layers" (here and to the
server), pull errors are shown, failures (die) are reported with their message, and nothing is reported without a
token. A fake `curl` records what would be sent."""
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
pull = re.search(r"\n(pull_progress\(\) \{.*?\n\}\n)", tpl, re.S).group(1)
root = tempfile.mkdtemp()
binp = os.path.join(root, "bin"); os.makedirs(binp)
sent = os.path.join(root, "sent")
# fake curl: the JSON body follows -d
open(os.path.join(binp, "curl"), "w").write(f"""#!/bin/bash
while [ $# -gt 0 ]; do [ "$1" = -d ] && {{ printf '%s\\n' "$2" >> {sent}; }}; shift; done
exit 0
""")
os.chmod(os.path.join(binp, "curl"), 0o755)
env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")

PULL = """0.3.18: Pulling from pdp/agent
a1: Already exists
b2: Pulling fs layer
c3: Pulling fs layer
d4: Pulling fs layer
c3: Waiting
b2: Verifying Checksum
b2: Download complete
b2: Pull complete
c3: Download complete
c3: Pull complete
d4: Download complete
d4: Pull complete
Digest: sha256:abc
Status: Downloaded newer image for srv/pdp/agent:0.3.18
"""


def bash(body, token="tok-123456789", stdin=""):
    script = f'set -euo pipefail\nSERVER=https://srv.example\ntoken="{token}"\n{funcs}{die}{pull}\n{body}\n'
    if os.path.exists(sent):
        os.remove(sent)
    r = subprocess.run(["bash", "-c", script], input=stdin, env=env, capture_output=True, text=True)
    msgs = [json.loads(x) for x in open(sent).read().splitlines()] if os.path.exists(sent) else []
    return r, msgs


r, msgs = bash("pull_progress", stdin=PULL)
check(r.returncode == 0, "pull progress parses docker's plain output")
check("downloading: 4 of 4 layers" in r.stdout, f"the last line shows every layer done ({r.stdout.strip().splitlines()[-1:]})")
check(msgs and msgs[-1] == {"token": "tok-123456789", "stage": "downloading", "detail": "4 of 4 layers", "host": msgs[-1]["host"]},
      "the server gets the layer count with the token")
check(all(m["stage"] == "downloading" for m in msgs) and len(msgs) <= 3, f"reports are rate-limited ({len(msgs)} for 13 lines)")

r, msgs = bash("pull_progress", stdin="0.3.18: Pulling from pdp/agent\nError response from daemon: unauthorized: authentication required\n")
check("unauthorized" in r.stderr and msgs == [], "a pull error is shown to the user")

r, msgs = bash("set -o pipefail; if ! (exit 1) | pull_progress; then die 'could not download x'; fi")
check(r.returncode == 1 and msgs and msgs[-1]["stage"] == "failed" and msgs[-1]["detail"] == "could not download x",
      "a failed pull fails the installation and reports why")

r, msgs = bash('report checks_ok "kernel \\"6.8\\" \\\\ ok"')
check(msgs and msgs[0]["detail"] == 'kernel "6.8" \\ ok', "quotes and backslashes in details stay valid JSON")

r, msgs = bash("report started x; die 'no token here'", token="")
check(r.returncode == 1 and msgs == [], "without a token (upgrade, uninstall) nothing is reported")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
