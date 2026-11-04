#!/bin/bash
# Publish an agent image to this server's registry so the one-line installer (/install.sh) hands it to clients.
#
#   deploy/publish-agent.sh 0.3.2            # pushes pdp/agent:0.3.2, makes it the version new installs get
#
# The registry listens on 127.0.0.1:${PDP_REGISTRY_PUSH_PORT:-5000} (push from this host only); clients pull through
# the gateway at https://$PDP_PUBLIC_HOSTNAME/v2/ with their enrolment token. Already installed agents keep their
# version until they are reinstalled.
set -euo pipefail
cd "$(dirname "$0")"
ver=${1:?usage: publish-agent.sh VERSION (the local image pdp/agent:VERSION)}
port=$(grep -E '^PDP_REGISTRY_PUSH_PORT=' .env 2>/dev/null | cut -d= -f2 || true); port=${port:-5000}
docker image inspect "pdp/agent:$ver" >/dev/null 2>&1 || { echo "no local image pdp/agent:$ver" >&2; exit 1; }
docker compose up -d registry >/dev/null
for i in $(seq 1 20); do curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break; sleep 1; done
docker tag "pdp/agent:$ver" "127.0.0.1:$port/pdp/agent:$ver"
docker push -q "127.0.0.1:$port/pdp/agent:$ver"
docker rmi "127.0.0.1:$port/pdp/agent:$ver" >/dev/null
if grep -q '^PDP_AGENT_VERSION=' .env; then sed -i "s/^PDP_AGENT_VERSION=.*/PDP_AGENT_VERSION=$ver/" .env; else echo "PDP_AGENT_VERSION=$ver" >> .env; fi
./rollout.sh api >/dev/null
echo "published pdp/agent:$ver; new installs pull $(grep -E '^PDP_PUBLIC_HOSTNAME=' .env | cut -d= -f2)/pdp/agent:$ver"
