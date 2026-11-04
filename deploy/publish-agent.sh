#!/bin/bash
# Publish an agent image to this server's registry so the one-line installer (/install.sh) hands it to clients.
#
#   deploy/publish-agent.sh 0.3.2            # pushes pdp/agent:0.3.2, makes it the version new installs get
#   deploy/publish-agent.sh 0.3.2 --arm64 pdp/agent:0.3.2-arm64
#                                            # one multi-architecture tag: x86_64 and arm64 hosts each pull their own
#                                            # (the arm64 image is built on an arm64 host, or with buildx and QEMU)
#
# The registry listens on 127.0.0.1:${PDP_REGISTRY_PUSH_PORT:-5000} (push from this host only); clients pull through
# the gateway at https://$PDP_PUBLIC_HOSTNAME/v2/ with their enrolment token. Already installed agents keep their
# version until they are reinstalled.
set -euo pipefail
cd "$(dirname "$0")"
ver=${1:?usage: publish-agent.sh VERSION [--arm64 LOCAL_ARM64_IMAGE] (the local image pdp/agent:VERSION)}
arm=""
if [ "${2:-}" = "--arm64" ]; then
  arm=${3:?--arm64 needs the local arm64 image}
  docker image inspect "$arm" >/dev/null 2>&1 || { echo "no local image $arm" >&2; exit 1; }
  [ "$(docker image inspect -f '{{.Architecture}}' "$arm")" = arm64 ] || { echo "$arm is not an arm64 image" >&2; exit 1; }
fi
port=$(grep -E '^PDP_REGISTRY_PUSH_PORT=' .env 2>/dev/null | cut -d= -f2 || true); port=${port:-5000}
docker image inspect "pdp/agent:$ver" >/dev/null 2>&1 || { echo "no local image pdp/agent:$ver" >&2; exit 1; }
docker compose up -d registry >/dev/null
for i in $(seq 1 20); do curl -fsS "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break; sleep 1; done
R="127.0.0.1:$port/pdp/agent"
if [ -z "$arm" ]; then
  docker tag "pdp/agent:$ver" "$R:$ver"
  docker push -q "$R:$ver"
  docker rmi "$R:$ver" >/dev/null
else
  for a in amd64 arm64; do
    src="pdp/agent:$ver"; [ "$a" = arm64 ] && src=$arm
    docker tag "$src" "$R:$ver-$a"; docker push -q "$R:$ver-$a"; docker rmi "$R:$ver-$a" >/dev/null
  done
  docker buildx imagetools create -t "$R:$ver" "$R:$ver-amd64" "$R:$ver-arm64" >/dev/null
  docker buildx imagetools inspect "$R:$ver" | grep -E 'Platform: +linux/(amd64|arm64)' | sort -u
fi
if grep -q '^PDP_AGENT_VERSION=' .env; then sed -i "s/^PDP_AGENT_VERSION=.*/PDP_AGENT_VERSION=$ver/" .env; else echo "PDP_AGENT_VERSION=$ver" >> .env; fi
./rollout.sh api >/dev/null
echo "published pdp/agent:$ver; new installs pull $(grep -E '^PDP_PUBLIC_HOSTNAME=' .env | cut -d= -f2)/pdp/agent:$ver"
