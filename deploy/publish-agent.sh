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
envval() { grep -E "^$1=" .env 2>/dev/null | tail -n1 | cut -d= -f2- || true; }
port=$(envval PDP_REGISTRY_PUSH_PORT); port=${port:-5000}
user=$(envval PDP_REGISTRY_PUSH_USER); pass=$(envval PDP_REGISTRY_PUSH_PASSWORD)
[ -n "$user" ] && [ -n "$pass" ] || { echo "no registry push credentials in .env (run deploy/bringup.sh once: it generates PDP_REGISTRY_PUSH_USER/PASSWORD)" >&2; exit 1; }
docker image inspect "pdp/agent:$ver" >/dev/null 2>&1 || { echo "no local image pdp/agent:$ver" >&2; exit 1; }
# the registry runs read-only (nothing on the backend network can re-point a tag); writable only for this push.
# --no-deps: never recreate the api replicas (use rollout.sh for those)
PDP_REGISTRY_READONLY=false docker compose up -d --no-deps registry >/dev/null
trap 'docker compose up -d --no-deps registry >/dev/null 2>&1 || true' EXIT     # ... and read-only again, whatever happens
docker compose up -d --no-deps gateway >/dev/null 2>&1 || true                 # the push goes through the gateway's loopback listener
for i in $(seq 1 30); do curl -fsS -u "$user:$pass" "http://127.0.0.1:$port/v2/" >/dev/null 2>&1 && break; sleep 1; done
cfg=$(mktemp -d); trap 'rm -rf "$cfg"; docker compose up -d --no-deps registry >/dev/null 2>&1 || true' EXIT
printf '%s' "$pass" | DOCKER_CONFIG=$cfg docker login -u "$user" --password-stdin "127.0.0.1:$port" >/dev/null
R="127.0.0.1:$port/pdp/agent"
if [ -z "$arm" ]; then
  docker tag "pdp/agent:$ver" "$R:$ver"
  DOCKER_CONFIG=$cfg docker push -q "$R:$ver"
  # the manifest digest the push produced (RepoDigests is filled in by the push): what installers and the updater pin
  digest=$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$R:$ver" | grep -F "$R@" | head -n1 | sed 's/.*@//')
  docker rmi "$R:$ver" >/dev/null
else
  for a in amd64 arm64; do
    src="pdp/agent:$ver"; [ "$a" = arm64 ] && src=$arm
    docker tag "$src" "$R:$ver-$a"; DOCKER_CONFIG=$cfg docker push -q "$R:$ver-$a"; docker rmi "$R:$ver-$a" >/dev/null
  done
  DOCKER_CONFIG=$cfg docker buildx imagetools create -t "$R:$ver" "$R:$ver-amd64" "$R:$ver-arm64" >/dev/null
  DOCKER_CONFIG=$cfg docker buildx imagetools inspect "$R:$ver" | grep -E 'Platform: +linux/(amd64|arm64)' | sort -u
  digest=$(DOCKER_CONFIG=$cfg docker buildx imagetools inspect "$R:$ver" --format '{{.Manifest.Digest}}')
fi
printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || { echo "could not determine the digest of $R:$ver (got '$digest'); not published" >&2; exit 1; }
# .env: the version, its digest, and the digest list of every version published since digests were recorded
setenv() { if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi; }
setenv PDP_AGENT_VERSION "$ver"
setenv PDP_AGENT_DIGEST "$digest"
digests=$(envval PDP_AGENT_DIGESTS | tr ',' '\n' | grep -v "^$ver=" | grep -v '^$' | tr '\n' ',' ; printf '%s=%s' "$ver" "$digest")
setenv PDP_AGENT_DIGESTS "$digests"
./rollout.sh api >/dev/null
echo "published pdp/agent:$ver ($digest); new installs pull $(envval PDP_PUBLIC_HOSTNAME)/pdp/agent:$ver@$digest"
