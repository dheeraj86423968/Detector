#!/bin/bash
# Build the pdp-agent .deb and .rpm into dist/agent/ (run from anywhere; paths are resolved from the repo root).
#
# Environment (all optional):
#   PDP_VERSION      package version (semver; default: VERSION in agent/pdp_agent/agent.py). A pre-release such as
#                    0.3.0-ci.12 becomes 0.3.0~ci.12 in the .deb so it sorts before the 0.3.0 release.
#   PDP_AGENT_IMAGE  image reference pdp-agent-install writes to /etc/pdp/agent.env by default
#                    (default: ${PDP_REGISTRY}/pdp/agent:${PDP_VERSION}, or pdp/agent:${PDP_VERSION} without a registry)
#   PDP_REGISTRY     registry prefix used for the default above, e.g. registry.example.com
#   PDP_MAINTAINER   "Name <email>"   PDP_HOMEPAGE  URL
#   PACKAGERS        default "deb rpm"
#   NFPM             nfpm binary to use; default: `nfpm` on PATH, else the goreleaser/nfpm container image
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"

NFPM_IMAGE=goreleaser/nfpm:v2.41.1
PDP_VERSION=${PDP_VERSION:-$(sed -nE 's/^VERSION = "([^"]+)"/\1/p' agent/pdp_agent/agent.py)}
[ -n "$PDP_VERSION" ] || { echo "cannot determine PDP_VERSION" >&2; exit 1; }
PDP_AGENT_IMAGE=${PDP_AGENT_IMAGE:-${PDP_REGISTRY:+${PDP_REGISTRY%/}/}pdp/agent:${PDP_VERSION}}
export PDP_VERSION PDP_AGENT_IMAGE
export PDP_MAINTAINER=${PDP_MAINTAINER:-PDP Engineering <pdp-release@example.com>}
export PDP_HOMEPAGE=${PDP_HOMEPAGE:-https://pdp.example.com}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}
PACKAGERS=${PACKAGERS:-deb rpm}

OUT=dist/agent
PDP_STAGE=./$OUT/.stage   # fixed path: nfpm.yaml refers to ./dist/agent/.stage
rm -rf "$PDP_STAGE"; mkdir -p "$PDP_STAGE"

# the unit is packaged as-is; fail early if it is missing or no longer runs the image this package configures
UNIT=deploy/systemd/pdp-agent.service
grep -q 'PDP_AGENT_IMAGE' "$UNIT" || { echo "$UNIT no longer references PDP_AGENT_IMAGE; update pdp-agent-install" >&2; exit 1; }
grep -q 'EnvironmentFile=-/etc/pdp/agent.env' "$UNIT" || { echo "$UNIT no longer reads /etc/pdp/agent.env" >&2; exit 1; }

deb_version=${PDP_VERSION/-/\~}
stamp=$(date -u -R -d "@$SOURCE_DATE_EPOCH")
cat >"$PDP_STAGE/defaults" <<EOF
# build-time defaults for pdp-agent-install (package $PDP_VERSION)
PDP_PACKAGE_VERSION=$PDP_VERSION
PDP_AGENT_IMAGE_DEFAULT=$PDP_AGENT_IMAGE
EOF
cat >"$PDP_STAGE/copyright" <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: pdp-agent
Source: $PDP_HOMEPAGE

Files: *
Copyright: $(date -u -d "@$SOURCE_DATE_EPOCH" +%Y) PDP
License: proprietary
 All rights reserved. Use is subject to the license agreement under which this
 software was provided.
EOF
cat <<EOF | gzip -9n >"$PDP_STAGE/changelog.Debian.gz"
pdp-agent (${deb_version}-1) stable; urgency=medium

  * Release ${PDP_VERSION}; default agent image ${PDP_AGENT_IMAGE}.

 -- ${PDP_MAINTAINER}  ${stamp}
EOF
gzip -9n <deploy/packaging/agent/pdp-agent-install.8 >"$PDP_STAGE/pdp-agent-install.8.gz"

run_nfpm() {
  if [ -n "${NFPM:-}" ] || command -v nfpm >/dev/null 2>&1; then
    "${NFPM:-nfpm}" "$@"
  else
    docker run --rm --user "$(id -u):$(id -g)" -v "$ROOT:/src" -w /src \
      -e PDP_VERSION -e PDP_AGENT_IMAGE -e PDP_MAINTAINER -e PDP_HOMEPAGE -e SOURCE_DATE_EPOCH \
      "$NFPM_IMAGE" "$@"
  fi
}

for p in $PACKAGERS; do
  run_nfpm package --config deploy/packaging/agent/nfpm.yaml --packager "$p" --target "$OUT/"
done
rm -rf "$PDP_STAGE"
ls -l "$OUT"
