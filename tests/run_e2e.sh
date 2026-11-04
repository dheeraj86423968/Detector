#!/bin/bash
# End-to-end suites against the staging stack (deploy/staging.sh up first):
#   tests/run_e2e.sh      stack_e2e (console + agent protocol), tenancy_e2e (organisation isolation), notify_e2e
set -uo pipefail
cd "$(dirname "$0")/.."
[ -f deploy/staging.env ] || { echo "no staging stack: deploy/staging.sh up" >&2; exit 2; }
PW=$(grep '^PDP_INITIAL_ADMIN_PASSWORD=' deploy/staging.env | cut -d= -f2)
NET=pdp-staging_edge; fail=0
suite() {   # name image cmd...
  local name=$1 img=$2; shift 2; local log; log=$(mktemp)
  if docker run --rm --network $NET -v "$PWD":/src:ro -w /src -e PDP_ADMIN_PASSWORD="$PW" -e PDP_SIGNUP_CODE=staging \
       -e PYTHONPATH=/src/engine:/src/agent:/src/server --entrypoint python "$img" "$@" >"$log" 2>&1; then
    echo "ok   $name: $(grep -c '^PASS' "$log") checks"
  else
    echo "FAIL $name"; grep -E '^FAIL|Traceback' "$log" | head -20; fail=1
  fi
  rm -f "$log"
}
suite stack_e2e pdp/agent:dev tests/e2e/stack_e2e.py
sleep 61     # the gateway allows 10 sign-ups a minute; both suites below sign up organisations
suite tenancy_e2e pdp/server:dev tests/e2e/tenancy_e2e.py
sleep 61
log=$(mktemp)
if PDP_E2E_STACK=staging tests/e2e/notify_e2e.sh >"$log" 2>&1; then echo "ok   notify_e2e: $(grep -c '^PASS' "$log") checks"
else echo "FAIL notify_e2e"; grep -E '^FAIL|Traceback|rror' "$log" | head -20; fail=1; fi
rm -f "$log"
exit $fail
