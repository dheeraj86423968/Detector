#!/bin/bash
# All unit tests, each in the image it targets (as CI does):
#   tests/run_unit.sh [server image] [agent image]     defaults: pdp/server:dev pdp/agent:dev
# Server image: every tests/unit/test_*.py (engine, agent logic, server, notifier, updater ...).
# Agent image: the agent-side tests again in the slim endpoint image (no PyG, no gensim: what ships).
# PDP_SKIP_TESTS="test_suite ..." skips tests by name (test_suite runs the harmless attack-suite programs: do not run
# it on a host whose agent feeds field validation).
set -uo pipefail
cd "$(dirname "$0")/.."
SERVER=${1:-pdp/server:dev}; AGENT=${2:-pdp/agent:dev}
fail=0; n=0
run() {   # image test
  local log; log=$(mktemp)
  if docker run --rm -v "$PWD":/src -w /src -e PYTHONPATH=/src/server:/src/engine:/src/agent:/src/sim -e PDP_ENGINE_PATH=/src/engine \
       -e PDP_SIM_PATH=/src/sim --entrypoint python "$1" "$2" >"$log" 2>&1; then
    echo "ok   $(basename "$1") $2: $(tail -n 1 "$log")"
  else
    echo "FAIL $(basename "$1") $2"; tail -n 40 "$log"; fail=1
  fi
  rm -f "$log"; n=$((n + 1))
}
for t in tests/unit/test_*.py; do
  case " ${PDP_SKIP_TESTS:-} " in *" $(basename "$t" .py) "*) echo "skip $t"; continue ;; esac
  run "$SERVER" "$t"
done
if docker image inspect "$AGENT" >/dev/null 2>&1; then
  for t in test_agent test_footprint test_nobtf test_ebpf test_agent_realtime; do
    case " ${PDP_SKIP_TESTS:-} " in *" $t "*) continue ;; esac
    [ "$t" = test_agent_realtime ] && continue      # trains a model: needs gensim (server image only)
    run "$AGENT" "tests/unit/$t.py"
  done
fi
echo "$n test runs, $([ $fail = 0 ] && echo 'all passed' || echo 'FAILURES')"
exit $fail
