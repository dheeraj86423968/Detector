#!/bin/bash
set -e
# Runs as the fixed uid 10001 (pdp) after fixing volume ownership (volumes may be created by root).
for d in /data /pki /var/lib/pdp; do [ -d "$d" ] && chown -R pdp:pdp "$d" 2>/dev/null; done; true
case "$1" in
  api)     gosu pdp python -c "from pdp_server.api import initialize; initialize()"
           exec gosu pdp uvicorn pdp_server.api:app --host 0.0.0.0 --port 8000 --workers "${PDP_API_WORKERS:-4}" --proxy-headers --forwarded-allow-ips '*' --no-server-header ;;
  exporter) exec gosu pdp python -m pdp_server.notify ;;     # the notifier replaced the server-wide exporter
  notifier) exec gosu pdp python -m pdp_server.notify ;;
  worker)  shift; exec gosu pdp python -m pdp_server.worker "$@" ;;
  agent)   shift; exec gosu pdp python -m pdp_agent "$@" ;;
  *)       exec gosu pdp "$@" ;;
esac
