#!/bin/bash
# stop all of my (bl-*) containers if free space on / drops below 25.6 GB (exact bytes)
while true; do
  f=$(df --output=avail -B1 / | tail -1 | tr -dc 0-9)
  if [ "$f" -lt 27487790694 ]; then
    echo "$(date +%T) free $f B < 25.6 GiB: stopping bl-* containers" >> /root/bl/watchdog.log
    docker ps --format '{{.Names}}' | grep '^bl-' | xargs -r docker stop >> /root/bl/watchdog.log 2>&1
  fi
  sleep 10
done
