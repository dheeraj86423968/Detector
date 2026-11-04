#!/bin/bash
# Zero-downtime update of the API (the console and agent endpoints):
#
#   deploy/rollout.sh            # after `docker compose build api` (or a new PDP_VERSION in .env)
#
# Starts a new set of replicas next to the running ones, waits until every new replica is healthy, lets nginx's DNS
# cache (5 s) pick them up, then stops the old replicas gracefully one by one (in-flight requests finish; new ones
# go to the new replicas - nginx retries a refused connection on another replica). Never `docker compose up` the
# api service directly: that recreates all replicas at once.
set -euo pipefail
cd "$(dirname "$0")"
svc=${1:-api}
old=$(docker compose ps -q "$svc")
n=$(printf '%s\n' "$old" | grep -c . || true)
[ "$n" -ge 1 ] || { echo "$svc is not running; start the stack first" >&2; exit 1; }
echo "rolling $svc: $n old replica(s)"
docker compose up -d --no-deps --no-recreate --scale "$svc=$((2 * n))" "$svc" >/dev/null
new=$(docker compose ps -q "$svc" | grep -v -F -x -f <(printf '%s\n' "$old") || true)
[ -n "$new" ] || { echo "no new replicas were created" >&2; exit 1; }
for c in $new; do
  for i in $(seq 1 120); do
    st=$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo gone)
    [ "$st" = healthy ] && break
    [ "$st" = unhealthy ] || [ "$st" = gone ] && { echo "new replica $c is $st; old replicas kept running" >&2; docker rm -f $new >/dev/null; exit 1; }
    sleep 2
  done
  [ "$st" = healthy ] || { echo "new replica $c did not become healthy; old replicas kept running" >&2; docker rm -f $new >/dev/null; exit 1; }
  echo "  new $(docker inspect -f '{{.Name}}' "$c" | tr -d /) healthy"
done
sleep 7                                   # nginx resolver cache (valid=5s) now lists the new replicas
for c in $old; do
  name=$(docker inspect -f '{{.Name}}' "$c" | tr -d /)
  docker stop -t 30 "$c" >/dev/null && docker rm "$c" >/dev/null
  echo "  old $name stopped"
done
echo "done: $(docker compose ps "$svc" --format '{{.Name}} ({{.Status}})' | paste -sd' ')"
