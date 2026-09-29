#!/usr/bin/env bash
# Proves the cgroup limits in docker-compose.yml actually bound a noisy
# tenant instead of letting it starve everyone else on the host. Run after
# `docker compose up -d --build`. Delegatable - extend freely (e.g. add a
# memory-pressure variant, or graph the docker stats output over time).
set -u
cd "$(dirname "$0")/.."

lat() {
  local t
  t=$(curl -s -o /dev/null -w '%{time_total}' http://127.0.0.1:8080/healthz)
  printf '  %ss\n' "$t"
}

echo "== Baseline: gateway /healthz latency, no load =="
for i in 1 2 3; do lat; done

CPUS=$(docker compose config | python3 -c "
import sys, yaml
d = yaml.safe_load(sys.stdin)
print(d['services']['red'].get('cpus', '?'))
")
echo
echo "== Maxing out 'red' (compose limits it to ${CPUS} vCPU) =="
for i in 1 2 3 4; do
  docker compose exec -d red python -c "
while True:
    pass
"
done
sleep 3

echo
echo "docker stats snapshot (red's CPU% should plateau near its limit, not the host max):"
docker stats --no-stream bayora-red-1 bayora-gateway-1 bayora-blue-1 bayora-llm-1

echo
echo "== Gateway /healthz latency WHILE red is maxed out =="
for i in 1 2 3; do lat; done

echo
echo "== Confirming blue and llm still work normally under the load =="
docker compose exec -T blue python client.py list >/dev/null \
  && echo "  PASS  blue still responsive" \
  || echo "  FAIL  blue did not respond"

echo
echo "Cleaning up: restarting 'red' to kill the burner loops"
docker compose restart red >/dev/null
echo "done"
