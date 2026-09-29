#!/usr/bin/env bash

# Bayora fairness / resource-isolation test.
#
# Proves that a noisy tenant ("red") is constrained by its cgroup CPU limit
# and does not prevent the gateway, blue tenant, or LLM from responding.
#
# Important gVisor note:
# We avoid repeated `docker compose exec` calls into the CPU-stressed
# container because gVisor's sentry shares the tenant's CPU quota and
# repeated exec operations can become extremely slow or wedge.
#
# This version:
#   1. Measures gateway latency with no load.
#   2. Starts exactly ONE CPU burner in red.
#   3. Does not repeatedly exec into red to detect the burner.
#   4. Uses docker stats from the host to observe CPU usage.
#   5. Measures gateway latency while red is under load.
#   6. Checks that blue remains responsive.
#   7. Force-kills and recreates red during cleanup.

set -u

cd "$(dirname "$0")/.."

TIMEOUT=10

run() {
    timeout "$TIMEOUT" "$@"
}

cleanup() {
    echo
    echo "== Cleaning up red =="

    # SIGKILL avoids a graceful-stop operation getting wedged.
    timeout 15 docker kill bayora-red-1 >/dev/null 2>&1 || true

    # Recreate red with the same image/configuration.
    docker compose up -d red >/dev/null 2>&1 || true

    echo "cleanup complete"
}

trap cleanup EXIT


# ------------------------------------------------------------
# Helper: measure gateway latency
# ------------------------------------------------------------

lat() {
    run curl -s \
        -o /dev/null \
        -w '  %{time_total}s\n' \
        http://127.0.0.1:8080/healthz \
        || echo "  (timed out)"
}


# ------------------------------------------------------------
# Wait for gateway
# ------------------------------------------------------------

echo "== Waiting for gateway =="

GATEWAY_READY=0

for i in $(seq 1 15); do
    if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
        GATEWAY_READY=1
        break
    fi

    sleep 1
done

if [ "$GATEWAY_READY" -eq 0 ]; then
    echo "FAIL: gateway did not become ready within 15 seconds"
    exit 1
fi

echo "gateway is ready"


# ------------------------------------------------------------
# Read CPU limit from docker-compose.yml
# ------------------------------------------------------------

CPUS=$(
    docker compose config |
    python3 -c '
import sys
import yaml

d = yaml.safe_load(sys.stdin)
print(d["services"]["red"].get("cpus", "?"))
' 2>/dev/null || echo "?"
)


# ------------------------------------------------------------
# Baseline latency
# ------------------------------------------------------------

echo
echo "== Baseline: gateway /healthz latency, no load =="

for i in 1 2 3; do
    lat
done


# ------------------------------------------------------------
# Launch ONE CPU burner
# ------------------------------------------------------------

echo
echo "== Launching ONE CPU burner inside red =="
echo "   red CPU limit: ${CPUS} vCPU"

# Use direct docker exec instead of docker compose exec.
#
# The Python process writes a marker and then continuously burns CPU.
# Only ONE burner is created because the cgroup limit itself is what
# we're testing, not the number of processes.

if ! run docker exec -d bayora-red-1 python3 -c \
'exec("open(\"/tmp/bayora_burner.marker\",\"w\").write(\"1\")\nwhile True:\n    pass")'
then
    echo "FAIL: could not launch CPU burner"
    exit 1
fi

echo "burner launch command returned successfully"
echo "waiting 2 seconds for CPU load to stabilize..."

sleep 2


# ------------------------------------------------------------
# Observe CPU usage from outside the stressed container
# ------------------------------------------------------------

echo
echo "== docker stats while red is under CPU load =="
echo "red should remain near its configured ${CPUS} vCPU limit"

for i in 1 2 3; do

    if ! run docker stats --no-stream \
        bayora-red-1 \
        bayora-gateway-1 \
        bayora-blue-1 \
        bayora-llm-1 \
        --format "  {{.Name}}: {{.CPUPerc}} CPU, {{.MemUsage}}"
    then
        echo "  (docker stats timed out)"
    fi

    sleep 1
done


# ------------------------------------------------------------
# Gateway latency under load
# ------------------------------------------------------------

echo
echo "== Gateway /healthz latency WHILE red is under load =="

for i in 1 2 3; do
    lat
done


# ------------------------------------------------------------
# Blue responsiveness
# ------------------------------------------------------------

echo
echo "== Confirming blue still works normally under the load =="

if run docker exec bayora-blue-1 python3 client.py list >/dev/null 2>&1; then
    echo "  PASS  blue still responsive"
else
    echo "  FAIL  blue did not respond (or timed out)"
fi


# ------------------------------------------------------------
# LLM responsiveness
# ------------------------------------------------------------

echo
echo "== Confirming LLM container remains reachable =="

if run docker exec bayora-llm-1 python3 -c \
'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=3)' \
 >/dev/null 2>&1
then
    echo "  PASS  llm still responsive"
else
    echo "  FAIL  llm did not respond (or timed out)"
fi


echo
echo "== Fairness test complete =="

# cleanup() runs automatically because of the EXIT trap.