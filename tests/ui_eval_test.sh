#!/bin/bash
# Headless UI test (jsdom) against a REAL gateway + mock LLM started locally. No Docker.
# Also starts tests/fake_provider.py (a fake OpenAI-compatible server) to exercise the REAL-provider UI paths.
# Needs: python deps from gateway/requirements.txt, Node 18+, and `npm install jsdom` run once in tests/.
# Not part of CI (needs Node + jsdom); run it by hand after UI changes:   bash tests/ui_eval_test.sh
set -e
cd "$(dirname "$0")/.."
D=$(mktemp -d); LP=18000; GP=18080
FP=18090; DEAD=18099
# models: the mock (default), a fake Ollama-shaped provider (REAL by configuration), and one whose port is closed
cat > $D/models.json <<JSON
{"default": "mock", "models": [
 {"id": "mock", "provider": "mock", "name": "Mock LLM", "kind": "mock"},
 {"id": "fake-ollama", "provider": "ollama", "name": "Fake Ollama", "model": "llama3.2", "endpoint": "http://127.0.0.1:$FP/v1", "timeout_s": 10},
 {"id": "dead-ollama", "provider": "ollama", "name": "Ollama (not running)", "model": "llama3.2", "endpoint": "http://127.0.0.1:$DEAD/v1", "timeout_s": 10}]}
JSON
export JWT_SECRET=ui-test-secret-ui-test-secret-123456 AUDIT_PATH=$D/audit.jsonl DEMO_UI=1 \
       LLM_URL=http://127.0.0.1:$LP MODELS_CONFIG=$D/models.json
python3 tests/fake_provider.py $FP & F=$!
python3 -m uvicorn main:app --app-dir containers/llm --port $LP --log-level warning & L=$!
python3 -m uvicorn main:app --app-dir gateway --port $GP --log-level warning & G=$!
trap 'kill $G $L $F 2>/dev/null' EXIT
for i in $(seq 1 100); do curl -sf http://127.0.0.1:$GP/healthz >/dev/null && curl -sf http://127.0.0.1:$LP/healthz >/dev/null && break; sleep 0.1; done
cd tests && NODE_PATH="$PWD/node_modules" node ui_eval_test.js http://127.0.0.1:$GP
