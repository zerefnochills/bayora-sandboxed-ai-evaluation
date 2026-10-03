#!/bin/bash
# Headless browser test (jsdom) of /app against a REAL gateway + mock LLM started locally. No Docker.
# Needs: python deps from gateway/requirements.txt, Node 18+, `npm install jsdom` once in tests/.
# Not part of CI. Run by hand after UI changes:   bash tests/ui_app_test.sh
set -e
cd "$(dirname "$0")/.."
D=$(mktemp -d); LP=18200; GP=18280
export JWT_SECRET=ui-app-test-secret-ui-app-test-secret-1234 AUDIT_PATH=$D/audit.jsonl LLM_URL=http://127.0.0.1:$LP MODELS_CONFIG=/nonexistent
export BOOT_CODE=$(cd gateway && python3 -c "import users,auth;print(users.bootstrap_code(auth.SECRET))")
python3 -m uvicorn main:app --app-dir containers/llm --port $LP --log-level warning & L=$!
python3 -m uvicorn main:app --app-dir gateway --port $GP --log-level warning & G=$!
trap 'kill $G $L 2>/dev/null' EXIT
for i in $(seq 1 100); do curl -sf http://127.0.0.1:$GP/healthz >/dev/null && curl -sf http://127.0.0.1:$LP/healthz >/dev/null && break; sleep 0.1; done
cd tests && NODE_PATH="$PWD/node_modules" node ui_app_test.js http://127.0.0.1:$GP
