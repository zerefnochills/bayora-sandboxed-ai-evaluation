#!/usr/bin/env bash
# Adds ANCHOR_TOKEN to .env if it isn't there. Safe to re-run.
# NOTE: scripts/setup_env.py rewrites .env from scratch and will drop this
# line - run this script again after every setup_env.py run.
set -eu
cd "$(dirname "$0")/.."
touch .env
if grep -q '^ANCHOR_TOKEN=' .env; then
  echo "ANCHOR_TOKEN already present in .env"
else
  printf 'ANCHOR_TOKEN=%s\n' "$(openssl rand -hex 24)" >> .env
  echo "ANCHOR_TOKEN added to .env"
fi
