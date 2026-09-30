#!/usr/bin/env bash
# Cross-checks the gateway's on-disk audit log against the audit-anchor
# sidecar's independent copy. Catches what AuditLog.verify() alone cannot:
#   - a full-file rewrite into a new, self-consistent chain
#   - truncation of the log tail (the anchor holds entries the disk lacks)
#   - entries on disk that were never anchored
#
# Exit codes:  0 PASS   1 integrity FAIL   2 could not read a log   124 timed out
#
# Designed not to hang. Under gVisor a `docker exec` can wedge, so:
#   * Nothing here needs `docker exec` unless the safer paths fail.
#       anchor log  -> HTTP GET /entries straight from the VM (curl, hard limits)
#       gateway log -> read from the volume's host path (found via `docker inspect`,
#                      which only talks to dockerd, never into the sandbox)
#       `docker compose exec` is only a last-resort fallback.
#   * Every external command has a hard timeout with a SIGKILL follow-up
#     (plain `timeout` sends only SIGTERM, which a wedged process can ignore).
#   * Every command gets stdin from /dev/null (no tty reads / SIGTTIN stalls).
#   * The whole script re-runs itself under one overall time limit.
#   * A stage line is printed before each operation, so a stall shows where.
#
# Honest limit: protects against a compromised gateway CONTAINER, not a
# compromised HOST or anchor volume.
set -u
cd "$(dirname "$0")/.."

TOTAL="${VERIFY_TOTAL_TIMEOUT:-90}"   # whole-script ceiling (seconds)
STEP="${VERIFY_STEP_TIMEOUT:-15}"     # per-command ceiling (seconds)
ANCHOR_URL="${ANCHOR_URL:-http://172.28.9.3:9000}"

# ---- overall watchdog: re-run ourselves under a hard limit ------------
if [ -z "${VERIFY_ANCHOR_INNER:-}" ]; then
  VERIFY_ANCHOR_INNER=1 timeout -k 3 "$TOTAL" bash "$0" "$@" </dev/null
  rc=$?
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    echo "FAIL: verify_anchor.sh exceeded ${TOTAL}s and was killed (see last [stage] line above)."
    exit 124
  fi
  exit "$rc"
fi

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
stage() { echo "[$1] $2"; }
# hard-limited command, no stdin, SIGKILL 2s after SIGTERM
hard() { local t="$1"; shift; timeout -k 2 "$t" "$@" </dev/null; }

# ---- 1. anchor's log ---------------------------------------------------
read_anchor_http() {
  local tok code
  tok=$(grep -m1 '^ANCHOR_TOKEN=' .env 2>/dev/null | cut -d= -f2- | tr -d '\r\n"' )
  [ -n "$tok" ] || { echo "    no ANCHOR_TOKEN in .env"; return 1; }
  code=$(hard "$((STEP + 3))" curl -sS -o "$tmp/anchor.jsonl" -w '%{http_code}' \
           --connect-timeout 3 --max-time "$STEP" \
           -H "Authorization: Bearer $tok" "$ANCHOR_URL/entries" 2>"$tmp/curl.err")
  [ "$code" = "200" ] || { echo "    HTTP status '${code:-none}' $(head -c 150 "$tmp/curl.err")"; return 1; }
}

read_via_exec() {  # $1=service  $2=path-in-container  $3=output file
  if ! hard "$STEP" docker compose exec -T "$1" cat "$2" > "$3" 2>"$tmp/exec.err"; then
    echo "    docker exec failed or timed out after ${STEP}s: $(head -c 200 "$tmp/exec.err")"
    return 1
  fi
}

stage 1/5 "reading anchor log over HTTP ($ANCHOR_URL/entries)"
if read_anchor_http; then
  echo "    ok (http)"
else
  stage 1/5 "HTTP failed; falling back to docker exec on audit-anchor (max ${STEP}s)"
  read_via_exec audit-anchor /anchor-data/anchor.jsonl "$tmp/anchor.jsonl" \
    || { echo "FAIL: could not read the anchor's log by HTTP or docker exec."; exit 2; }
  echo "    ok (exec)"
fi

# ---- 2. gateway's log --------------------------------------------------
read_gateway_hostpath() {
  local cid src f
  cid=$(hard 10 docker compose ps -q gateway 2>/dev/null | head -n1)
  [ -n "$cid" ] || cid="bayora-gateway-1"
  src=$(hard 10 docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' "$cid" 2>/dev/null)
  [ -n "$src" ] || { echo "    no host path for /data (not a volume/bind mount?)"; return 1; }
  f="$src/audit.jsonl"
  if [ -r "$f" ]; then
    hard "$STEP" cat "$f" > "$tmp/disk.jsonl" 2>/dev/null
  elif hard 5 sudo -n true 2>/dev/null; then
    hard "$STEP" sudo -n cat "$f" > "$tmp/disk.jsonl" 2>/dev/null
  else
    echo "    $f not readable and passwordless sudo unavailable"; return 1
  fi
}

stage 2/5 "reading gateway audit log from the volume's host path"
if read_gateway_hostpath; then
  echo "    ok (host path)"
else
  stage 2/5 "host path failed; falling back to docker exec on gateway (max ${STEP}s)"
  read_via_exec gateway /data/audit.jsonl "$tmp/disk.jsonl" \
    || { echo "FAIL: could not read the gateway's audit log by host path or docker exec."; exit 2; }
  echo "    ok (exec)"
fi

# ---- 3-5. compare ------------------------------------------------------
stage 3/5 "parsing both logs"
timeout -k 2 30 python3 - "$tmp/disk.jsonl" "$tmp/anchor.jsonl" <<'PY'
import json, sys

def load(path, label):
    out = {}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                out[e["seq"]] = e
            except (ValueError, KeyError, TypeError):
                print(f"FAIL: {label} log line {n} is not a valid entry "
                      f"(torn write mid-copy? re-run once; if it persists the file is damaged).")
                sys.exit(2)
    return out

disk, anc = load(sys.argv[1], "gateway"), load(sys.argv[2], "anchor")
print("[4/5] comparing entries")
print(f"    on-disk entries:  {len(disk)}")
print(f"    anchored entries: {len(anc)}")

print("[5/5] checking for rewrites, truncation and unanchored entries")
differ     = [s for s in sorted(disk) if s in anc and disk[s] != anc[s]]
unanchored = [s for s in sorted(disk) if s not in anc]
missing    = [s for s in sorted(anc)  if s not in disk]

failed = False
if differ:
    failed = True
    print(f"\nFAIL: {len(differ)} on-disk entries differ from what was anchored "
          f"(seq {differ[:10]}). The log was rewritten after the fact.")
if missing:
    failed = True
    print(f"\nFAIL: the anchor holds {len(missing)} entries absent from disk "
          f"(seq {missing[:10]}). The on-disk log was truncated.")
if unanchored:
    failed = True
    print(f"\nFAIL: {len(unanchored)} on-disk entries have no anchored copy "
          f"(seq {unanchored[:10]}). Either the anchor was down/bypassed, or entries were "
          f"injected. If the anchor was just restarting, run one more request and re-check.")
if failed:
    sys.exit(1)

print("\nPASS: every on-disk entry matches its anchored copy, and nothing is missing.")
print("(Does not cover a compromise of the HOST or of the anchor's own volume.)")
PY
