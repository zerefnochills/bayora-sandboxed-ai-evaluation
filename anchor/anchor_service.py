"""Bayora audit anchor - a tiny append-only witness for the gateway's audit log.

Why it exists: the gateway's own /data/audit.jsonl can be rewritten wholesale
by an attacker who controls the gateway container, into a new, internally
consistent chain. This service keeps an independent copy in its OWN volume
with its OWN lifecycle (it survives gateway rebuilds), and it only supports
append. There is no update or delete endpoint, and it rejects any entry that
doesn't extend its current chain, so the gateway cannot fork history.

Stdlib only (no pip needed). Endpoints:
  GET  /health   (no auth)  status + entry count
  GET  /head     (auth)     {count, next_seq, head}
  GET  /entries  (auth)     the raw JSON-lines file
  POST /append   (auth)     one entry; must extend the chain exactly
"""
import hashlib
import hmac
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GENESIS = "0" * 64
DATA = os.environ.get("ANCHOR_DATA", "/anchor-data")
PATH = os.path.join(DATA, "anchor.jsonl")
TOKEN = os.environ.get("ANCHOR_TOKEN", "")
PORT = int(os.environ.get("ANCHOR_PORT", "9000"))
MAX_BODY = 64 * 1024

_lock = threading.Lock()
_state = {"next_seq": 0, "head": GENESIS, "healthy": True, "reason": ""}
_hashes = {}  # seq -> hash, for idempotent retries and fork detection


def _digest(prev, seq, ts, event, actor, data):
    payload = json.dumps(
        {"prev": prev, "seq": seq, "ts": ts, "event": event, "actor": actor, "data": data},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _check_link(e, prev, seq):
    try:
        exp = _digest(prev, e["seq"], e["ts"], e["event"], e["actor"], e["data"])
        return e["prev"] == prev and e["seq"] == seq and e["hash"] == exp
    except (KeyError, TypeError):
        return False


def load():
    """Re-verify our own file on startup. If it's damaged, refuse appends."""
    os.makedirs(DATA, exist_ok=True)
    if not os.path.exists(PATH):
        return
    prev, n = GENESIS, 0
    with open(PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                e = None
            if not e or not _check_link(e, prev, n):
                _state.update(healthy=False, reason="anchor file failed verification at seq %d" % n)
                print("ANCHOR CORRUPT at seq", n, flush=True)
                return
            _hashes[n] = e["hash"]
            prev, n = e["hash"], n + 1
    _state.update(next_seq=n, head=prev)


def append(e):
    """Returns (http_status, body)."""
    with _lock:
        if not _state["healthy"]:
            return 503, {"error": _state["reason"]}
        try:
            seq = e["seq"]
        except (KeyError, TypeError):
            return 400, {"error": "missing seq"}
        if not isinstance(seq, int):
            return 400, {"error": "bad seq"}
        if seq < _state["next_seq"]:  # retry of something we hold, or a fork attempt
            if _hashes.get(seq) == e.get("hash"):
                return 200, {"status": "duplicate", "next_seq": _state["next_seq"]}
            print("ANCHOR CONFLICT: fork attempt at seq", seq, flush=True)
            return 409, {"error": "conflict: seq %d already anchored with a different hash" % seq}
        if seq > _state["next_seq"]:
            return 409, {"error": "gap", "next_seq": _state["next_seq"]}
        if not _check_link(e, _state["head"], seq):
            print("ANCHOR REJECT: entry does not extend chain at seq", seq, flush=True)
            return 409, {"error": "entry does not extend the anchored chain"}
        with open(PATH, "a") as f:
            f.write(json.dumps(e, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        _hashes[seq] = e["hash"]
        _state.update(next_seq=seq + 1, head=e["hash"])
        return 201, {"status": "anchored", "next_seq": seq + 1, "head": e["hash"]}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self):
        got = self.headers.get("Authorization", "")
        ok = bool(TOKEN) and hmac.compare_digest(got, "Bearer " + TOKEN)
        if not ok:
            self._send(401, {"error": "unauthorized"})
        return ok

    def do_GET(self):
        if self.path == "/health":
            with _lock:
                return self._send(200 if _state["healthy"] else 503, {
                    "healthy": _state["healthy"], "reason": _state["reason"],
                    "count": _state["next_seq"]})
        if not self._authed():
            return
        if self.path == "/head":
            with _lock:
                return self._send(200, {"count": _state["next_seq"],
                                        "next_seq": _state["next_seq"], "head": _state["head"]})
        if self.path == "/entries":
            with _lock:
                data = open(PATH, "rb").read() if os.path.exists(PATH) else b""
            return self._send(200, data, "application/x-ndjson")
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/append":
            return self._send(404, {"error": "not found"})
        if not self._authed():
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0 or n > MAX_BODY:
                return self._send(400, {"error": "bad length"})
            e = json.loads(self.rfile.read(n))
        except ValueError:
            return self._send(400, {"error": "bad json"})
        code, body = append(e)
        self._send(code, body)

    # Deliberately no PUT / PATCH / DELETE: append-only by construction.


if __name__ == "__main__":
    if not TOKEN:
        sys.exit("ANCHOR_TOKEN is not set - refusing to start")
    load()
    print("anchor up: %d entries, healthy=%s" % (_state["next_seq"], _state["healthy"]), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
