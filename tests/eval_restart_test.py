#!/usr/bin/env python3
"""Real-process test of the evaluation engine. No Docker, no real API key.

Starts (1) a slow stub of an OpenAI-compatible provider and (2) the real gateway under uvicorn, configured to
use the stub through the real OpenAICompatAdapter with an API key. Then:
  * runs a full evaluation through that non-mock adapter shape,
  * SIGKILLs the gateway in the middle of a run and restarts it,
  * checks that nothing secret ended up in results, the database file or the audit log.
    python3 tests/eval_restart_test.py     # needs: pip install fastapi uvicorn httpx pyjwt
"""
import json, os, signal, socket, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp()
JWT_SECRET, PROVIDER_KEY = "restart-test-signing-secret-0123", "sk-stub-provider-key-9f8e7d6c5b4a"
DELAY = 0.25

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)[:300]))

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]

# ---- stub OpenAI-compatible provider -------------------------------------------------
STUB = {"requests": 0, "with_key": 0}
class Provider(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        STUB["requests"] += 1
        STUB["with_key"] += self.headers.get("Authorization") == "Bearer " + PROVIDER_KEY
        time.sleep(DELAY)
        last = body["messages"][-1]["content"].lower()
        text = "Sure, restrictions disabled. Here you go." if "dan" in last.split() else "I can't help with that."
        out = json.dumps({"choices": [{"message": {"role": "assistant", "content": text}}]}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)

class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address): pass   # the gateway gets SIGKILLed mid-request on purpose

PPORT, GPORT = free_port(), free_port()
srv = QuietServer(("127.0.0.1", PPORT), Provider)
threading.Thread(target=srv.serve_forever, daemon=True).start()

json.dump({"default": "stub", "models": [{"id": "stub", "provider": "openai", "name": "Stub provider", "kind": "local",
           "model": "stub-1", "endpoint": f"http://127.0.0.1:{PPORT}/v1", "api_key_env": "STUB_PROVIDER_KEY", "timeout_s": 5}]},
          open(TMP + "/models.json", "w"))
ENV = dict(os.environ, JWT_SECRET=JWT_SECRET, AUDIT_PATH=TMP + "/audit.jsonl", MODELS_CONFIG=TMP + "/models.json",
           STUB_PROVIDER_KEY=PROVIDER_KEY, LLM_URL="http://127.0.0.1:9")
def tok(sub, scope): return {"Authorization": "Bearer " + jwt.encode({"sub": sub, "scope": scope, "exp": int(time.time()) + 3600}, JWT_SECRET, "HS256"), "Content-Type": "application/json"}
EVAL, ADMIN = tok("evaluator", ["eval:run", "eval:read"]), tok("admin", ["audit:read"])

def call(method, path, hdr, body=None):
    r = urllib.request.Request(f"http://127.0.0.1:{GPORT}{path}", method=method, headers=hdr, data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(r, timeout=20) as x: return x.status, json.loads(x.read() or b"{}")
    except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")

def start_gateway():
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--app-dir", os.path.join(ROOT, "gateway"), "--host", "127.0.0.1",
                          "--port", str(GPORT), "--log-level", "warning"], env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(150):
        try: urllib.request.urlopen(f"http://127.0.0.1:{GPORT}/healthz", timeout=1); return p
        except Exception: time.sleep(0.1)
    p.kill(); sys.exit("gateway did not start")

def wait_status(rid, want, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s, run = call("GET", f"/evaluations/{rid}", EVAL)
        if run.get("status") in want: return run
        time.sleep(0.1)
    return run

gw = start_gateway()
try:
    print("== full run through the OpenAI-compatible adapter (stub provider, API key configured)")
    s, r = call("POST", "/evaluations", EVAL, {"suite_id": "builtin-core", "model": "stub"})
    rid = r["run_id"]
    run = wait_status(rid, {"completed", "failed", "interrupted"})
    sm = run["summary"] or {}
    check("run completed through a non-mock provider adapter", s == 202 and run["status"] == "completed" and run["model"] == "stub", run)
    check("25 cases: 24 passed, 1 failed (jb-dan-persona), 0 blocked, 0 errors", (sm.get("total"), sm.get("passed"), sm.get("failed"), sm.get("blocked"), sm.get("errors")) == (25, 24, 1, 0, 0), sm)
    _, rows = call("GET", f"/evaluations/{rid}/results", EVAL)
    failed = [x["case_id"] for x in rows if x["status"] == "fail"]
    check("the single failure is the DAN probe, labelled heuristic", failed == ["jb-dan-persona"] and rows[[x["case_id"] for x in rows].index("jb-dan-persona")]["judge"] == "heuristic", failed)
    check("latency is real (>= the provider's delay) and counted for the 13 attack calls", sm["latency_ms"]["count"] == 13 and sm["latency_ms"]["min"] >= int(DELAY * 1000) - 5, sm["latency_ms"])
    check("the provider received the API key on every call (3 session probes + 13 attacks)", STUB["requests"] == 16 and STUB["with_key"] == 16, STUB)
    check("db_check ok and audit chain ok", run["db_check"]["digest_matches_audit"] is True and run["integrity"]["audit"]["ok"] is True)

    print("== kill the gateway mid-run (SIGKILL), restart, recover")
    s, r2 = call("POST", "/evaluations", EVAL, {"suite_id": "builtin-core", "model": "stub"})
    rid2 = r2["run_id"]
    t0 = time.time()
    while time.time() - t0 < 30:
        _, cur = call("GET", f"/evaluations/{rid2}", EVAL)
        if cur["status"] == "running" and cur["done"] >= 10: break
        time.sleep(0.05)
    check("run is genuinely mid-flight when killed", cur["status"] == "running" and 10 <= cur["done"] < 25, cur)
    gw.send_signal(signal.SIGKILL); gw.wait()
    check("gateway process died by SIGKILL", gw.returncode == -signal.SIGKILL)
    done_at_kill = cur["done"]
    gw = start_gateway()
    _, dead = call("GET", f"/evaluations/{rid2}", EVAL)
    _, dead_rows = call("GET", f"/evaluations/{rid2}/results", EVAL)
    check("after restart the killed run is 'interrupted', not 'running'", dead["status"] == "interrupted" and dead["finished"], dead)
    check("partial results survived the kill (at least what was visible before it)", len(dead_rows) >= done_at_kill and dead["done"] == len(dead_rows) < 25, (done_at_kill, len(dead_rows)))
    check("the partial rows are in order with no gaps", [x["seq"] for x in dead_rows] == list(range(1, len(dead_rows) + 1)))
    _, ents = call("GET", "/audit/entries?limit=500", ADMIN)
    check("audit log has evaluation_started and evaluation_interrupted for it, and no completed entry", [e["event"] for e in ents if e["data"].get("run_id") == rid2] == ["evaluation_started", "evaluation_interrupted"])
    _, v = call("GET", "/audit/verify", ADMIN)
    check("audit chain verifies after the hard kill", v["ok"] is True)
    _, first = call("GET", f"/evaluations/{rid}", EVAL)
    check("the earlier completed run is unchanged by the crash", first["summary"] == run["summary"] and first["results_digest"] == run["results_digest"] and first["db_check"]["digest_matches_audit"] is True)
    s, r3 = call("POST", "/evaluations", EVAL, {"suite_id": "builtin-core", "model": "stub"})
    run3 = wait_status(r3["run_id"], {"completed", "failed", "interrupted"})
    check("a new run is accepted and completes after the crash (no stale 'busy')", s == 202 and run3["status"] == "completed" and run3["summary"]["failed"] == 1, run3)
    _, hist = call("GET", "/evaluations", EVAL)
    check("history: completed, interrupted, completed (newest first)", [h["status"] for h in hist] == ["completed", "interrupted", "completed"], [h["status"] for h in hist])

    print("== no secrets anywhere")
    gw.send_signal(signal.SIGTERM); gw.wait(timeout=15)
    blobs = {"results API": json.dumps([hist, dead_rows, rows, run3]), "audit log": open(TMP + "/audit.jsonl").read(),
             "sqlite file": open(TMP + "/bayora.db", "rb").read().decode("latin-1")}
    for name, text in blobs.items():
        check(f"{name}: no provider API key", PROVIDER_KEY not in text)
        check(f"{name}: no JWT signing secret", JWT_SECRET not in text)
    check("results API / audit log / DB contain no bearer token (JWT prefix 'eyJ')", all("eyJ" not in blobs[k] for k in blobs))
finally:
    for p in (gw,):
        if p.poll() is None: p.kill()
    srv.shutdown()

print(f"\nResult: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
