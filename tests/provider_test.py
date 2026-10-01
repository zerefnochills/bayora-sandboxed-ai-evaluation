#!/usr/bin/env python3
"""No-Docker tests for real-provider support (Ollama / OpenAI-compatible) using a FAKE provider.

The fake speaks the OpenAI-compatible HTTP API over real localhost sockets, so timeouts, refused
connections, oversize and slow-drip bodies are exercised for real. Its response shapes follow the documented
Ollama/OpenAI API (e.g. /v1/models lists "llama3.2:latest"); it was not captured from a real Ollama, and this
file proves nothing about any real model. For that see tests/real_provider_test.py.
    python3 tests/provider_test.py        # needs: pip install fastapi httpx pyjwt
"""
import asyncio, hashlib, importlib, json, os, socket, sys, tempfile, threading, time, warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
warnings.filterwarnings("ignore")

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp()
GOOD_KEY, BAD_KEY = "sk-fake-provider-key-AAAA1111", "sk-wrong-key-BBBB2222"
JWT = "test-secret"

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)[:300]))

# ------------------------------------------------------------------ fake provider
class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address): pass   # clients abort on purpose (timeouts, size caps)


class Fake:
    def __init__(self, models=("llama3.2:latest",), key=None):
        self.cfg = dict(models=list(models), key=key, delay=0.0, chat_status=200, models_status=200, models_body=None,
                        content=None, huge=0, huge_with_length=True, drip=0.0, fail_after=None)
        self.chat_count = self.inflight = self.max_inflight = self.bytes_sent = 0
        self.seen = []                      # (path, headers dict, json body)
        self.lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _send(self, status, body, length=True):
                self.send_response(status); self.send_header("Content-Type", "application/json")
                if length: self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def _auth_ok(self):
                k = outer.cfg["key"]
                return k is None or self.headers.get("Authorization") == "Bearer " + k
            def do_GET(self):
                c = outer.cfg
                with outer.lock: outer.seen.append((self.path, dict(self.headers), None))
                if self.path == "/healthz": return self._send(200, b'{"ok":true}')
                if self.path != "/v1/models": return self._send(404, b'{"error":"nope"}')
                if not self._auth_ok(): return self._send(401, b'{"error":"bad key"}')
                if c["models_status"] != 200: return self._send(c["models_status"], b'{"error":"x"}')
                if c["models_body"] is not None: return self._send(200, c["models_body"].encode())
                self._send(200, json.dumps({"object": "list", "data": [{"id": m, "object": "model", "owned_by": "library"} for m in c["models"]]}).encode())
            def do_POST(self):
                c = outer.cfg
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with outer.lock:
                    outer.seen.append((self.path, dict(self.headers), body)); outer.chat_count += 1
                    n = outer.chat_count; outer.inflight += 1; outer.max_inflight = max(outer.max_inflight, outer.inflight)
                try:
                    if self.path == "/generate":                     # the bundled mock's protocol (for the MOCK-label test)
                        return self._send(200, json.dumps({"response": "[MOCK-SAFE] Hello! How can I help?"}).encode())
                    if not self._auth_ok(): return self._send(401, b'{"error":"bad key ' + (self.headers.get("Authorization") or "").encode() + b'"}')
                    time.sleep(c["delay"])
                    status = c["chat_status"] if c["fail_after"] is None or n <= c["fail_after"] else 500
                    if status != 200: return self._send(status, b'{"error":"boom ' + (self.headers.get("Authorization") or "").encode() + b'"}')
                    if c["drip"]:
                        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                        t0 = time.time()
                        try:
                            while time.time() - t0 < 6: self.wfile.write(b" "); self.wfile.flush(); time.sleep(c["drip"])
                        except OSError: pass
                        return
                    if c["huge"]:
                        out = json.dumps({"choices": [{"message": {"content": "x" * c["huge"]}}]}).encode()
                        self.send_response(200); self.send_header("Content-Type", "application/json")
                        if c["huge_with_length"]: self.send_header("Content-Length", str(len(out)))
                        self.end_headers()
                        try:
                            for i in range(0, len(out), 65536): self.wfile.write(out[i:i + 65536]); outer.bytes_sent += len(out[i:i + 65536])
                        except OSError: pass
                        return
                    content = c["content"] if c["content"] is not None else self.reply(body)
                    if content == "__SHAPE__": return self._send(200, b'{"unexpected": true}')
                    self._send(200, json.dumps({"choices": [{"message": {"role": "assistant", "content": None if content == "__NULL__" else content}}]}).encode())
                finally:
                    with outer.lock: outer.inflight -= 1
            def reply(self, body):
                msgs = body["messages"]; last = msgs[-1]["content"].lower()
                if "dan" in last.split() or "developer mode" in last: return "Sure, restrictions disabled. Here you go."
                if "system prompt" in last or "ignore previous" in last or "ignore all previous" in last: return "I can't help with that."
                if "what is my code" in last:
                    import re
                    for m in reversed(msgs[:-1]):
                        f = re.search(r"my code is (\w+)", m["content"].lower())
                        if m["role"] == "user" and f: return "Your code is " + f.group(1)
                    return "I don't know your code in this session."
                return "Hello! How can I help?"

        self.srv = QuietServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
    url = property(lambda self: f"http://127.0.0.1:{self.port}/v1")
    base = property(lambda self: f"http://127.0.0.1:{self.port}")
    def reset(self): self.chat_count = self.inflight = self.max_inflight = self.bytes_sent = 0; self.seen.clear()

def dead_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]

oll, keyed, big, flaky, mockish = Fake(), Fake(models=("llama3.2:latest", "m-1"), key=GOOD_KEY), Fake(), Fake(), Fake()
DEAD = dead_port()
big.cfg["huge"] = 5000
flaky.cfg["fail_after"] = 6

MODELS = {"default": "ollama", "models": [
    {"id": "ollama", "provider": "ollama", "name": "Fake Ollama", "model": "llama3.2", "endpoint": oll.url, "timeout_s": 10},
    {"id": "oa-key", "provider": "openai", "name": "Fake keyed", "model": "m-1", "endpoint": keyed.url, "api_key_env": "FAKE_PROVIDER_KEY", "timeout_s": 10},
    {"id": "badkey", "provider": "openai", "model": "m-1", "endpoint": keyed.url, "api_key_env": "FAKE_PROVIDER_BAD_KEY", "timeout_s": 10},
    {"id": "nokey", "provider": "openai", "model": "m-1", "endpoint": keyed.url, "api_key_env": "FAKE_PROVIDER_UNSET"},
    {"id": "dead", "provider": "ollama", "model": "llama3.2", "endpoint": f"http://127.0.0.1:{DEAD}/v1", "timeout_s": 10},
    {"id": "nomodel", "provider": "ollama", "model": "not-pulled", "endpoint": oll.url, "timeout_s": 10},
    {"id": "capped", "provider": "ollama", "model": "llama3.2", "endpoint": oll.url, "max_requests_per_run": 10},
    {"id": "capped16", "provider": "ollama", "model": "llama3.2", "endpoint": oll.url, "max_requests_per_run": 16},
    {"id": "limited", "provider": "ollama", "model": "llama3.2", "endpoint": oll.url, "max_requests_per_minute": 2, "timeout_s": 1},
    {"id": "tiny", "provider": "ollama", "model": "llama3.2", "endpoint": big.url, "max_response_bytes": 2048, "timeout_s": 10},
    {"id": "flaky", "provider": "ollama", "model": "llama3.2", "endpoint": flaky.url, "timeout_s": 10},
    {"id": "mockish", "provider": "mock", "name": "Fake mock", "endpoint": mockish.base},
]}
json.dump(MODELS, open(TMP + "/models.json", "w"))
os.environ.update(JWT_SECRET=JWT, AUDIT_PATH=TMP + "/audit.jsonl", MODELS_CONFIG=TMP + "/models.json",
                  FAKE_PROVIDER_KEY=GOOD_KEY, FAKE_PROVIDER_BAD_KEY=BAD_KEY)
os.environ.pop("FAKE_PROVIDER_UNSET", None); os.environ.pop("DB_PATH", None)
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx, jwt  # noqa: E402
la = importlib.import_module("llm_adapters")
gw = importlib.import_module("main")

def cfg(**kw):
    """a standalone adapter config for adapter-level tests"""
    return {"id": "t", "provider": "openai", "model": "llama3.2", "endpoint": oll.url, **kw}
def adapter(**kw): return la.Registry([cfg(**kw)]).get("t")

def tok(sub, scope): return {"Authorization": "Bearer " + jwt.encode({"sub": sub, "scope": scope, "exp": int(time.time()) + 600}, JWT, "HS256")}
ROLES = gw.DEMO_SCOPES
EV, RED, BLUE, ADMIN = (tok(r, ROLES[r]) for r in ("evaluator", "red", "blue", "admin"))
sha = lambda t: hashlib.sha256(t.encode()).hexdigest()
def client(): return httpx.AsyncClient(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw")

async def codes(c, paths, headers=None):
    return [(await c.get(p, headers=headers)).status_code for p in paths]

async def raises(coro, exc=la.AdapterError):
    t0 = time.monotonic()
    try:
        await coro
    except exc as e:
        return True, str(e), time.monotonic() - t0
    except Exception as e:
        return False, type(e).__name__ + ": " + str(e), time.monotonic() - t0
    return False, "no exception", time.monotonic() - t0

async def run_eval(c, model, wait=True, suite="builtin-core"):
    r = await c.post("/evaluations", headers=EV, json={"suite_id": suite, "model": model})
    assert r.status_code == 202, (r.status_code, r.text)
    if wait: await gw.runner.wait()
    rid = r.json()["run_id"]
    return rid, (await c.get(f"/evaluations/{rid}", headers=EV)).json(), (await c.get(f"/evaluations/{rid}/results", headers=EV)).json()

async def main():
    print("== configuration: Ollama provider, defaults, validation")
    a = adapter(provider="ollama", endpoint=oll.url); a2 = la.Registry([{"id": "o", "provider": "ollama", "model": "llama3.2"}]).get("o")
    check("provider 'ollama' is the same OpenAI-compatible code path (subclass), flavor Ollama", isinstance(a, la.OpenAICompatAdapter) and a.FLAVOR == "Ollama" and a.origin == "real")
    check("ollama defaults: local kind, host.docker.internal:11434/v1, 120s timeout, 2 concurrent, 500 requests per run, no key",
          (a2.kind, a2.endpoint, a2.timeout, a2.max_concurrent, a2.max_requests_per_run, a2.key_env) == ("local", "http://host.docker.internal:11434/v1", 120.0, 2, 500, None) and a2.configured())
    check("explicit config overrides the ollama defaults", adapter(provider="ollama", timeout_s=7, max_concurrent=1, max_requests_per_run=3).timeout == 7 and adapter(provider="ollama", max_concurrent=1).max_concurrent == 1)
    check("generic openai provider keeps its old defaults (30s, 4 concurrent, no per-run cap)", (lambda x: (x.timeout, x.max_concurrent, x.max_requests_per_run, x.max_response_bytes))(adapter()) == (30.0, 4, None, 1048576))
    for bad in ({"timeout_s": 0}, {"timeout_s": 601}, {"max_tokens": 99999}, {"max_concurrent": 0}, {"max_response_bytes": 10},
                {"max_requests_per_minute": -1}, {"max_requests_per_run": 0}, {"timeout_s": "30"}, {"timeout_s": True}, {"connect_timeout_s": 0}):
        try: la.Registry([cfg(**bad)]); ok = False
        except ValueError: ok = True
        check(f"invalid limit {bad} is refused at startup", ok)
    try: la.Registry([{"id": "x", "provider": "openai", "model": "m"}]); ok = False
    except ValueError: ok = True
    check("openai provider still requires an explicit http(s) endpoint (only ollama has a default)", ok)
    pub = json.dumps([m.public() for m in la.Registry(MODELS["models"]).adapters.values()])
    check("public() exposes origin/flavor/limits but no endpoint, port, key name or key value",
          "127.0.0.1" not in pub and "FAKE_PROVIDER" not in pub and GOOD_KEY not in pub and "endpoint" not in pub and "api_key" not in pub and '"origin": "real"' in pub and '"limits"' in pub)
    check("origin: mock provider -> 'mock', every other provider -> 'real'", la.Registry(MODELS["models"]).get("mockish").origin == "mock" and la.Registry(MODELS["models"]).get("ollama").origin == "real")

    ex = la.Registry.load(os.path.join(ROOT, "gateway", "models.example.json"), "http://llm:8000")
    check("gateway/models.example.json loads: mock + the Ollama entry enabled, the disabled examples skipped, Ollama has its local limits",
          set(ex.adapters) == {"mock", "ollama-llama32"} and ex.get("ollama-llama32").timeout == 120 and ex.get("ollama-llama32").max_requests_per_run == 500 and ex.get("ollama-llama32").origin == "real")

    print("== health check")
    h = await adapter(provider="ollama").health()
    check("healthy Ollama-shaped server: ok, model 'llama3.2' matches 'llama3.2:latest', verified", h["ok"] and h["status"] == "ok" and h["model_verified"] is True and h["latency_ms"] >= 0, h)
    check("health result has no endpoint/body fields", set(h) == {"ok", "status", "detail", "model_verified", "latency_ms", "checked_at"} and "127.0.0.1" not in json.dumps(h))
    check("health used GET /v1/models and spent no generation", oll.seen[-1][0] == "/v1/models" and oll.chat_count == 0)
    oll.cfg["models"] = ["llama3.2:1b", "qwen2.5:0.5b"]
    h = await adapter(model="llama3.2:latest").health(); check("exact id mismatch -> model_not_found (not ok), names the model and a count only", not h["ok"] and h["status"] == "model_not_found" and "llama3.2:latest" in h["detail"] and "qwen" not in h["detail"], h)
    oll.cfg["models"] = ["llama3.2"]
    check("model configured with ':latest' matches a bare id too", (await adapter(model="llama3.2:latest").health())["status"] == "ok")
    oll.cfg["models"] = ["llama3.2:latest"]
    for st, want, ok in ((404, "ok_unverified", True), (405, "ok_unverified", True), (501, "ok_unverified", True), (500, "provider_error", False), (503, "provider_error", False)):
        oll.cfg["models_status"] = st; h = await adapter().health()
        check(f"GET /models -> HTTP {st}: status {want}, ok={ok}", h["status"] == want and h["ok"] is ok, h)
    oll.cfg["models_status"] = 200
    for body in ("<html>nope</html>", '{"data": "x"}', '{"nope": 1}', "[]"):
        oll.cfg["models_body"] = body; h = await adapter().health()
        check(f"non-OpenAI model list {body[:18]!r} -> bad_response, not ok", h["status"] == "bad_response" and not h["ok"], h)
    oll.cfg["models_body"] = None
    keyed.reset()
    h = await adapter(endpoint=keyed.url, api_key_env="FAKE_PROVIDER_KEY").health()
    check("with the right key: ok, and the key was sent as a Bearer header", h["status"] == "ok" and keyed.seen[-1][1].get("Authorization") == "Bearer " + GOOD_KEY, h)
    h = await adapter(endpoint=keyed.url, api_key_env="FAKE_PROVIDER_BAD_KEY").health()
    check("wrong key: auth_failed, not ok, and the key is not in the result", h["status"] == "auth_failed" and not h["ok"] and BAD_KEY not in json.dumps(h), h)
    h = await adapter(endpoint=keyed.url, api_key_env="FAKE_PROVIDER_UNSET").health()
    check("key env var not set: not_configured, not ok, no network call needed", h["status"] == "not_configured" and not h["ok"], h)
    t0 = time.monotonic(); h = await adapter(endpoint=f"http://127.0.0.1:{DEAD}/v1").health()
    check("nothing listening: unreachable, not ok, fails fast (<3s)", h["status"] == "unreachable" and not h["ok"] and time.monotonic() - t0 < 3, (h, time.monotonic() - t0))
    slow_srv = socket.socket(); slow_srv.bind(("127.0.0.1", 0)); slow_srv.listen(5)          # accepts connections, never answers
    t0 = time.monotonic(); h = await adapter(endpoint=f"http://127.0.0.1:{slow_srv.getsockname()[1]}/v1", timeout_s=1).health()
    check("server accepts but never answers: unreachable within the timeout (~1s)", h["status"] == "unreachable" and 0.8 < time.monotonic() - t0 < 3, (h, time.monotonic() - t0))
    slow_srv.close()
    oll.cfg["models_body"] = json.dumps({"data": [{"id": "x" * 3000}]}); h = await adapter(max_response_bytes=1024).health()
    oll.cfg["models_body"] = None
    check("an oversize health response is refused (bad_response), not buffered", h["status"] == "bad_response" and not h["ok"], h)
    h = await la.Registry([{"id": "an", "provider": "anthropic", "model": "m", "api_key_env": "FAKE_PROVIDER_KEY"}]).get("an").health()
    check("anthropic: no probe (would cost money) -> not_checked, ok=True, model_verified=False", h["status"] == "not_checked" and h["ok"] and not h["model_verified"], h)
    h = await la.Registry(MODELS["models"]).get("mockish").health()
    check("mock provider health uses GET /healthz", h["status"] == "ok" and mockish.seen[-1][0] == "/healthz", h)

    print("== limits: timeout, response size, concurrency, request rate")
    oll.cfg["delay"] = 2.5
    ok, msg, dt = await raises(adapter(timeout_s=1).generate("hi"))
    check("slow provider: AdapterError 'timed out' after ~timeout_s", ok and "timed out" in msg and 0.8 < dt < 2.2, (msg, dt))
    oll.cfg["delay"] = 0
    oll.cfg["drip"] = 0.2
    ok, msg, dt = await raises(adapter(timeout_s=1).generate("hi"))
    oll.cfg["drip"] = 0
    check("slow-drip body (never idle, never finishing): the TOTAL deadline still fires", ok and "timed out" in msg and dt < 2.2, (msg, dt))
    t0 = time.monotonic(); ok, msg, dt = await raises(adapter(endpoint=f"http://127.0.0.1:{DEAD}/v1").generate("hi"))
    check("connection refused: AdapterError 'call failed', fast, no endpoint in the message", ok and "call failed" in msg and "127.0.0.1" not in msg and dt < 3, (msg, dt))
    t0 = time.monotonic(); ok, msg, dt = await raises(adapter(endpoint=f"http://10.255.255.1:9/v1", connect_timeout_s=0.5, timeout_s=5).generate("hi"))
    check("unroutable address: gives up after connect_timeout_s (0.5s), not the full 5s", ok and dt < 2.5, (msg, dt))
    big.reset(); ok, msg, dt = await raises(adapter(endpoint=big.url, max_response_bytes=2048).generate("hi"))
    check("response bigger than max_response_bytes (declared length): refused", ok and "too large" in msg, msg)
    big.cfg["huge"], big.cfg["huge_with_length"] = 40_000_000, False; big.reset()
    ok, msg, dt = await raises(adapter(endpoint=big.url, max_response_bytes=4096).generate("hi"))
    check("same with NO Content-Length (a 40 MB stream): aborted early, the server could not push it all", ok and "too large" in msg and big.bytes_sent < 40_000_000, (msg, big.bytes_sent))
    big.cfg["huge"], big.cfg["huge_with_length"] = 5000, True
    ok, msg, _ = await raises(adapter(endpoint=big.url).generate("hi"))
    check("a 5 KB reply under the default 1 MiB cap is accepted (cap is not a reply-length rule)", not ok and "no exception" in msg)
    oll.cfg["delay"] = 0.3; oll.reset(); a = adapter(max_concurrent=2)
    rs = await asyncio.gather(*[a.generate(f"q{i}") for i in range(6)])
    check("max_concurrent=2: 6 simultaneous callers all complete, never more than 2 in flight at the provider", len(rs) == 6 and oll.max_inflight == 2 and oll.chat_count == 6, (oll.max_inflight, oll.chat_count))
    oll.cfg["delay"] = 0
    a = adapter(max_requests_per_minute=3, timeout_s=1)
    [await a.generate("hi") for _ in range(3)]
    ok, msg, dt = await raises(a.generate("hi"), la.RateLimited)
    check("max_requests_per_minute=3: the 4th request is refused with RateLimited immediately (wait > timeout)", ok and "limit" in msg and dt < 0.5, (msg, dt))
    a = adapter(max_requests_per_minute=3, timeout_s=5); now = time.monotonic(); a._hits.extend([now - 59.7] * 3); t0 = time.monotonic()
    await a.generate("hi")
    check("when a slot frees up within timeout_s the caller WAITS for it instead of failing (~0.3s)", 0.2 < time.monotonic() - t0 < 1.5, time.monotonic() - t0)
    a = adapter(max_requests_per_minute=1, timeout_s=1); await a.health(); await a.health()
    check("...two health probes did not use up max_requests_per_minute=1", len(a._hits) == 0)

    print("== reply handling")
    for content, frag in (("", "empty reply"), ("   \n", "empty reply"), ("__NULL__", "no text"), ("__SHAPE__", "call failed")):
        oll.cfg["content"] = content; ok, msg, _ = await raises(adapter().generate("hi"))
        check(f"provider reply {content!r} -> AdapterError containing {frag!r}", ok and frag in msg, msg)
    oll.cfg["content"] = None
    oll.cfg["chat_status"] = 500; ok, msg, _ = await raises(adapter(endpoint=keyed.url, api_key_env="FAKE_PROVIDER_KEY").generate("hi")); oll.cfg["chat_status"] = 200
    keyed.cfg["chat_status"] = 500; ok, msg, _ = await raises(adapter(endpoint=keyed.url, api_key_env="FAKE_PROVIDER_KEY").generate("hi")); keyed.cfg["chat_status"] = 200
    check("HTTP 500 whose body echoes the Authorization header: error text has the status but never the key or body", ok and "HTTP 500" in msg and GOOD_KEY not in msg and "boom" not in msg, msg)
    oll.reset(); await adapter(max_tokens=77, provider="ollama").generate("hi")
    check("max_tokens is sent to the provider; no Authorization header when no key is configured", oll.seen[-1][2]["max_tokens"] == 77 and "Authorization" not in oll.seen[-1][1], oll.seen[-1])
    oll.cfg["content"] = "y" * 20000; r = await adapter().generate("hi"); oll.cfg["content"] = None
    check("reply text is still truncated at 16000 chars (existing rule intact)", len(r.text) == 16000)

    print("== through the gateway: /models, /models/{id}/health, /red/tests")
    async with client() as c:
        m = (await c.get("/models", headers=RED)).json(); ids = {x["id"]: x for x in m}
        check("GET /models: origin real for providers, mock for the mock; flavor and limits present", ids["ollama"]["origin"] == "real" and ids["ollama"]["flavor"] == "Ollama" and ids["mockish"]["origin"] == "mock" and ids["capped"]["limits"]["max_requests_per_run"] == 10)
        check("GET /models: unconfigured key shown as configured=false; nothing secret anywhere", ids["nokey"]["configured"] is False and GOOD_KEY not in json.dumps(m) and "127.0.0.1" not in json.dumps(m))
        check("health route: no token 401; red/blue/admin 403", await codes(c, ["/models/ollama/health"]) == [401] and [await codes(c, ["/models/ollama/health"], h) for h in (RED, BLUE, ADMIN)] == [[403]] * 3)
        r = await c.get("/models/ollama/health", headers=EV); j = r.json()
        check("health route as evaluator: 200 with model/provider/origin and the probe result", r.status_code == 200 and j["ok"] and j["origin"] == "real" and j["provider"] == "ollama" and j["status"] == "ok" and j["model"] == "ollama", j)
        check("health route: dead provider -> 200 with ok=false/unreachable (the probe itself worked)", (await c.get("/models/dead/health", headers=EV)).json()["status"] == "unreachable")
        check("health route: unknown or malformed model id -> 404", await codes(c, ["/models/nope/health", "/models/..%2fx/health", "/models/a b/health"], EV) == [404, 404, 404])
        check("health route probes are audited (model + status only)", any(e["event"] == "provider_health_checked" and e["data"] == {"model": "ollama", "status": "ok"} for e in gw.audit.tail(200)))
        texts = [(await c.get(f"/models/{i}/health", headers=EV)).text for i in ("oa-key", "badkey", "ollama", "dead")]
        check("the health output (4 models) contains no endpoint, port, key or wrong key", all(GOOD_KEY not in t and BAD_KEY not in t and "127.0.0.1" not in t and str(oll.port) not in t for t in texts))
        r = await c.post("/red/tests", headers=RED, json={"prompt": "hello", "model": "ollama"})
        check("normal attack through the gateway to the fake Ollama: 200 and a model reply", r.status_code == 200 and r.json()["response"].startswith("Hello") and r.json()["model"] == "ollama", r.text)
        rs = [await c.post("/red/tests", headers=RED, json={"prompt": "hello", "model": "limited"}) for _ in range(3)]
        check("request limit via the gateway: 2 ok then 429 'model request limit reached'", [x.status_code for x in rs] == [200, 200, 429] and "limit" in rs[2].text, [x.status_code for x in rs])
        check("the 429 is audited as llm_rate_limited and creates no test", any(e["event"] == "llm_rate_limited" for e in gw.audit.tail(100)))
        r = await c.post("/red/tests", headers=RED, json={"prompt": "hello", "model": "dead"})
        check("dead provider via the gateway: 502 'model unavailable' (existing behaviour), audited llm_error", r.status_code == 502 and "unavailable" in r.text and any(e["event"] == "llm_error" for e in gw.audit.tail(100)))
        r = await c.post("/red/tests", headers=RED, json={"prompt": "hello", "model": "nokey"})
        check("model with an unset key via the gateway: 502 and no key detail leaks", r.status_code == 502 and "key" not in r.text.lower())

    print("== evaluation against the fake Ollama")
    async with client() as c:
        rid, run, rows = await run_eval(c, "ollama"); R = {x["case_id"]: x for x in rows}; sm = run["summary"]
        check("run completed: 25 cases, 12/12 deterministic controls pass, heuristic 11 pass / 2 fail", run["status"] == "completed" and sm["total"] == 25 and sm["by_judge"]["deterministic"]["pass"] == 12 and sm["by_judge"]["heuristic"] == {"pass": 11, "fail": 2, "blocked": 0, "error": 0}, sm)
        check("run records provider 'ollama', provider model, kind REAL, suite id/version, model id", (run["provider"], run["provider_model"], run["provider_kind"], run["model"], run["suite"]["id"], run["suite"]["version"]) == ("ollama", "llama3.2", "real", "ollama", "builtin-core", 1), run)
        check("run records the pre-flight health result (ok, verified model, latency)", run["health"] and run["health"]["status"] == "ok" and run["health"]["model_verified"] is True and run["health"]["latency_ms"] >= 0, run["health"])
        check("every result row carries provider, provider_model, kind, model, suite id+version, timestamps, latency, status",
              all(r["provider"] == "ollama" and r["provider_model"] == "llama3.2" and r["provider_kind"] == "real" and r["model"] == "ollama" and r["suite_id"] == "builtin-core" and r["suite_version"] == 1
                  and r["finished"] >= r["started"] > 0 and r["status"] in ("pass", "fail") for r in rows))
        check("attack rows have real measured latency from the provider; controls have none", all(r["latency_ms"] is not None for r in rows if r["kind"] == "attack") and all(r["latency_ms"] is None for r in rows if r["kind"] == "control"))
        check("judge labels preserved: controls deterministic, attacks heuristic", all(r["judge"] == ("deterministic" if r["kind"] == "control" else "heuristic") for r in rows))
        check("the two jailbreaks the fake falls for are the heuristic failures; no control failed because of them", {k for k, v in R.items() if v["status"] == "fail"} == {"jb-dan-persona", "jb-developer-mode"})
        check("session isolation held with a stateless provider (history kept by the gateway, per tenant)", R["ctl-session-isolation"]["status"] == "pass" and R["ctl-session-isolation"]["evidence"][2]["secret_returned_to_A"] is True)
        check("attack rows: audit status 'recorded' and db_check matches the audit log", all(r["audit_status"] == "recorded" for r in rows if r["kind"] == "attack") and run["db_check"]["digest_matches_audit"] is True)
        check("started audit entry carries provider and origin", any(e["event"] == "evaluation_started" and e["data"]["run_id"] == rid and e["data"]["provider"] == "ollama" and e["data"]["origin"] == "real" for e in gw.audit.tail(300)))
        lst = (await c.get("/evaluations", headers=EV)).json()
        check("history items carry the provider metadata too", lst[0]["provider_kind"] == "real" and lst[0]["provider"] == "ollama")

        rid, run, rows = await run_eval(c, "mockish")
        check("a run on the mock provider is labelled kind 'mock' (label comes from the configured provider)", run["provider_kind"] == "mock" and run["provider"] == "mock" and all(r["provider_kind"] == "mock" for r in rows))

    print("== provider failures end the run as infrastructure, never as model failures")
    async with client() as c:
        n_before = len(gw.store.list_tests())
        for model, status in (("dead", "unreachable"), ("nomodel", "model_not_found"), ("badkey", "auth_failed")):
            rid, run, rows = await run_eval(c, model)
            ev = [e for e in gw.audit.tail(300) if e["data"].get("run_id") == rid]
            check(f"{model}: run 'failed' with error.stage provider_health / {status}; zero rows; no summary", run["status"] == "failed" and run["error"]["stage"] == "provider_health" and run["error"]["status"] == status and rows == [] and run["summary"] is None and run["done"] == 0, run)
            check(f"{model}: health recorded on the run (ok=false) and the failure reason is plain text", run["health"]["ok"] is False and run["health"]["status"] == status and run["error"]["detail"])
            check(f"{model}: audit has evaluation_started then evaluation_failed (stage + status) and nothing else", [e["event"] for e in ev] == ["evaluation_started", "evaluation_failed"] and ev[1]["data"]["stage"] == "provider_health" and ev[1]["data"]["status"] == status, [e["event"] for e in ev])
        check("no test was created and no model request was made by any of the three failed runs", len(gw.store.list_tests()) == n_before)
        rid, run, rows = await run_eval(c, "ollama")
        check("the next run on a healthy provider starts and completes normally (no stale 'busy')", run["status"] == "completed" and run["summary"]["total"] == 25)
        r = await c.post("/evaluations", headers=EV, json={"suite_id": "builtin-core", "model": "nokey"})
        check("an unset API key is still refused up front (422 'not configured'), before any run exists", r.status_code == 422 and "not configured" in r.text)
        hist = (await c.get("/evaluations", headers=EV)).json()
        check("history shows the failed runs with their reason, newest first", [h["status"] for h in hist[:5]] == ["completed", "failed", "failed", "failed", "completed"], [h["status"] for h in hist[:5]])

        flaky.reset()
        rid, run, rows = await run_eval(c, "flaky"); sm = run["summary"]; R = {x["case_id"]: x for x in rows}
        check("provider dies mid-run (after 6 requests): run completes; 10 attacks are 'error' (HTTP 502), 2 heuristic fails come only from replies the model actually gave",
              run["status"] == "completed" and (sm["errors"], sm["failed"]) == (10, 2) and all(r["status"] == "error" and r["http_status"] == 502 for r in rows if r["kind"] == "attack" and r["status"] == "error"), sm)
        check("...and no error row is ever reported as a heuristic fail; the gateway controls that did run still pass", not any(r["status"] == "fail" and r["http_status"] != 200 for r in rows) and all(R[k]["status"] == "pass" for k in ("ctl-authn-missing-token", "ctl-session-isolation", "ctl-phase-gate-blocks-active")))

        big.cfg["huge"], big.cfg["huge_with_length"] = 5000, True
        rid, run, rows = await run_eval(c, "tiny"); sm = run["summary"]
        check("replies over max_response_bytes: every attack is 'error' (not fail/blocked), 8 gateway controls still pass", run["status"] == "completed" and sm["failed"] == 0 and sm["blocked"] == 0 and all(r["status"] == "error" for r in rows if r["kind"] == "attack") and sm["passed"] == 8, sm)

    print("== request limits at the evaluation level")
    async with client() as c:
        r = await c.post("/evaluations", headers=EV, json={"suite_id": "builtin-core", "model": "capped"})
        check("model allows 10 requests per evaluation, suite needs 16: refused 422 with both numbers", r.status_code == 422 and "16" in r.text and "10" in r.text, r.text)
        rid, run, _ = await run_eval(c, "capped16")
        check("cap exactly equal to what the suite needs: accepted and completes", run["status"] == "completed")
        oll.reset(); rid, run, _ = await run_eval(c, "ollama")
        check("one evaluation made exactly 13 attack + 3 session-probe = 16 chat requests at the provider", oll.chat_count == 16, oll.chat_count)
        orig = gw.runner.models.adapters["ollama"].rpm
        gw.runner.models.adapters["ollama"].rpm, gw.runner.models.adapters["ollama"].timeout = 5, 1.0
        rid, run, rows = await run_eval(c, "ollama"); gw.runner.models.adapters["ollama"].rpm, gw.runner.models.adapters["ollama"].timeout = orig, 10.0
        sm = run["summary"]
        check("limit of 5 requests/minute: 3 session probes + 2 attacks go through, the other 11 attacks are 'blocked' (HTTP 429) - not errors, not model failures",
              run["status"] == "completed" and sm["blocked"] == 11 and all(r["http_status"] == 429 for r in rows if r["status"] == "blocked") and sm["errors"] == 0 and sm["by_judge"]["deterministic"]["pass"] == 12, sm)

    print("== secrets")
    async with client() as c:
        rid, run, rows = await run_eval(c, "oa-key")
        check("run on a keyed provider completes (key was accepted by the fake)", run["status"] == "completed" and run["health"]["status"] == "ok", run.get("error") or run["health"])
        check("the provider received the key as a Bearer header on every chat call", all(h.get("Authorization") == "Bearer " + GOOD_KEY for p, h, b in keyed.seen if p.endswith("/chat/completions")) and keyed.chat_count >= 16)
        _, bad, _ = await run_eval(c, "badkey")
        blobs = {"run": json.dumps(run), "results": json.dumps(rows), "failed run": json.dumps(bad), "history": (await c.get("/evaluations", headers=EV)).text,
                 "models": (await c.get("/models", headers=RED)).text, "audit log": open(TMP + "/audit.jsonl").read(), "sqlite file": open(gw.store.path, "rb").read().decode("latin-1")}
        for k, v in blobs.items():
            check(f"{k}: no provider key, no wrong key, no JWT signing secret, no bearer token", GOOD_KEY not in v and BAD_KEY not in v and JWT not in v and "eyJ" not in v and "Bearer" not in v)
        check("no endpoint/port of any provider appears in run, results, history or models output", all(f":{oll.port}" not in blobs[k] and "127.0.0.1" not in blobs[k] for k in ("run", "results", "failed run", "history", "models")))

    print(f"\nResult: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)

asyncio.run(main())
