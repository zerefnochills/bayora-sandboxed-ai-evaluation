#!/usr/bin/env python3
"""No-Docker tests for the LLM adapter layer (gateway/llm_adapters.py + /models + /red/tests).

Providers are FAKE in-process servers that record what the gateway sent. This
checks our adapter code (request shape, key handling, session separation,
failure handling); it does not test any real model or cloud API.
    python3 tests/adapter_test.py      # needs: pip install fastapi httpx pyjwt
"""
import asyncio, importlib, importlib.util, json, os, sys, tempfile, time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
tmp = tempfile.mkdtemp()
SECRET_KEY = "sk-very-secret-123"
cfg = {"default": "mock", "models": [
    {"id": "mock", "provider": "mock", "endpoint": "http://llm"},
    {"id": "oa", "provider": "openai", "kind": "cloud", "name": "Fake OA", "endpoint": "http://fake-oa/v1",
     "model": "m-1", "api_key_env": "FAKE_OA_KEY", "max_tokens": 77},
    {"id": "oa2", "provider": "openai", "endpoint": "http://fake-oa/v1", "model": "m-2", "api_key_env": "FAKE_OA_KEY"},
    {"id": "an", "provider": "anthropic", "endpoint": "http://fake-an", "model": "a-1", "api_key_env": "FAKE_AN_KEY"},
    {"id": "nokey", "provider": "openai", "endpoint": "http://fake-oa/v1", "model": "m", "api_key_env": "NOT_SET_ANYWHERE"},
    {"id": "bad", "provider": "openai", "endpoint": "http://fake-bad/v1", "model": "m", "api_key_env": "FAKE_OA_KEY"},
    {"id": "off", "enabled": False, "provider": "openai", "endpoint": "http://x/v1"}]}
json.dump(cfg, open(tmp + "/models.json", "w"))
os.environ.update(JWT_SECRET="test-secret", AUDIT_PATH=tmp + "/audit.jsonl", MODELS_CONFIG=tmp + "/models.json",
                  FAKE_OA_KEY=SECRET_KEY, FAKE_AN_KEY=SECRET_KEY + "-an")
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx, jwt  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

llm = load(os.path.join(ROOT, "containers/llm/main.py"), "llm_app")
gw = importlib.import_module("main")
adapters = importlib.import_module("llm_adapters")

SEEN = []  # every request a fake provider received: (host, path, headers, json)
def fake_openai():
    a = FastAPI()
    @a.post("/v1/chat/completions")
    async def c(req: Request):
        b = await req.json(); SEEN.append(("oa", req.url.path, dict(req.headers), b))
        last = b["messages"][-1]["content"]
        return {"choices": [{"message": {"role": "assistant", "content": "oa-echo:" + last + ":hist=" + str(len(b["messages"]))}}]}
    return a
def fake_anthropic():
    a = FastAPI()
    @a.post("/v1/messages")
    async def m(req: Request):
        b = await req.json(); SEEN.append(("an", req.url.path, dict(req.headers), b))
        return {"content": [{"type": "text", "text": "an-echo:"}, {"type": "text", "text": b["messages"][-1]["content"]}]}
    return a
def fake_bad():
    a = FastAPI()
    @a.post("/v1/chat/completions")
    async def c(req: Request):
        return JSONResponse({"error": "boom " + req.headers.get("authorization", "")}, status_code=500)
    return a

APPS = {"llm": llm.app, "fake-oa": fake_openai(), "fake-an": fake_anthropic(), "fake-bad": fake_bad()}
class Router(httpx.AsyncBaseTransport):
    def __init__(self):
        self.t = {h: httpx.ASGITransport(app=a) for h, a in APPS.items()}
    async def handle_async_request(self, request):
        return await self.t[request.url.host].handle_async_request(request)
_real = httpx.AsyncClient
class Routed(_real):
    def __init__(self, *a, **k):
        k["transport"] = Router(); super().__init__(*a, **k)
httpx.AsyncClient = Routed  # adapters import the httpx module, so this routes their calls

def tok(sub, scope):
    return {"Authorization": "Bearer " + jwt.encode({"sub": sub, "scope": scope, "exp": int(time.time()) + 600}, "test-secret", "HS256")}
RED, RED2 = tok("red", ["test:submit", "test:conclude"]), tok("red2", ["test:submit"])
PASS = FAIL = 0
def check(name, cond):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name)

async def main():
    async with _real(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw") as c:
        sub = lambda h, **b: c.post("/red/tests", headers=h, json=b)
        print("== registry / listing")
        m = await c.get("/models", headers=RED)
        ids = [x["id"] for x in m.json()]
        check("GET /models lists enabled models only", m.status_code == 200 and ids == ["mock", "oa", "oa2", "an", "nokey", "bad"])
        check("/models never exposes endpoints, key names or keys",
              not any(k in json.dumps(m.json()) for k in ("fake-oa", "FAKE_OA_KEY", SECRET_KEY, "endpoint", "api_key")))
        check("/models reports key presence as a bool", {x["id"]: x["configured"] for x in m.json()}["nokey"] is False)
        check("/models requires authentication", (await c.get("/models")).status_code == 401)
        check("default model is used when none is given", (await sub(RED, prompt="hello")).json()["model"] == "mock")
        r = await sub(RED, prompt="hi", model="nope")
        check("unknown model -> 422", r.status_code == 422)
        r = await sub(RED, prompt="hi", model="off")
        check("disabled model is not selectable", r.status_code == 422)
        r = await sub(RED, prompt="hi", model="http://evil")
        check("model field can't smuggle a URL (validation)", r.status_code == 422)

        print("== OpenAI-compatible adapter")
        r = (await sub(RED, prompt="ping", model="oa")).json()
        host, path, hdr, body = SEEN[-1]
        check("calls {endpoint}/chat/completions", path == "/v1/chat/completions")
        check("sends bearer key from env", hdr.get("authorization") == "Bearer " + SECRET_KEY)
        check("sends configured model + max_tokens", body["model"] == "m-1" and body["max_tokens"] == 77)
        check("parses reply; returns model + latency", r["response"].startswith("oa-echo:ping") and r["model"] == "oa" and isinstance(r["latency_ms"], int))

        print("== Anthropic adapter")
        r = (await sub(RED, prompt="ping", model="an")).json()
        host, path, hdr, body = SEEN[-1]
        check("calls /v1/messages with x-api-key + version", path == "/v1/messages" and hdr.get("x-api-key") == SECRET_KEY + "-an" and "anthropic-version" in hdr)
        check("joins text blocks", r["response"] == "an-echo:ping")

        print("== session separation for stateless providers")
        await sub(RED, prompt="my code is 4711", model="oa", session_id="s1")
        await sub(RED, prompt="follow-up", model="oa", session_id="s1")
        check("same session: history is sent (3 prior msgs + new)", SEEN[-1][3]["messages"][0]["content"] == "my code is 4711" and len(SEEN[-1][3]["messages"]) == 3)
        await sub(RED, prompt="what is my code", model="oa", session_id="s2")
        check("other session: no history leaks", len(SEEN[-1][3]["messages"]) == 1 and "4711" not in json.dumps(SEEN[-1][3]))
        await sub(RED2, prompt="what is my code", model="oa", session_id="s1")
        check("same session NAME, other tenant: no leak", len(SEEN[-1][3]["messages"]) == 1 and "4711" not in json.dumps(SEEN[-1][3]))
        await sub(RED, prompt="what is my code", model="oa2", session_id="s1")
        check("same session, other model: separate history", len(SEEN[-1][3]["messages"]) == 1)
        await sub(RED, prompt="my code is 99", model="an", session_id="sa")
        await sub(RED, prompt="again", model="an", session_id="sa")
        check("anthropic sessions keep history too", len(SEEN[-1][3]["messages"]) == 3)
        await sub(RED, prompt="my code is 4711", model="mock", session_id="m1")
        a = (await sub(RED, prompt="what is my code", model="mock", session_id="m1")).json()["response"]
        b = (await sub(RED, prompt="what is my code", model="mock", session_id="m2")).json()["response"]
        check("mock: session recalls its own fact, other session doesn't", "4711" in a and "4711" not in b)

        print("== failure handling and secrets")
        r = await sub(RED, prompt="x", model="bad")
        check("provider HTTP 500 -> 502 'model unavailable'", r.status_code == 502 and r.json()["detail"] == "model unavailable")
        check("error response contains no key or provider body", SECRET_KEY not in r.text and "boom" not in r.text)
        r = await sub(RED, prompt="x", model="nokey")
        check("missing api key -> 502, no detail leak", r.status_code == 502 and "NOT_SET" not in r.text)
        log = open(os.environ["AUDIT_PATH"]).read()
        check("llm_error audited with model id", '"event": "llm_error"' in log and '"model": "bad"' in log)
        check("api keys never written to the audit log", SECRET_KEY not in log)
        check("successful entries record model + latency", '"model": "oa"' in log and '"latency_ms"' in log)
        check("audit chain still verifies", gw.audit.verify()["ok"])

        print("== registry validation")
        bad = [[{"id": "a", "provider": "nope"}], [{"id": "a", "provider": "mock", "endpoint": "http://x"}] * 2,
               [{"id": "a", "provider": "openai", "endpoint": "file:///etc/passwd"}], [{"id": "a b", "provider": "mock", "endpoint": "http://x"}], []]
        def raises(cfgs):
            try: adapters.Registry(cfgs); return False
            except ValueError: return True
        check("rejects unknown provider / duplicate / non-http endpoint / bad id / empty", all(raises(x) for x in bad))
        check("missing models.json falls back to mock", adapters.Registry.load(tmp + "/none.json", "http://llm").default == "mock")
        big = adapters.SessionStore(max_sessions=3, max_turns=2)
        for i in range(10): big.commit(f"k{i}", "q", "a")
        for i in range(5): big.commit("k9", "q", "a")
        check("session store bounded (sessions and turns)", len(big._s) <= 3 and len(big._s["k9"]) <= 4)
    print(f"\nResult: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)

asyncio.run(main())
