#!/usr/bin/env python3
"""No-Docker test: per-session LLM context can't cross sessions or tenants.

Wires the real gateway to the real mock LLM in-process. Run from repo root:
    python3 tests/session_test.py
Needs: pip install fastapi httpx pyjwt
"""
import asyncio, importlib.util, os, sys, tempfile, time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
os.environ.update(JWT_SECRET="test-secret", AUDIT_PATH=tempfile.mkdtemp() + "/audit.jsonl")
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx, jwt  # noqa: E402

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

llm = load(os.path.join(ROOT, "containers/llm/main.py"), "llm_app")
gw = importlib.import_module("main")

# Route the gateway's outbound LLM call to the in-process LLM app.
_real = httpx.AsyncClient
class Routed(_real):
    def __init__(self, *a, **k):
        k["transport"] = httpx.ASGITransport(app=llm.app); super().__init__(*a, **k)
gw.httpx.AsyncClient = Routed

def tok(sub, scope):
    return {"Authorization": "Bearer " + jwt.encode(
        {"sub": sub, "scope": scope, "exp": int(time.time()) + 600}, "test-secret", "HS256")}
RED = tok("red", ["test:submit", "test:conclude"])
RED2 = tok("red2", ["test:submit", "test:conclude"])   # a second tenant-like principal

PASS = FAIL = 0
def check(name, cond):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name)

async def main():
    async with _real(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw") as c:
        say = lambda h, sid, text: c.post("/red/tests", headers=h, json={"prompt": text, "session_id": sid})
        r = (await say(RED, "s1", "my code is 4711")).json()["response"]
        check("session s1 stores a fact", "Noted" in r)
        r = (await say(RED, "s1", "what is my code")).json()["response"]
        check("same session recalls it", "4711" in r)
        r = (await say(RED, "s2", "what is my code")).json()["response"]
        check("other session of same tenant can't see it", "4711" not in r and "don't know" in r)
        r = (await say(RED2, "s1", "what is my code")).json()["response"]
        check("same session NAME under another tenant can't see it", "4711" not in r)
        r = (await c.post("/red/tests", headers=RED, json={"prompt": "what is my code"})).json()["response"]
        check("sessionless request is stateless", "4711" not in r and "turn" not in r)
        r = await say(RED, "../evil", "hi")
        check("malformed session id rejected (422)", r.status_code == 422)
        stored = {k for k in llm.SESSIONS}
        check("LLM sees opaque ids, not raw tenant/session names", "s1" not in stored and all(len(k) == 32 for k in stored))
        for i in range(llm.MAX_SESSIONS + 20):
            llm.generate(llm.Req(prompt="x", session_id=f"flood{i}"))
        check("session store is bounded", len(llm.SESSIONS) <= llm.MAX_SESSIONS)
    print(f"\nResult: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)

asyncio.run(main())
