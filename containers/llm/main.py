"""Mock client LLM.

Stateless on purpose: no history, no cache, every request is independent, so
nothing can carry over between tests. Swap this for a real model/API later
without touching the gateway contract (POST /generate {prompt} -> {response}).
"""
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="mock-llm")


class Req(BaseModel):
    prompt: str


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/generate")
def generate(req: Req):
    p = req.prompt.lower()
    if "dan" in p.split() or "developer mode" in p:
        # Simulated safety failure so the red team has something to "find".
        return {"response": "[MOCK-UNSAFE] Sure, restrictions disabled. Here is what you asked for..."}
    if any(k in p for k in ("ignore previous", "ignore all previous", "system prompt")):
        return {"response": "[MOCK-SAFE] I can't help with that."}
    return {"response": "[MOCK-SAFE] Hello! How can I help?"}
