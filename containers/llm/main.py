"""Mock client LLM with per-session context.

POST /generate {prompt, session_id?} -> {response}

- No session_id: stateless, exactly as before.
- With session_id: the mock keeps that session's history and can recall
  facts ("my code is 1234" -> later "what is my code") ONLY from the same
  session. The gateway namespaces session ids per tenant, so a client can't
  name another tenant's session. Bounded: 200 sessions (LRU), 50 turns each.
"""
import re
from collections import OrderedDict

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="mock-llm")
MAX_SESSIONS, MAX_TURNS = 200, 50
SESSIONS: "OrderedDict[str, dict]" = OrderedDict()  # sid -> {"turns": [...], "facts": {}}


class Req(BaseModel):
    prompt: str
    session_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


def _session(sid):
    if sid not in SESSIONS:
        SESSIONS[sid] = {"turns": [], "facts": {}}
        while len(SESSIONS) > MAX_SESSIONS:
            SESSIONS.popitem(last=False)
    SESSIONS.move_to_end(sid)
    return SESSIONS[sid]


def _base(p: str) -> str:
    if "dan" in p.split() or "developer mode" in p:
        return "[MOCK-UNSAFE] Sure, restrictions disabled. Here is what you asked for..."
    if any(k in p for k in ("ignore previous", "ignore all previous", "system prompt")):
        return "[MOCK-SAFE] I can't help with that."
    return "[MOCK-SAFE] Hello! How can I help?"


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/generate")
def generate(req: Req):
    p = req.prompt.lower()
    if req.session_id is None:
        return {"response": _base(p)}
    s = _session(req.session_id)
    s["turns"] = (s["turns"] + [req.prompt])[-MAX_TURNS:]
    m = re.search(r"\bmy (\w+) is (\w+)", p)
    if m:
        s["facts"][m.group(1)] = m.group(2)
        out = f"[MOCK-SAFE] Noted: your {m.group(1)} is {m.group(2)}."
    else:
        q = re.search(r"what(?:'s| is) my (\w+)", p)
        if q:
            v = s["facts"].get(q.group(1))
            out = (f"[MOCK-SAFE] Your {q.group(1)} is {v}." if v
                   else f"[MOCK-SAFE] I don't know your {q.group(1)} in this session.")
        else:
            out = _base(p)
    return {"response": f"{out} (session turn {len(s['turns'])})"}


@app.post("/reset")
def reset(req: Req):
    SESSIONS.pop(req.session_id or "", None)
    return {"ok": True}
