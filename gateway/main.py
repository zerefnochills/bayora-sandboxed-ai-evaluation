"""Bayora policy gateway.

The only component attached to all three tenant networks. Every cross-tenant
interaction is authenticated, scope-checked (ABAC, see auth.py) and audited
here.

Core rule: blue team cannot see a test's prompt/response until red team has
marked that test concluded.
"""
import hashlib
import os
import time
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from audit import AuditLog
from auth import require

LLM_URL = os.environ.get("LLM_URL", "http://llm:8000")
audit = AuditLog(os.environ.get("AUDIT_PATH", "/data/audit.jsonl"))
app = FastAPI(title="Bayora policy gateway")

TESTS: dict = {}     # test_id -> record (in memory for the PoC)
DEFENSES: dict = {}  # test_id -> list of blue-team notes (never readable by red)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def need(authorization, scope):
    return require(authorization, scope, audit=audit)


def get_test(test_id: str) -> dict:
    t = TESTS.get(test_id)
    if t is None:
        raise HTTPException(404, "unknown test")
    return t


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ---------------- red team ----------------
class Submit(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)


@app.post("/red/tests")
async def submit_test(body: Submit, authorization: Optional[str] = Header(None)):
    p = need(authorization, "test:submit")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(f"{LLM_URL}/generate", json={"prompt": body.prompt})
            r.raise_for_status()
            response = r.json()["response"]
    except (httpx.HTTPError, KeyError, ValueError):
        audit.append("llm_error", "gateway", {})
        raise HTTPException(502, "model unavailable")
    test_id = uuid.uuid4().hex[:12]
    TESTS[test_id] = {"status": "active", "prompt": body.prompt,
                      "response": response, "created": time.time()}
    # The audit log stores hashes, not content, so it can't leak payloads.
    audit.append("test_submitted", p.sub, {"test_id": test_id,
                                           "prompt_sha256": sha(body.prompt),
                                           "response_sha256": sha(response)})
    return {"test_id": test_id, "status": "active", "response": response}


@app.post("/red/tests/{test_id}/conclude")
def conclude_test(test_id: str, authorization: Optional[str] = Header(None)):
    p = need(authorization, "test:conclude")
    t = get_test(test_id)
    if t["status"] != "concluded":
        t["status"] = "concluded"
        audit.append("test_concluded", p.sub, {"test_id": test_id})
    return {"test_id": test_id, "status": "concluded"}


# ---------------- blue team ----------------
@app.get("/blue/tests")
def blue_list(authorization: Optional[str] = Header(None)):
    need(authorization, "test:list")
    # Metadata only: no prompts or responses until a test concludes.
    return [{"test_id": k, "status": v["status"]} for k, v in TESTS.items()]


@app.get("/blue/tests/{test_id}")
def blue_read(test_id: str, authorization: Optional[str] = Header(None)):
    p = need(authorization, "test:read")
    t = get_test(test_id)
    if t["status"] != "concluded":
        audit.append("early_access_denied", p.sub, {"test_id": test_id})
        raise HTTPException(403, "test still active; results not released")
    audit.append("results_released", p.sub, {"test_id": test_id})
    return {"test_id": test_id, "prompt": t["prompt"], "response": t["response"]}


class Defense(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


@app.post("/blue/tests/{test_id}/defense")
def blue_defend(test_id: str, body: Defense, authorization: Optional[str] = Header(None)):
    p = need(authorization, "test:defend")
    t = get_test(test_id)
    if t["status"] != "concluded":
        raise HTTPException(403, "test still active")
    DEFENSES.setdefault(test_id, []).append(body.note)
    audit.append("defense_recorded", p.sub, {"test_id": test_id,
                                              "note_sha256": sha(body.note)})
    return {"test_id": test_id, "recorded": True}


# ---------------- admin / audit ----------------
@app.get("/audit/verify")
def audit_verify(authorization: Optional[str] = Header(None)):
    need(authorization, "audit:read")
    return audit.verify()


@app.get("/audit/entries")
def audit_entries(limit: int = 50, authorization: Optional[str] = Header(None)):
    need(authorization, "audit:read")
    return audit.tail(max(1, min(limit, 500)))
