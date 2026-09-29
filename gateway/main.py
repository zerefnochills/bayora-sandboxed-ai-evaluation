"""Bayora policy gateway.

The only component attached to all three tenant networks. Every cross-tenant
interaction is authenticated, policy-checked and audited here.

Core rule: blue team cannot see a test's prompt/response until red team has
marked that test concluded.

Week-1 placeholder: static per-tenant bearer tokens. Week 2 replaces this
with scoped JWTs / ABAC.
"""
import hashlib
import hmac
import os
import time
import uuid
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from audit import AuditLog

LLM_URL = os.environ.get("LLM_URL", "http://llm:8000")
TOKENS = {
    "red": os.environ["RED_TOKEN"],
    "blue": os.environ["BLUE_TOKEN"],
    "admin": os.environ["ADMIN_TOKEN"],
}
audit = AuditLog(os.environ.get("AUDIT_PATH", "/data/audit.jsonl"))
app = FastAPI(title="Bayora policy gateway")

TESTS: dict = {}     # test_id -> record (in memory for the PoC)
DEFENSES: dict = {}  # test_id -> list of blue-team notes (never readable by red)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def authenticate(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    presented = authorization[7:].encode()
    who = None
    for tenant, secret in TOKENS.items():  # no early exit
        if hmac.compare_digest(presented, secret.encode()):
            who = tenant
    if who is None:
        audit.append("auth_failed", "unknown", {})
        raise HTTPException(401, "invalid token")
    return who


def require(authorization: Optional[str], role: str) -> str:
    who = authenticate(authorization)
    if who != role:
        audit.append("policy_violation", who, {"needed_role": role})
        raise HTTPException(403, "not permitted for this tenant")
    return who


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
    require(authorization, "red")
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
    audit.append("test_submitted", "red", {"test_id": test_id,
                                           "prompt_sha256": sha(body.prompt),
                                           "response_sha256": sha(response)})
    return {"test_id": test_id, "status": "active", "response": response}


@app.post("/red/tests/{test_id}/conclude")
def conclude_test(test_id: str, authorization: Optional[str] = Header(None)):
    require(authorization, "red")
    t = get_test(test_id)
    if t["status"] != "concluded":
        t["status"] = "concluded"
        audit.append("test_concluded", "red", {"test_id": test_id})
    return {"test_id": test_id, "status": "concluded"}


# ---------------- blue team ----------------
@app.get("/blue/tests")
def blue_list(authorization: Optional[str] = Header(None)):
    require(authorization, "blue")
    # Metadata only: no prompts or responses until a test concludes.
    return [{"test_id": k, "status": v["status"]} for k, v in TESTS.items()]


@app.get("/blue/tests/{test_id}")
def blue_read(test_id: str, authorization: Optional[str] = Header(None)):
    require(authorization, "blue")
    t = get_test(test_id)
    if t["status"] != "concluded":
        audit.append("early_access_denied", "blue", {"test_id": test_id})
        raise HTTPException(403, "test still active; results not released")
    audit.append("results_released", "blue", {"test_id": test_id})
    return {"test_id": test_id, "prompt": t["prompt"], "response": t["response"]}


class Defense(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


@app.post("/blue/tests/{test_id}/defense")
def blue_defend(test_id: str, body: Defense, authorization: Optional[str] = Header(None)):
    require(authorization, "blue")
    t = get_test(test_id)
    if t["status"] != "concluded":
        raise HTTPException(403, "test still active")
    DEFENSES.setdefault(test_id, []).append(body.note)
    audit.append("defense_recorded", "blue", {"test_id": test_id,
                                              "note_sha256": sha(body.note)})
    return {"test_id": test_id, "recorded": True}


# ---------------- admin / audit ----------------
@app.get("/audit/verify")
def audit_verify(authorization: Optional[str] = Header(None)):
    require(authorization, "admin")
    return audit.verify()


@app.get("/audit/entries")
def audit_entries(limit: int = 50, authorization: Optional[str] = Header(None)):
    require(authorization, "admin")
    return audit.tail(max(1, min(limit, 500)))
