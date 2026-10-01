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
import logging

import jwt
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from audit import AuditLog
from auth import ALGO, SECRET, require, verify
from llm_adapters import AdapterError, ID_RE, RateLimited, Registry
from store import Store
from evaluator import Runner, RunBusy, RunRefused
from suites import SuiteRegistry

LLM_URL = os.environ.get("LLM_URL", "http://llm:8000")
audit = AuditLog(os.environ.get("AUDIT_PATH", "/data/audit.jsonl"))
MODELS = Registry.load(os.environ.get("MODELS_CONFIG", os.path.join(os.path.dirname(__file__), "models.json")), LLM_URL)
app = FastAPI(title="Bayora policy gateway")

# Tests and blue-team defenses (defenses are never readable by red) live in SQLite on the
# same volume as the audit log, so they survive a restart.
store = Store(os.environ.get("DB_PATH") or os.path.join(os.path.dirname(audit.path), "bayora.db"))


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def need(authorization, scope):
    return require(authorization, scope, audit=audit)


def get_test(test_id: str) -> dict:
    t = store.get_test(test_id)
    if t is None:
        raise HTTPException(404, "unknown test")
    return t


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ---------------- red team ----------------
class Submit(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    # Optional conversation. The gateway namespaces it by tenant, so the LLM
    # only ever sees an opaque id and no tenant can name another's session.
    session_id: Optional[str] = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    # Which configured model to test (id from GET /models). Default: the configured default.
    model: Optional[str] = Field(default=None, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")


def llm_session(sub: str, sid: Optional[str]) -> Optional[str]:
    return None if sid is None else sha(f"{sub}:{sid}")[:32]


@app.post("/red/tests")
async def submit_test(body: Submit, authorization: Optional[str] = Header(None)):
    p = need(authorization, "test:submit")
    adapter = MODELS.get(body.model)
    if adapter is None:
        raise HTTPException(422, "unknown model")
    try:
        res = await adapter.generate(body.prompt, llm_session(p.sub, body.session_id))
    except RateLimited:
        audit.append("llm_rate_limited", "gateway", {"model": adapter.id})
        raise HTTPException(429, "model request limit reached")
    except AdapterError:
        audit.append("llm_error", "gateway", {"model": adapter.id})
        raise HTTPException(502, "model unavailable")
    response = res.text
    test_id = uuid.uuid4().hex[:12]
    store.create_test(test_id, body.prompt, response, adapter.id, res.latency_ms)
    # The audit log stores hashes, not content, so it can't leak payloads.
    audit.append("test_submitted", p.sub, {"test_id": test_id,
                                           "prompt_sha256": sha(body.prompt),
                                           "response_sha256": sha(response),
                                           "session": body.session_id is not None,
                                           "model": adapter.id, "latency_ms": res.latency_ms})
    return {"test_id": test_id, "status": "active", "response": response,
            "model": adapter.id, "latency_ms": res.latency_ms}


@app.get("/models")
def list_models(authorization: Optional[str] = Header(None)):
    """Any valid token may list models. Endpoints and key names are never returned."""
    verify(authorization)
    return MODELS.public()


@app.post("/red/tests/{test_id}/conclude")
def conclude_test(test_id: str, authorization: Optional[str] = Header(None)):
    p = need(authorization, "test:conclude")
    get_test(test_id)  # 404 if unknown
    if store.conclude(test_id):
        audit.append("test_concluded", p.sub, {"test_id": test_id})
    return {"test_id": test_id, "status": "concluded"}


# ---------------- blue team ----------------
@app.get("/blue/tests")
def blue_list(authorization: Optional[str] = Header(None)):
    need(authorization, "test:list")
    # Metadata only: no prompts or responses until a test concludes.
    return store.list_tests()


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
    store.add_defense(test_id, body.note)
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


# ---------------- demo UI ----------------
# DEMO ONLY: /ui/demo-tokens hands the browser a token for every role, which
# defeats tenant isolation. Off unless DEMO_UI=1, and refused for any caller
# on the red/blue/model networks (only the VM's published port may use it).
# With DEMO_UI=1 it MINTS fresh short-lived tokens per request with the
# gateway's existing signing secret, so the demo page never depends on the
# 12h tokens in .env. Normal auth is unchanged: these are ordinary scoped
# JWTs verified by auth.verify() like any other. Keep DEMO_SCOPES identical
# to scripts/setup_env.py SCOPES (tests/demo_token_test.py enforces this).
UI_DIR = os.path.join(os.path.dirname(__file__), "ui")
TENANT_NETS = ("172.28.1.", "172.28.2.", "172.28.3.")
DEMO_SCOPES = {
    "red":   ["test:submit", "test:conclude"],
    "blue":  ["test:list", "test:read", "test:defend"],
    "admin": ["audit:read"],
    "evaluator": ["eval:run", "eval:read"],
}
log = logging.getLogger("uvicorn.error")


def _demo_ttl() -> int:
    try:
        return max(5, min(3600, int(os.environ.get("DEMO_TOKEN_TTL", "900"))))
    except ValueError:
        return 900


@app.get("/ui/demo-tokens")
def demo_tokens(request: Request, response: Response):
    host = request.client.host if request.client else ""
    if os.environ.get("DEMO_UI") != "1" or host.startswith(TENANT_NETS):
        raise HTTPException(404, "not found")
    now, ttl = int(time.time()), _demo_ttl()
    response.headers["Cache-Control"] = "no-store"
    log.info("demo tokens minted (ttl=%ss) for %s", ttl, host)  # never logs the tokens
    return {role: jwt.encode({"sub": role, "scope": scope, "iat": now, "exp": now + ttl,
                              "jti": uuid.uuid4().hex, "demo": True}, SECRET, algorithm=ALGO)
            for role, scope in DEMO_SCOPES.items()}


@app.get("/ui")
def ui():
    return FileResponse(os.path.join(UI_DIR, "index.html"))


# ---------------- evaluation engine ----------------
# The runner drives this gateway's own routes in-process with short-lived tokens for the
# actors eval-red / eval-blue / eval-probe-*, so every request it makes is authenticated,
# scope-checked and audited exactly like a Red or Blue client's. See evaluator.py.
SUITES = SuiteRegistry.load(os.environ.get("SUITES_DIR", os.path.join(os.path.dirname(__file__), "suites")))


def _mint(sub: str, scope: list, ttl: int = 120, key: Optional[str] = None) -> str:
    now = int(time.time())
    return jwt.encode({"sub": sub, "scope": scope, "iat": now, "exp": now + ttl, "jti": uuid.uuid4().hex},
                      key or SECRET, algorithm=ALGO)


def _secret_values() -> list:
    names = ["RED_TOKEN", "BLUE_TOKEN", "ADMIN_TOKEN", "EVALUATOR_TOKEN", "ANCHOR_TOKEN"]
    names += [a.key_env for a in MODELS.adapters.values() if a.key_env]
    return [SECRET] + [os.environ.get(n, "") for n in names]


runner = Runner(app, audit, store, MODELS, SUITES, _mint, DEMO_SCOPES, _secret_values)
runner.recover()


class EvalRequest(BaseModel):
    suite_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    model: Optional[str] = Field(default=None, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")


def _get_run(run_id: str) -> dict:
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(404, "unknown evaluation")
    return run


@app.get("/models/{model_id}/health")
async def model_health(model_id: str, authorization: Optional[str] = Header(None)):
    """Probe a configured model's provider (reachable? credentials accepted? model present?) without spending
    a generation. The result never contains the endpoint, a key or a provider response body."""
    p = need(authorization, "eval:read")
    adapter = MODELS.adapters.get(model_id) if ID_RE.match(model_id) else None
    if adapter is None:
        raise HTTPException(404, "unknown model")
    h = await adapter.health()
    audit.append("provider_health_checked", p.sub, {"model": adapter.id, "status": h["status"]})
    return {"model": adapter.id, "provider": adapter.provider, "origin": adapter.origin, **h}


@app.get("/suites")
def list_suites(authorization: Optional[str] = Header(None)):
    need(authorization, "eval:read")
    return SUITES.public()


@app.post("/evaluations", status_code=202)
async def start_evaluation(body: EvalRequest, authorization: Optional[str] = Header(None)):
    p = need(authorization, "eval:run")
    try:
        run = runner.start(p.sub, body.model, body.suite_id)
    except RunBusy as e:
        raise HTTPException(409, "an evaluation is already running: " + str(e.run_id))
    except RunRefused as e:
        raise HTTPException(422, str(e))
    return runner.public_run(run)


@app.get("/evaluations")
def list_evaluations(authorization: Optional[str] = Header(None)):
    need(authorization, "eval:read")
    return [runner.public_run(r) for r in store.list_runs()]


@app.get("/evaluations/{run_id}")
def get_evaluation(run_id: str, authorization: Optional[str] = Header(None)):
    need(authorization, "eval:read")
    return runner.public_run(_get_run(run_id), with_check=True)


@app.get("/evaluations/{run_id}/results")
def get_evaluation_results(run_id: str, authorization: Optional[str] = Header(None)):
    need(authorization, "eval:read")
    return runner.public_results(_get_run(run_id))
