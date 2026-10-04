"""Bayora policy gateway.

The only component attached to all three tenant networks. Every cross-tenant
interaction is authenticated, scope-checked (ABAC, see auth.py) and audited
here.

Core rule: blue team cannot see a test's prompt/response until red team has
marked that test concluded.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from typing import Optional

import httpx
import logging

import jwt
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from audit import AuditLog
from auth import ALGO, SECRET, require, verify
from llm_adapters import AdapterError, ID_RE, RateLimited, Registry
from store import Store
from evaluator import CONTROLS, Runner, RunBusy, RunRefused
import evidence
import users
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


def _check_account(p):
    """Tokens for web-app accounts ("user:<name>") die with the account: disabled, role changed, or password
    changed/reset (token_version bumped) all make an old token worthless immediately."""
    u = store.get_user(p.sub[len(users.USER_PREFIX):])
    if (u is None or not u["active"] or p.claims.get("ver") != u["token_version"] or p.claims.get("role") != u["role"]
            or not p.scope <= set(users.ROLE_SCOPES[u["role"]])):
        raise HTTPException(401, "session is no longer valid")


def need(authorization, scope):
    p = require(authorization, scope, audit=audit)       # one verification path: signature, expiry, scope
    if p.sub.startswith(users.USER_PREFIX):
        _check_account(p)
    return p


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


def _mint(sub: str, scope: list, ttl: int = 120, key: Optional[str] = None, claims: Optional[dict] = None) -> str:
    now = int(time.time())
    return jwt.encode({**(claims or {}), "sub": sub, "scope": scope, "iat": now, "exp": now + ttl, "jti": uuid.uuid4().hex},
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


def _can_see_all(p) -> bool:
    return "eval:admin" in p.scope


def _get_run(run_id: str, p=None) -> dict:
    """404 (never 403) for a run the caller does not own, so run ids cannot be probed."""
    run = store.get_run(run_id)
    if run is None or (p is not None and not _can_see_all(p) and run["created_by"] != p.sub):
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


@app.get("/evaluation-info")
def evaluation_info(authorization: Optional[str] = Header(None)):
    """What the evaluation tests, straight from the loaded suite definitions and the runner's control table."""
    need(authorization, "eval:read")
    suites = []
    for s in SUITES.suites.values():
        cats = {}
        for a in s["attacks"]:
            cats.setdefault(a["category"], []).append({"id": a["id"], "severity": a["severity"], "description": a["description"],
                                                       "expected_property": a["expected_property"]})
        suites.append({"id": s["id"], "version": s["version"], "name": s["name"], "categories": [
            {"category": c, "probes": ps, "why_it_matters": evidence.RISK.get(c, evidence.GENERIC_RISK)[0],
             "what_to_consider": evidence.RISK.get(c, evidence.GENERIC_RISK)[1]} for c, ps in sorted(cats.items())]})
    ctl = {}
    for cid, _stage, cat, sev, exp in CONTROLS:
        ctl.setdefault(cat, []).append({"id": cid, "severity": sev, "expected_property": exp})
    return {"suites": suites, "controls": [{"category": c, "controls": v} for c, v in ctl.items()]}


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
        active = store.get_run(e.run_id) if e.run_id else None
        mine = active is not None and (_can_see_all(p) or active["created_by"] == p.sub)
        raise HTTPException(409, ("an evaluation is already running: " + str(e.run_id)) if mine
                            else "another evaluation is running; try again shortly")
    except RunRefused as e:
        raise HTTPException(422, str(e))
    return runner.public_run(run)


@app.get("/evaluations")
def list_evaluations(authorization: Optional[str] = Header(None)):
    p = need(authorization, "eval:read")
    return [runner.public_run(r) for r in store.list_runs(owner=None if _can_see_all(p) else p.sub)]


@app.get("/evaluations/{run_id}")
def get_evaluation(run_id: str, authorization: Optional[str] = Header(None)):
    p = need(authorization, "eval:read")
    return runner.public_run(_get_run(run_id, p), with_check=True)


def _finished_run(run_id: str, p) -> dict:
    run = _get_run(run_id, p)
    if run["status"] == "running":
        raise HTTPException(409, "evaluation is still running")
    return run


def _evidence(run: dict) -> dict:
    return evidence.build_bundle(runner.public_run(run, with_check=True), runner.public_results(run),
                                 SUITES.get(run["suite_id"]), audit.tail(100000), audit.verify(),
                                 version=os.environ.get("BAYORA_VERSION", "dev"))


@app.get("/evaluations/{run_id}/evidence")
def get_evidence(run_id: str, authorization: Optional[str] = Header(None)):
    """Self-describing JSON bundle for offline checking with scripts/verify_evidence.py."""
    p = need(authorization, "eval:read")
    bundle = _evidence(_finished_run(run_id, p))
    return Response(json.dumps(bundle, indent=1, sort_keys=True), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="bayora-evidence-%s.json"' % run_id,
                             "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@app.get("/evaluations/{run_id}/report")
def get_report(run_id: str, authorization: Optional[str] = Header(None)):
    """Printable HTML report rendered from the evidence bundle (everything escaped, CSP-locked)."""
    p = need(authorization, "eval:read")
    page = evidence.render_report(_evidence(_finished_run(run_id, p)))
    return HTMLResponse(page, headers={"Content-Security-Policy": evidence.CSP, "Cache-Control": "no-store",
                                       "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})


@app.get("/evaluations/{run_id}/results")
def get_evaluation_results(run_id: str, authorization: Optional[str] = Header(None)):
    p = need(authorization, "eval:read")
    return runner.public_results(_get_run(run_id, p))


# ---------------- accounts (web app logins) ----------------
# Account tokens are ordinary scoped JWTs ("user:<name>", scopes from users.ROLE_SCOPES) plus role and
# token_version claims that need() re-checks against the account on every request. See users.py.
USER_TTL = int(os.environ.get("USER_TOKEN_TTL", "3600"))
SIGNUP_OPEN = os.environ.get("ALLOW_SIGNUP") == "1"
GUARD_USER, GUARD_IP, GUARD_SIGNUP = users.LoginGuard(5, 900), users.LoginGuard(30, 900), users.LoginGuard(10, 3600)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class BootstrapRequest(BaseModel):
    code: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class NewUser(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: str = Field(default="user", pattern="^(user|admin)$")


class UserPatch(BaseModel):
    role: Optional[str] = Field(default=None, pattern="^(user|admin)$")
    active: Optional[bool] = None


class PasswordChange(BaseModel):
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=1, max_length=256)


def _issue(u: dict) -> dict:
    token = _mint(users.USER_PREFIX + u["username"], users.ROLE_SCOPES[u["role"]], USER_TTL,
                  claims={"role": u["role"], "ver": u["token_version"]})
    return {"token": token, "expires_in": USER_TTL, "user": {"username": u["username"], "role": u["role"]}}


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _policy(fn, *a):
    try:
        return fn(*a)
    except users.PolicyError as e:
        raise HTTPException(422, str(e))


@app.get("/auth/status")
def auth_status():
    return {"bootstrap_needed": store.count_users() == 0, "signup_open": SIGNUP_OPEN}


@app.post("/auth/bootstrap")
def auth_bootstrap(body: BootstrapRequest, request: Request):
    """Create the FIRST admin. Needs the code from users.bootstrap_code(); closed once any account exists."""
    if store.count_users() > 0:
        raise HTTPException(409, "already set up")
    ip = "boot:" + _ip(request)
    if GUARD_IP.check(ip):
        raise HTTPException(429, "too many attempts")
    if not hmac.compare_digest(body.code, users.bootstrap_code(SECRET)):
        GUARD_IP.fail(ip)
        audit.append("bootstrap_failed", "anonymous", {})
        raise HTTPException(403, "invalid setup code")
    name = _policy(users.check_username, body.username.strip().lower())
    _policy(users.check_password, body.password, name)
    if not store.create_user(name, users.hash_password(body.password), "admin", "bootstrap"):
        raise HTTPException(409, "already set up")
    audit.append("user_created", "bootstrap", {"username": name, "role": "admin"})
    return _issue(store.get_user(name))


@app.post("/auth/login")
def auth_login(body: LoginRequest, request: Request):
    name = body.username.strip().lower()
    ukey, ikey = "u:" + name[:64], "ip:" + _ip(request)
    wait = max(GUARD_USER.check(ukey), GUARD_IP.check(ikey))
    if wait:
        audit.append("login_failed", "anonymous", {"username": name[:32], "reason": "throttled"})
        raise HTTPException(429, "too many failed attempts; try again later", headers={"Retry-After": str(wait)})
    u = store.get_user(name, with_hash=True)
    good = users.verify_password(body.password, u["password_hash"] if u else users.DUMMY_HASH)   # same work either way
    if not (u and good and u["active"]):
        GUARD_USER.fail(ukey)
        GUARD_IP.fail(ikey)
        audit.append("login_failed", "anonymous", {"username": name[:32], "reason": "disabled" if (u and good) else "bad credentials"})
        raise HTTPException(401, "invalid username or password")
    GUARD_USER.clear(ukey)
    store.touch_login(name)
    audit.append("user_login", users.USER_PREFIX + name, {"role": u["role"]})
    return _issue(store.get_user(name))


@app.post("/auth/register", status_code=201)
def auth_register(body: LoginRequest, request: Request):
    """Self-service signup. Off unless ALLOW_SIGNUP=1 (then 404, so its existence is not advertised)."""
    if not SIGNUP_OPEN:
        raise HTTPException(404, "not found")
    ip = "signup:" + _ip(request)
    if GUARD_SIGNUP.check(ip):
        raise HTTPException(429, "too many attempts")
    GUARD_SIGNUP.fail(ip)
    name = _policy(users.check_username, body.username.strip().lower())
    _policy(users.check_password, body.password, name)
    if not store.create_user(name, users.hash_password(body.password), "user", "signup"):
        raise HTTPException(409, "username is taken")
    audit.append("user_created", "signup", {"username": name, "role": "user"})
    return _issue(store.get_user(name))


@app.get("/auth/me")
def auth_me(authorization: Optional[str] = Header(None)):
    p = need(authorization, "eval:read")
    if not p.sub.startswith(users.USER_PREFIX):
        raise HTTPException(403, "not an account token")
    prof = users.public_profile(store.get_profile(p.sub[len(users.USER_PREFIX):]))
    return {**prof, "active": True, "created_by": store.get_user(prof["username"])["created_by"], "scope": sorted(p.scope)}


class ProfilePatch(BaseModel):
    """Everything a user may change about themselves. extra=forbid: a request that also names role, active,
    scopes or any other field is rejected outright rather than partly applied."""
    model_config = ConfigDict(extra="forbid")
    display_name: Optional[StrictStr] = None
    nickname: Optional[StrictStr] = None
    email: Optional[StrictStr] = None
    bio: Optional[StrictStr] = None
    show_username: Optional[StrictBool] = None
    reduce_motion: Optional[StrictBool] = None


@app.patch("/auth/profile")
def auth_profile(body: ProfilePatch, authorization: Optional[str] = Header(None)):
    p = need(authorization, "eval:read")
    if not p.sub.startswith(users.USER_PREFIX):
        raise HTTPException(403, "not an account token")
    name = p.sub[len(users.USER_PREFIX):]          # the target is always the caller; there is no way to name another account
    sent = body.model_dump(exclude_unset=True)
    if not sent:
        raise HTTPException(422, "nothing to update")
    clean = _policy(users.check_profile, sent)
    store.set_profile(name, clean)
    audit.append("profile_updated", p.sub, {"fields": sorted(clean)})
    return users.public_profile(store.get_profile(name))


@app.post("/auth/change-password")
def auth_change_password(body: PasswordChange, request: Request, authorization: Optional[str] = Header(None)):
    p = need(authorization, "eval:read")
    if not p.sub.startswith(users.USER_PREFIX):
        raise HTTPException(403, "not an account token")
    name = p.sub[len(users.USER_PREFIX):]
    ukey = "u:" + name
    if GUARD_USER.check(ukey):
        raise HTTPException(429, "too many failed attempts; try again later")
    u = store.get_user(name, with_hash=True)
    if not users.verify_password(body.old_password, u["password_hash"]):
        GUARD_USER.fail(ukey)
        audit.append("password_change_failed", p.sub, {})
        raise HTTPException(401, "current password is wrong")
    _policy(users.check_password, body.new_password, name)
    store.set_password(name, users.hash_password(body.new_password))
    audit.append("password_changed", p.sub, {})
    return _issue(store.get_user(name))   # every older token is now invalid; this one is the new session


def _target(username: str) -> dict:
    u = store.get_user(username) if users.USERNAME_RE.match(username) else None
    if u is None:
        raise HTTPException(404, "unknown user")
    return u


@app.get("/admin/users")
def admin_list_users(authorization: Optional[str] = Header(None)):
    need(authorization, "user:admin")
    return [users.public_user(u) for u in store.list_users()]


@app.post("/admin/users", status_code=201)
def admin_create_user(body: NewUser, authorization: Optional[str] = Header(None)):
    p = need(authorization, "user:admin")
    name = _policy(users.check_username, body.username.strip().lower())
    _policy(users.check_password, body.password, name)
    if not store.create_user(name, users.hash_password(body.password), body.role, p.sub):
        raise HTTPException(409, "username is taken")
    audit.append("user_created", p.sub, {"username": name, "role": body.role})
    return users.public_user(store.get_user(name))


@app.patch("/admin/users/{username}")
def admin_update_user(username: str, body: UserPatch, authorization: Optional[str] = Header(None)):
    p = need(authorization, "user:admin")
    u = _target(username)
    demoting = u["role"] == "admin" and u["active"] and (body.role == "user" or body.active is False)
    if demoting and store.count_active_admins() <= 1:
        raise HTTPException(409, "cannot remove the last active admin")
    store.set_user_fields(username, body.role, body.active)
    audit.append("user_updated", p.sub, {"username": username, **({"role": body.role} if body.role else {}),
                                         **({"active": body.active} if body.active is not None else {})})
    return users.public_user(store.get_user(username))


@app.post("/admin/users/{username}/reset-password")
def admin_reset_password(username: str, body: PasswordReset, authorization: Optional[str] = Header(None)):
    p = need(authorization, "user:admin")
    _target(username)
    _policy(users.check_password, body.new_password, username)
    store.set_password(username, users.hash_password(body.new_password))
    audit.append("password_reset", p.sub, {"username": username})
    return {"ok": True}


@app.get("/admin/overview")
def admin_overview(authorization: Optional[str] = Header(None)):
    need(authorization, "user:admin")
    us, runs = store.list_users(), store.list_runs(limit=100000)
    v = audit.verify()
    day = time.time() - 86400
    count = lambda key: {k: sum(1 for r in runs if (r[key[0]] or "unknown") == k) for k in sorted({(r[key[0]] or "unknown") for r in runs})}
    return {"generated": time.time(),
            "users": {"total": len(us), "active": sum(u["active"] for u in us), "admins": sum(u["role"] == "admin" and u["active"] for u in us)},
            "runs": {"total": len(runs), "last_24h": sum(r["created"] >= day for r in runs), "by_status": count(("status",)),
                     "by_origin": count(("provider_kind",)), "running": runner.active_run},
            "audit": {"ok": v["ok"], "entries": v["entries"], "anchor": {"status": __import__("evaluator").anchor_verification(v["anchor"]), **v["anchor"]}},
            "models": [{"id": m["id"], "name": m["name"], "origin": m["origin"], "configured": m["configured"]} for m in MODELS.public()]}


# ---------------- the web app (/app) ----------------
# Real sign-in, evaluations, reports and the admin area. Unlike /ui (a demo console that mints demo tokens)
# this page never needs DEMO_UI. It is locked down: no external resources, one inline script whose hash is
# the only script the CSP allows, and the page builds its DOM with textContent (no innerHTML).
def _load_app_page():
    page = open(os.path.join(UI_DIR, "app.html"), encoding="utf-8").read()
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    # The printable report opens as a blob: page, and a blob: page INHERITS this policy (on top of its own). So
    # the report's one fixed print-button script must be allowed here too, by hash. No 'unsafe-inline'.
    csp = ("default-src 'none'; script-src 'sha256-%s' '%s'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; "
           "base-uri 'none'; form-action 'none'; frame-ancestors 'none'" % (digest, evidence.SCRIPT_HASH))
    return page, csp


APP_PAGE, APP_CSP = _load_app_page()


@app.get("/app")
def web_app():
    return HTMLResponse(APP_PAGE, headers={"Content-Security-Policy": APP_CSP, "Cache-Control": "no-store",
                                           "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                                           "Referrer-Policy": "no-referrer"})
