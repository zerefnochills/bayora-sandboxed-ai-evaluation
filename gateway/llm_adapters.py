"""Model-agnostic LLM adapter layer.

    Gateway -> LLMAdapter.generate(prompt, session) -> Mock | OpenAI-compatible | Anthropic

Providers
  mock      the existing mock-llm container (POST {endpoint}/generate). Keeps its own per-session history.
  openai    any OpenAI-compatible /chat/completions API: cloud APIs AND local servers
            (Ollama, vLLM, llama.cpp, LM Studio all speak this).
  ollama    an Ollama server (its OpenAI-compatible /v1 API) with local-friendly defaults.
  anthropic Anthropic Messages API.

Limits enforced here, per model (all optional; see gateway/models.example.json)
  timeout_s (whole request) / connect_timeout_s, max_tokens (sent to the provider),
  max_response_bytes (the body is read as a stream and aborted when it exceeds this),
  max_concurrent, max_requests_per_minute (callers wait for a slot, up to timeout_s,
  then get HTTP 429), max_requests_per_run (an evaluation that needs more is refused).

Security rules enforced here
  * Endpoints, model names and key *names* come only from the server-side
    config file (models.json). Requests can pick a model id, nothing else,
    so a client can't point the gateway at an arbitrary URL (no SSRF).
  * API keys are read from the gateway's environment at call time. They are
    never stored on adapter objects, logged, returned by any API, or included
    in error text.
  * Real providers are stateless, so the gateway keeps conversation history
    itself, keyed by (model id, tenant-namespaced session id), bounded in
    size. That preserves the session-isolation guarantee for every provider.
"""
import asyncio
import contextlib
import json
import os
import re
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Optional

import httpx

MAX_REPLY_CHARS = 16000
HEALTHY = {"ok", "ok_unverified", "not_checked"}   # health statuses an evaluation may start on
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


class AdapterError(Exception):
    """Provider failure. The message is safe to log: it never contains secrets or provider bodies."""


class RateLimited(AdapterError):
    """The model's configured request limit was reached (the gateway answers 429)."""


def _num(cfg, key, default, lo, hi):
    v = cfg.get(key, default)
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise ValueError(f"model {cfg.get('id')!r}: {key} must be a number between {lo} and {hi}")
    return v


@dataclass
class GenResult:
    text: str
    latency_ms: int


class SessionStore:
    """Bounded per-(model, session) history for stateless providers."""

    def __init__(self, max_sessions=200, max_turns=20):
        self.max_sessions, self.max_turns = max_sessions, max_turns
        self._s: "OrderedDict[str, list]" = OrderedDict()

    def messages(self, key, prompt):
        hist = list(self._s.get(key, [])) if key else []
        return hist + [{"role": "user", "content": prompt}]

    def commit(self, key, prompt, reply):
        if not key:
            return
        h = self._s.setdefault(key, [])
        h += [{"role": "user", "content": prompt}, {"role": "assistant", "content": reply}]
        del h[:-2 * self.max_turns]
        self._s.move_to_end(key)
        while len(self._s) > self.max_sessions:
            self._s.popitem(last=False)


class Adapter:
    FLAVOR = "Provider"
    DEFAULTS: dict = {}

    def __init__(self, cfg, store):
        cfg = {**self.DEFAULTS, **cfg}
        self.id, self.provider = cfg["id"], cfg["provider"]
        self.name = cfg.get("name", cfg["id"])
        self.kind = cfg.get("kind", "cloud" if self.provider == "anthropic" else "local")
        self.model = cfg.get("model", "")
        self.endpoint = cfg.get("endpoint", "").rstrip("/")
        self.key_env = cfg.get("api_key_env")
        self.timeout = float(_num(cfg, "timeout_s", 30, 1, 600))
        self.connect_timeout = min(float(_num(cfg, "connect_timeout_s", 5, 0.5, 60)), self.timeout)
        self.max_tokens = int(_num(cfg, "max_tokens", 512, 1, 8192))
        self.max_tokens_param = cfg.get("max_tokens_param", "max_tokens")
        self.max_response_bytes = int(_num(cfg, "max_response_bytes", 1_048_576, 1024, 16_777_216))
        self.max_concurrent = int(_num(cfg, "max_concurrent", 4, 1, 64))
        self.rpm = int(_num(cfg, "max_requests_per_minute", 0, 0, 100_000))          # 0 = unlimited
        cap = cfg.get("max_requests_per_run")
        self.max_requests_per_run = None if cap is None else int(_num(cfg, "max_requests_per_run", cap, 1, 1_000_000))
        self._store = store
        self._hits = deque()
        self._sem, self._sem_loop = None, None

    @property
    def origin(self) -> str:
        """'mock' for the bundled mock LLM, 'real' for any configured provider."""
        return "mock" if self.provider == "mock" else "real"

    def configured(self) -> bool:  # is the key present? (never reveals it)
        return self.key_env is None or bool(os.environ.get(self.key_env))

    def _key(self):
        if self.key_env is None:
            return None
        k = os.environ.get(self.key_env, "")
        if not k:
            raise AdapterError("api key not configured")
        return k

    def limits(self):
        return {"timeout_s": self.timeout, "max_tokens": self.max_tokens, "max_response_bytes": self.max_response_bytes,
                "max_concurrent": self.max_concurrent, "max_requests_per_minute": self.rpm or None,
                "max_requests_per_run": self.max_requests_per_run}

    def public(self):
        """Never includes the endpoint or the key's name or value."""
        return {"id": self.id, "name": self.name, "provider": self.provider, "flavor": self.FLAVOR,
                "origin": self.origin, "kind": self.kind, "model": self.model,
                "configured": self.configured(), "limits": self.limits()}

    # ---- generation ---------------------------------------------------------
    async def generate(self, prompt: str, session: Optional[str] = None) -> GenResult:
        t0 = time.monotonic()
        try:
            text = await self._call(prompt, f"{self.id}:{session}" if session else None, session)
        except AdapterError:
            raise
        except (asyncio.TimeoutError, httpx.TimeoutException):   # overall deadline or httpx's own: same outcome
            raise AdapterError(f"{self.provider} timed out") from None
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
            raise AdapterError(f"{self.provider} call failed") from None
        if not isinstance(text, str):
            raise AdapterError("provider returned no text")
        return GenResult(text[:MAX_REPLY_CHARS], int((time.monotonic() - t0) * 1000))

    # ---- limits + transport -------------------------------------------------------
    def _semaphore(self):
        loop = asyncio.get_running_loop()
        if self._sem is None or self._sem_loop is not loop:
            self._sem, self._sem_loop = asyncio.Semaphore(self.max_concurrent), loop
        return self._sem

    async def _rate_wait(self):
        if not self.rpm:
            return
        while True:
            now = time.monotonic()
            while self._hits and now - self._hits[0] >= 60:
                self._hits.popleft()
            if len(self._hits) < self.rpm:
                self._hits.append(now)
                return
            wait = 60 - (now - self._hits[0])
            if wait > self.timeout:
                raise RateLimited("request limit reached")
            await asyncio.sleep(wait)

    async def _request(self, method, url, headers=None, payload=None, limited=True, deadline=None):
        """One bounded HTTP call -> (status, body bytes). Deadline covers the whole exchange; the body is
        read as a stream and aborted as soon as it exceeds max_response_bytes."""
        if limited:
            await self._rate_wait()

        async def go():
            timeout = httpx.Timeout(self.timeout, connect=self.connect_timeout)
            async with httpx.AsyncClient(timeout=timeout) as c:
                async with c.stream(method, url, headers=headers or {}, json=payload) as r:
                    declared = r.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > self.max_response_bytes:
                        raise AdapterError("provider response too large")
                    buf = bytearray()
                    async for chunk in r.aiter_bytes():
                        buf += chunk
                        if len(buf) > self.max_response_bytes:
                            raise AdapterError("provider response too large")
                    return r.status_code, bytes(buf)

        async with self._semaphore():
            return await asyncio.wait_for(go(), deadline or self.timeout)

    async def _post(self, url, headers, payload):
        status, body = await self._request("POST", url, headers, payload)
        if status >= 400:
            raise AdapterError(f"{self.provider} returned HTTP {status}")
        return json.loads(body)

    # ---- health ---------------------------------------------------------------------
    async def health(self) -> dict:
        """Cheap reachability/credentials/model-presence probe. Never spends a generation, never returns
        the endpoint, a key, or any provider response body."""
        t0 = time.monotonic()

        def done(status, detail, verified=False):
            return {"ok": status in HEALTHY, "status": status, "detail": detail, "model_verified": verified,
                    "latency_ms": int((time.monotonic() - t0) * 1000), "checked_at": time.time()}

        if not self.configured():
            return done("not_configured", "the API key environment variable for this model is not set")
        try:
            return done(*await self._probe())
        except (asyncio.TimeoutError, httpx.TimeoutException):
            return done("unreachable", f"no answer from the provider within {min(self.timeout, 15):g}s")
        except httpx.HTTPError:
            return done("unreachable", "could not connect to the provider")
        except AdapterError as e:
            return done("bad_response", str(e))
        except Exception:
            return done("provider_error", "the health probe failed unexpectedly")

    async def _probe(self):
        raise NotImplementedError


class MockAdapter(Adapter):
    FLAVOR = "Mock"

    async def _call(self, prompt, key, session):
        body = {"prompt": prompt, "session_id": session}
        return (await self._post(self.endpoint + "/generate", {}, body))["response"]

    async def _probe(self):
        status, _ = await self._request("GET", self.endpoint + "/healthz", limited=False, deadline=min(self.timeout, 15))
        return ("ok", "mock model is up", True) if status == 200 else ("provider_error", f"mock returned HTTP {status}", False)


class OpenAICompatAdapter(Adapter):
    FLAVOR = "OpenAI-compatible"

    async def _call(self, prompt, key, session):
        headers = {"Content-Type": "application/json"}
        k = self._key()
        if k:
            headers["Authorization"] = "Bearer " + k
        payload = {"model": self.model, "messages": self._store.messages(key, prompt),
                   self.max_tokens_param: self.max_tokens}
        data = await self._post(self.endpoint + "/chat/completions", headers, payload)
        text = data["choices"][0]["message"]["content"]
        if not isinstance(text, str):
            raise AdapterError("provider returned no text")
        if not text.strip():   # e.g. a reasoning model that used its whole budget thinking: not an answer to judge
            raise AdapterError("provider returned an empty reply")
        self._store.commit(key, prompt, text)
        return text

    def _has_model(self, ids):
        m = self.model
        return m in ids or (m + ":latest") in ids or (m.endswith(":latest") and m[:-7] in ids)

    async def _probe(self):
        headers = {}
        k = self._key()
        if k:
            headers["Authorization"] = "Bearer " + k
        status, body = await self._request("GET", self.endpoint + "/models", headers, limited=False,
                                           deadline=min(self.timeout, 15))
        if status in (401, 403):
            return "auth_failed", f"the provider rejected the credentials (HTTP {status})", False
        if status in (404, 405, 501):
            return "ok_unverified", "reachable, but it does not list models so the model name could not be checked", False
        if status >= 400:
            return "provider_error", f"the provider returned HTTP {status}", False
        try:
            ids = [m["id"] for m in json.loads(body)["data"]]
        except (ValueError, KeyError, TypeError):
            return "bad_response", "the provider answered, but not with an OpenAI-style model list", False
        if not self.model:
            return "ok_unverified", "reachable (no model name configured to check)", False
        if not self._has_model(ids):
            return "model_not_found", f"model {self.model!r} is not available on the provider ({len(ids)} model(s) listed)", False
        return "ok", f"reachable; model {self.model!r} is available", True


class OllamaAdapter(OpenAICompatAdapter):
    """Ollama through its OpenAI-compatible /v1 API. Same code path as any OpenAI-compatible server; only the
    defaults differ (local kind, no key, a generous timeout because the first request loads the model)."""
    FLAVOR = "Ollama"
    DEFAULTS = {"kind": "local", "endpoint": "http://host.docker.internal:11434/v1", "timeout_s": 120,
                "max_concurrent": 2, "max_requests_per_run": 500}


class AnthropicAdapter(Adapter):
    FLAVOR = "Anthropic"

    async def _call(self, prompt, key, session):
        headers = {"x-api-key": self._key(), "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
        payload = {"model": self.model, "max_tokens": self.max_tokens,
                   "messages": self._store.messages(key, prompt)}
        url = (self.endpoint or "https://api.anthropic.com") + "/v1/messages"
        data = await self._post(url, headers, payload)
        text = "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        if not text.strip():
            raise AdapterError("provider returned an empty reply")
        self._store.commit(key, prompt, text)
        return text

    async def _probe(self):
        return "not_checked", "no connectivity probe for this provider (it would need a billable call); problems show up per case", False


PROVIDERS = {"mock": MockAdapter, "openai": OpenAICompatAdapter, "ollama": OllamaAdapter, "anthropic": AnthropicAdapter}


class Registry:
    def __init__(self, cfgs, default=None):
        store = SessionStore()
        self.adapters = {}
        for c in cfgs:
            if c.get("enabled", True) is False:
                continue
            if c.get("provider") not in PROVIDERS:
                raise ValueError(f"model {c.get('id')!r}: unknown provider {c.get('provider')!r}")
            if not ID_RE.match(str(c.get("id", ""))) or c["id"] in self.adapters:
                raise ValueError(f"bad or duplicate model id {c.get('id')!r}")
            a = PROVIDERS[c["provider"]](c, store)    # applies provider defaults, validates every limit
            if a.provider != "anthropic" and not a.endpoint.startswith(("http://", "https://")):
                raise ValueError(f"model {c['id']!r}: endpoint must be http(s)")
            self.adapters[c["id"]] = a
        if not self.adapters:
            raise ValueError("no enabled models")
        self.default = default if default in self.adapters else next(iter(self.adapters))

    def get(self, model_id: Optional[str]) -> Optional[Adapter]:
        return self.adapters.get(model_id or self.default)

    def public(self):
        return [{**a.public(), "default": a.id == self.default} for a in self.adapters.values()]

    @classmethod
    def load(cls, path, fallback_mock_url):
        """Missing file -> just the mock. A present-but-invalid file fails loudly at startup."""
        if not os.path.exists(path):
            return cls([{"id": "mock", "provider": "mock", "name": "Mock LLM", "kind": "mock",
                         "endpoint": fallback_mock_url}])
        with open(path) as f:
            doc = json.load(f)
        cfgs = doc["models"]
        for c in cfgs:  # the mock's address always comes from LLM_URL unless set explicitly
            if c.get("provider") == "mock" and not c.get("endpoint"):
                c["endpoint"] = fallback_mock_url
        return cls(cfgs, doc.get("default"))
