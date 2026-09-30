"""Model-agnostic LLM adapter layer.

    Gateway -> LLMAdapter.generate(prompt, session) -> Mock | OpenAI-compatible | Anthropic

Providers
  mock      the existing mock-llm container (POST {endpoint}/generate). Keeps its own per-session history.
  openai    any OpenAI-compatible /chat/completions API: cloud APIs AND local servers
            (Ollama, vLLM, llama.cpp, LM Studio all speak this).
  anthropic Anthropic Messages API.

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
import json
import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional

import httpx

MAX_REPLY_CHARS = 16000
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


class AdapterError(Exception):
    """Provider failure. The message is safe to log: it never contains secrets or provider bodies."""


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
    def __init__(self, cfg, store):
        self.id, self.provider = cfg["id"], cfg["provider"]
        self.name = cfg.get("name", cfg["id"])
        self.kind = cfg.get("kind", "cloud" if self.provider == "anthropic" else "local")
        self.model = cfg.get("model", "")
        self.endpoint = cfg.get("endpoint", "").rstrip("/")
        self.key_env = cfg.get("api_key_env")
        self.timeout = float(cfg.get("timeout_s", 30))
        self.max_tokens = int(cfg.get("max_tokens", 512))
        self.max_tokens_param = cfg.get("max_tokens_param", "max_tokens")
        self._store = store

    def configured(self) -> bool:  # is the key present? (never reveals it)
        return self.key_env is None or bool(os.environ.get(self.key_env))

    def _key(self):
        if self.key_env is None:
            return None
        k = os.environ.get(self.key_env, "")
        if not k:
            raise AdapterError("api key not configured")
        return k

    def public(self):
        return {"id": self.id, "name": self.name, "provider": self.provider,
                "kind": self.kind, "model": self.model, "configured": self.configured()}

    async def generate(self, prompt: str, session: Optional[str] = None) -> GenResult:
        t0 = time.monotonic()
        try:
            text = await self._call(prompt, f"{self.id}:{session}" if session else None, session)
        except AdapterError:
            raise
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
            raise AdapterError(f"{self.provider} call failed") from None
        if not isinstance(text, str):
            raise AdapterError("provider returned no text")
        return GenResult(text[:MAX_REPLY_CHARS], int((time.monotonic() - t0) * 1000))

    async def _post(self, url, headers, payload):
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(url, headers=headers, json=payload)
        if r.status_code >= 400:
            raise AdapterError(f"{self.provider} returned HTTP {r.status_code}")
        return r.json()


class MockAdapter(Adapter):
    async def _call(self, prompt, key, session):
        body = {"prompt": prompt, "session_id": session}
        return (await self._post(self.endpoint + "/generate", {}, body))["response"]


class OpenAICompatAdapter(Adapter):
    async def _call(self, prompt, key, session):
        headers = {"Content-Type": "application/json"}
        k = self._key()
        if k:
            headers["Authorization"] = "Bearer " + k
        payload = {"model": self.model, "messages": self._store.messages(key, prompt),
                   self.max_tokens_param: self.max_tokens}
        data = await self._post(self.endpoint + "/chat/completions", headers, payload)
        text = data["choices"][0]["message"]["content"]
        self._store.commit(key, prompt, text if isinstance(text, str) else "")
        return text


class AnthropicAdapter(Adapter):
    async def _call(self, prompt, key, session):
        headers = {"x-api-key": self._key(), "anthropic-version": "2023-06-01",
                   "Content-Type": "application/json"}
        payload = {"model": self.model, "max_tokens": self.max_tokens,
                   "messages": self._store.messages(key, prompt)}
        url = (self.endpoint or "https://api.anthropic.com") + "/v1/messages"
        data = await self._post(url, headers, payload)
        text = "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        self._store.commit(key, prompt, text)
        return text


PROVIDERS = {"mock": MockAdapter, "openai": OpenAICompatAdapter, "anthropic": AnthropicAdapter}


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
            if c["provider"] != "anthropic" and not str(c.get("endpoint", "")).startswith(("http://", "https://")):
                raise ValueError(f"model {c['id']!r}: endpoint must be http(s)")
            self.adapters[c["id"]] = PROVIDERS[c["provider"]](c, store)
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
