# Bayora - week 1 scaffold

Red team, blue team and a (mock) client LLM run in separate gVisor-sandboxed
containers on separate internal networks. The policy gateway is the only
thing attached to all of them.

```
red  --red-net---\
                  gateway --model-net-- llm
blue --blue-net--/    |
                      +-- hash-chained audit log (/data/audit.jsonl)
```

Services address each other by **fixed IP, not hostname** (see the note at
the top of `docker-compose.yml`) — gVisor's default sandboxed netstack
doesn't support Docker's embedded DNS server, so `gateway`/`llm`/etc. don't
resolve from inside these containers even though routing itself is fine.

| Service | red-net     | blue-net    | model-net    |
|---------|-------------|-------------|--------------|
| gateway | 172.28.1.2  | 172.28.2.2  | 172.28.3.10  |
| llm     | -           | -           | 172.28.3.2   |
| red     | 172.28.1.3  | -           | -            |
| blue    | -           | 172.28.2.3  | -            |

## Quick start (on the Ubuntu VM, inside this folder)

```bash
# 1. generate secrets (each tenant only ever receives its own token)
pip install --break-system-packages pyjwt   # once, on the VM
python3 scripts/setup_env.py            # writes .env (JWT_SECRET + 3 scoped tokens, 12h)

# 2. build and start
docker compose up -d --build
docker compose ps

# 3. prove gVisor is the runtime
docker inspect -f '{{.HostConfig.Runtime}}' bayora-red-1     # -> runsc

# 4. run the isolation + policy + audit checks
bash tests/isolation_test.sh

# 5. prove cgroup limits actually cap a noisy tenant (takes ~10s)
bash tests/fairness_test.sh
```

If a container won't start under gVisor, set `SANDBOX_RUNTIME=runc` in `.env`
to confirm the rest works, then debug gVisor separately.

## Manual poking

```bash
docker compose exec red  python client.py submit "hello"
docker compose exec blue python client.py list
docker compose exec blue python client.py read <test_id>   # 403 until concluded
docker compose exec red  python client.py conclude <test_id>
```

(`docker compose exec` talks to the Docker API directly to pick the
container, so it isn't affected by the DNS issue above — only requests
*from inside* a container to another service's hostname are.)

## Layout / ownership

- `gateway/`    routing, auth, gating, audit (core, owner: you)
- `containers/llm|red|blue/`  one folder per tenant (delegatable)
- `tests/`      isolation checks (delegatable, extend freely)

## Known limits (go in the threat model)

- Test state lives in gateway memory; audit log persists in a volume.
- Tokens are scoped, signed JWTs (HS256, one shared secret) with a 12h
  default lifetime — real ABAC now, not just per-tenant role names. One
  trust root for the PoC: a production version would give each tenant its
  own signing identity so one can be revoked without re-minting the others.
- gateway joins `admin-net` (has egress) only to publish 127.0.0.1:8080.
- Audit chain detects edits, not a full-file rewrite or tail truncation.
- No timing/padding mitigation yet (side-channel work, week 3).
- Mock LLM is stateless, which sidesteps KV-cache leakage rather than solving it.
- Service discovery uses static IPs, not DNS, because gVisor's sandboxed
  netstack doesn't support Docker's embedded DNS server. The alternative
  (`runsc --network=host`) would fix DNS by handing network syscalls
  straight to the host kernel instead of gVisor's sentry, which trades away
  exactly the network-level isolation gVisor is providing. Namespace/bridge/
  iptables isolation between tenants (separate `internal: true` networks) is
  unaffected either way — that's enforced by the host kernel regardless of
  which netstack mode runsc uses.

## Models (LLM adapter layer)

The gateway calls models through `gateway/llm_adapters.py` (providers: `mock`,
`openai` = any OpenAI-compatible API incl. local Ollama/vLLM/llama.cpp, `anthropic`).
Configure them in `gateway/models.json` (see `models.example.json`); API keys come
from gateway environment variables named by `api_key_env` and are never stored in
the file, returned by an API, or logged. Clients choose a model by id only
(`POST /red/tests {"prompt":..., "model":"<id>"}`, list with `GET /models`).
Cloud/local models need egress from the gateway (it already has `admin-net`);
local servers must be reachable from the gateway container.
Tests without Docker: `python3 tests/adapter_test.py`.

## Demo UI (`/ui`) — demo only

Set `DEMO_UI=1` for the gateway, then open `http://127.0.0.1:8080/ui`. The page calls
`GET /ui/demo-tokens`, which mints a fresh short-lived token per role (red/blue/admin) with
the gateway's existing signing secret (default 15 min; `DEMO_TOKEN_TTL` seconds, clamped
5–3600). The page refetches on a 401. The endpoint is 404 unless `DEMO_UI=1` and for any
caller on the red/blue/model networks. It hands one browser every role, so it defeats
tenant isolation and must never be enabled outside a demo. Real deployments are unchanged:
tokens still come from `scripts/setup_env.py` (12h) and go through the same `auth.verify()`.
The red/blue containers and the test scripts still use those `.env` tokens.
