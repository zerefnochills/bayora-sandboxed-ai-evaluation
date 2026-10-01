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

- Tests and blue-team defenses persist in SQLite (`gateway/store.py`, `/data/bayora.db` on the
  same volume as the audit log; `DB_PATH` overrides). The DB is mutable and not tamper-evident by
  itself: the audit log holds sha256 of every stored prompt/response to check it against.
  Prompts and responses are stored in plaintext with no retention policy yet.
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

## Evaluation engine

Run a whole attack suite against a model and get a scored, persisted, audited result.

```
POST /evaluations {"suite_id": "builtin-core", "model": "mock"}   -> 202 {run_id, ...}   (scope eval:run)
GET  /evaluations/{id}            progress, summary, integrity, db_check                 (scope eval:read)
GET  /evaluations/{id}/results    one row per case                                       (scope eval:read)
GET  /evaluations                 history                                                (scope eval:read)
GET  /suites                      available suites (no prompt text)                      (scope eval:read)
```

The new `evaluator` role (`eval:run`, `eval:read`) can do nothing else: it cannot use Red, Blue
or audit routes (a control in every run checks this). The runner executes in the gateway
process, one run at a time (a second start gets 409), and drives the gateway's **own routes**
in-process with short-lived tokens for the actors `eval-red`, `eval-blue` and `eval-probe-*`,
so every request takes the normal auth -> phase gate -> adapter -> store -> audit path and is
attributable in the audit log. Attack tests are concluded after judging, so they show up in
Blue's test list like any other concluded test.

**Two kinds of verdict, never mixed**
- *Deterministic* (12 gateway controls per run: missing/forged/expired token, Red/Blue/evaluator
  scope separation, session isolation, phase gating, audit completeness). They check status
  codes, store state and audit entries; a failure is a real defect.
- *Heuristic* (the attack suite). A case-insensitive substring screen over the model's reply.
  It misses paraphrased failures and can flag a refusal that quotes the attack. Every such
  row is labelled HEURISTIC; treat it as a screening aid, not ground truth.

Statuses: `pass`, `fail`, `blocked` (the gateway refused the request itself), `error`
(model down, network, runner exception). Summary: totals, per-judge and per-category tallies,
latency count/min/mean/p50/p95/max, audit-chain status and anchor status (at the end of the run).

**Suites** are single JSON files in `gateway/suites/` (`format: "bayora.suite/1"`, strict
validation, canonical sha256 recorded with every run; import/export = copy the file; an invalid
file stops the gateway at startup). See `gateway/suites.py` for the format.

**Consistency.** Each result row stores sha256 of the model reply, the same hash the audit log
holds. A digest over all rows is stored on the run and sealed into an `evaluation_completed`
audit entry, and `GET /evaluations/{id}` recomputes it (`db_check`), so editing a stored row
afterwards is detected. Write order is DB then audit; a crash between them shows up in
`db_check` as a missing completion entry. A run still `running` at startup becomes
`interrupted` (with an audit entry). The DB itself stays mutable and unencrypted.

Tests without Docker: `python3 tests/suites_test.py tests/eval_store_test.py tests/evaluator_test.py
tests/eval_restart_test.py` (one at a time). UI: `bash tests/ui_eval_test.sh` (needs Node + jsdom, not in CI).

## Demo UI (`/ui`) — demo only

Set `DEMO_UI=1` for the gateway, then open `http://127.0.0.1:8080/ui`. The page calls
`GET /ui/demo-tokens`, which mints a fresh short-lived token per role (red/blue/admin) with
the gateway's existing signing secret (red/blue/admin/evaluator; default 15 min; `DEMO_TOKEN_TTL` seconds, clamped
5–3600). The page refetches on a 401. The endpoint is 404 unless `DEMO_UI=1` and for any
caller on the red/blue/model networks. It hands one browser every role, so it defeats
tenant isolation and must never be enabled outside a demo. Real deployments are unchanged:
tokens still come from `scripts/setup_env.py` (12h) and go through the same `auth.verify()`.
The red/blue containers and the test scripts still use those `.env` tokens.
