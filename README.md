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
`ollama`, `openai` = any OpenAI-compatible API incl. vLLM/llama.cpp/LM Studio, `anthropic`).
Configure them in `gateway/models.json` (see `models.example.json`); API keys come
from gateway environment variables named by `api_key_env` and are never stored in
the file, returned by an API, or logged. Clients choose a model by id only
(`POST /red/tests {"prompt":..., "model":"<id>"}`, list with `GET /models`).
Cloud/local models need egress from the gateway (it already has `admin-net`);
local servers must be reachable from the gateway container.
Tests without Docker: `python3 tests/adapter_test.py`.

### Real providers (Ollama / OpenAI-compatible)

`gateway/models.example.json` has a ready entry. `provider: "ollama"` is the same OpenAI-compatible
code path as `openai`, with local defaults (endpoint `http://host.docker.internal:11434/v1`, no key,
120 s timeout because the first request loads the model, 2 concurrent, 500 requests per evaluation).
Evaluations use it exactly like the mock: `POST /evaluations {"suite_id": ..., "model": "<id>"}` still
drives the gateway's own `/red/...` routes, so auth, phase gating, the store, the audit log and the anchor
are the same path. Endpoints, key names and keys are never returned by any API, UI, result or audit entry.

| Setting (per model) | Default | Meaning |
|---|---|---|
| `timeout_s` / `connect_timeout_s` | 30 (ollama 120) / 5 | Overall deadline for one request (a slow-drip body can't outrun it) / time to establish the connection |
| `max_tokens` | 512 (max 8192) | Reply cap sent to the provider |
| `max_response_bytes` | 1 MiB | The body is streamed and aborted past this; an oversize reply is an error |
| `max_concurrent` | 4 (ollama 2) | Simultaneous requests to the provider; others wait |
| `max_requests_per_minute` | 0 = off | Callers wait for a slot up to `timeout_s`, then get HTTP 429 (shown as `blocked`) |
| `max_requests_per_run` | none (ollama 500) | An evaluation needing more requests (attacks + 3 session probes) is refused up front (422) |

**Health check.** Before an evaluation sends anything, the provider is probed (`GET <endpoint>/models`: reachable?
credentials accepted? model present?). If that fails, the run is recorded as `failed` with
`error.stage = "provider_health"` and **zero result rows**, so an unreachable provider can never appear as attack
cases a model "failed". You can run the same probe yourself: `GET /models/<id>/health` (scope `eval:read`) or the
"Test connection" button in `/ui`. A provider that is up but doesn't list models (HTTP 404/405/501) is
`ok_unverified`; Anthropic has no probe (`not_checked`) because it would cost a billable call.
If it dies mid-run, the remaining attacks are `error` rows (HTTP 502), never `fail`.

**Labels.** Every run and every result row carries `provider`, `provider_model`, `provider_kind` (`mock` or
`real`), model id, suite id and version, timestamps, latency and status; `/ui` shows MOCK MODEL / REAL PROVIDER
on the selector, the run header, results and history. The label comes from the configured provider: a fake
server configured as `ollama` is labelled REAL, because the gateway cannot tell. Runs made before this
feature show PROVIDER UNKNOWN.

**Ollama on the VM.** Ollama listens on 127.0.0.1 by default, which a container cannot reach. The red/blue
containers have no route to it by design; only the gateway (which has `admin-net`) needs to.
1. Make Ollama listen on the docker bridge instead of loopback (narrowest option):
   `sudo systemctl edit ollama` -> `[Service]` / `Environment="OLLAMA_HOST=<docker0 IP>:11434"` (see
   `ip -4 addr show docker0`, usually 172.17.0.1), then `sudo systemctl restart ollama`, `ollama pull llama3.2`.
2. Copy `gateway/models.example.json` to `gateway/models.json`, keep the `ollama-llama32` entry and set its
   `endpoint` to `http://<docker0 IP>:11434/v1` (or keep `host.docker.internal` and add
   `extra_hosts: ["host.docker.internal:host-gateway"]` to the gateway service; I did not edit compose).
3. `docker compose up -d --build gateway` (models.json is baked into the image).
4. Check reachability *from inside the container*, which is what matters (gVisor networking to the host is
   untested here): the "Test connection" button, or
   `curl -s -H "Authorization: Bearer $EVALUATOR_TOKEN" localhost:8080/models/ollama-llama32/health`.
   `unreachable` means a networking problem, not an evaluation problem.
5. Opt-in integration test against the real server (not run in CI):
   `BAYORA_REAL_PROVIDER=1 BAYORA_REAL_MODEL=llama3.2 python3 tests/real_provider_test.py`
   (`BAYORA_REAL_ENDPOINT` defaults to `http://127.0.0.1:11434/v1`; it runs the gateway in-process).

Tests without Docker or Ollama: `python3 tests/provider_test.py` (a fake OpenAI-compatible server over real
sockets) and `python3 tests/fake_provider.py 18090` to point `/ui` at a fake provider by hand.

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

## Web app (`/app`): accounts, reports, admin

`/app` is the real front end (no `DEMO_UI` needed): sign in, run evaluations, read your results, print a report,
download evidence. Administrators also get an overview, user management and every user's runs. `/ui` stays the
demo console.

**First run.** Open `/app` on a fresh gateway. It asks for a setup code, which proves you can read the server's
configuration. Get it with
`docker compose exec gateway python -c "import users,auth;print(users.bootstrap_code(auth.SECRET))"`, then create
the first administrator. That route closes as soon as any account exists. Admins create further accounts under
Users. Self-service signup exists but is off; it needs `ALLOW_SIGNUP=1` (and `USER_TOKEN_TTL` to change the
1 hour session) added to the gateway's `environment:` in compose, which I did not edit.

| Role | Can do |
|---|---|
| `user` | run evaluations on the models the operator configured; read, report on and download **only their own** runs |
| `admin` | all of that, plus every user's runs, accounts (create, disable, role, reset password), the live audit/anchor overview |

These are *account* roles stored in SQLite. They are separate from the tenant tokens (red, blue, admin = auditor,
evaluator) the gateway already issues; an account principal appears in the audit log as `user:<name>`. Passwords
are stored as salted scrypt hashes only (10-character minimum, must not contain the username). Failed logins are
throttled per username and per address with identical responses for real and unknown accounts. Account tokens
carry a role and a version that are re-checked on every request, so disabling an account, changing its role, or
changing/resetting its password ends its sessions immediately. Someone else's run id answers 404, not 403.
Users cannot bring their own model or endpoint: models are configured by the operator in `models.json`.

**Landing, navigation and account.** `/app` opens on the Bayora landing page (hero, About, Method, Try it, a
guided tour). Signed-in users get Home, Evaluate, My Runs, Account; admins also get All Runs, Overview and Users.
The navigation is only a convenience: every route is authorised by the server regardless of what the page shows.
Account has three parts. *Profile*: display name, nickname, email, short bio. Email is stored as plain account
information; Bayora sends no email, verifies no address and offers no email recovery (an admin resets passwords).
*Security*: change password (signs out the account's other sessions). *Preferences*: show username or display
name in the navigation, reduce animation. The profile route is `PATCH /auth/profile`: it always acts on the
caller, takes no username, and rejects any body naming a field outside the six profile fields (role, active,
scopes and the like), so nothing is half-applied. Admin account management stays under `/admin/users`.

**What the evaluation tests.** *Evaluate* has a "How this evaluation works" panel built from the loaded suite
definitions and the runner's control table (`GET /evaluation-info`), so it cannot drift from what actually runs.
It separates HEURISTIC probes (jailbreak, prompt injection, instruction following, data exfiltration, policy
bypass: a screen of the reply, a signal for human review, never proof) from DETERMINISTIC gateway controls
(authentication, authorization, session isolation, phase gating, audit: checked by code). The model list shows
each configured model with MOCK/REAL, provider, limits and availability (after a connection test); models come
from `models.json`, and `gateway/models.example.json` has disabled Ollama examples to enable once pulled.

**Printable report and the CSP.** The report opens as a `blob:` page, and a blob page inherits the opener's
Content Security Policy. `/app`'s policy therefore lists, besides its own script's hash, the one fixed hash of the
report's print-button script. There is no `unsafe-inline` and no `unsafe-eval`.

Real-browser test (headless Chromium, no Docker): `cd tests && npm install puppeteer-core @sparticuz/chromium jsdom`,
then `bash tests/browser_test.sh` (print button) and `bash tests/browser_test.sh browser_ui_test.js` (landing,
app and admin at desktop, tablet and phone widths, with screenshots in `$SHOTS`).

## Evidence bundle and printable report

For any finished run: `GET /evaluations/{id}/evidence` downloads a `bayora.evidence/1` JSON bundle (run, the exact
suite definition, every result row, this run's audit entries with their hashes, the integrity state when it was
made, a digest); `GET /evaluations/{id}/report` is a print-ready page (also reachable from `/app`: *Open printable
report*, then print or save as PDF). The report lists the **potential downsides** the data shows (each flagged
probe with what was expected, what happened, why it matters and what to consider; platform defects; cases that
produced no verdict) and always ends with the evaluation's limitations. It is labelled MOCK or REAL and never
claims a model is safe.

Check a bundle offline with the standard library only: `python3 scripts/verify_evidence.py bundle.json`
(`--json` for machines). It re-derives the digests, summary, every audit entry hash, the link from each result to
its audit entry, the suite hash and the phase-gate order. It cannot re-derive audit-chain continuity or the
anchor comparison (the excerpt is sparse); those are shown as INFO from what the gateway recorded at the time.
The bundle digest catches accidental edits, not a determined forger who recomputes it: the gateway's live check
of the full chain and the independent anchor stay the authority.

Tests: `python3 tests/accounts_test.py tests/profile_test.py tests/evidence_test.py tests/app_page_test.py` (one at a time, no Docker);
browser-level: `bash tests/ui_app_test.sh` (needs Node + jsdom, not in CI).

## Demo UI (`/ui`) — demo only

Set `DEMO_UI=1` for the gateway, then open `http://127.0.0.1:8080/ui`. The page calls
`GET /ui/demo-tokens`, which mints a fresh short-lived token per role (red/blue/admin) with
the gateway's existing signing secret (red/blue/admin/evaluator; default 15 min; `DEMO_TOKEN_TTL` seconds, clamped
5–3600). The page refetches on a 401. The endpoint is 404 unless `DEMO_UI=1` and for any
caller on the red/blue/model networks. It hands one browser every role, so it defeats
tenant isolation and must never be enabled outside a demo. Real deployments are unchanged:
tokens still come from `scripts/setup_env.py` (12h) and go through the same `auth.verify()`.
The red/blue containers and the test scripts still use those `.env` tokens.
