# Bayora — threat model

What this architecture protects against, what it doesn't, the assumptions
each protection relies on, and what's still open. Written from what has
actually been built and tested, not from the original plan.

## Claims

| Claim | Protects against | Does NOT protect against | Assumption it relies on |
|---|---|---|---|
| Network segmentation (3 internal-only Docker networks; gateway is the only shared node) | Direct container-to-container traffic between red, blue and the LLM. Verified: 10/10 network-isolation checks pass, including no route to the internet from red or the LLM. | A compromised gateway process itself — it's the one node with legitimate access to all three networks, so it's also the single point of failure for the isolation model. | Docker's bridge/iptables enforcement isn't bypassed by host-level misconfiguration. |
| ABAC via scoped, signed JWTs (12h expiry) | Early exposure of red-team payloads or blue-team defensive notes; use of a valid token on the wrong route (verified: a valid red-scoped token gets 403 on every blue-scoped and admin-scoped endpoint, and vice versa); forged signatures (verified: a token signed with the wrong secret is rejected); expired tokens (verified: a real token was left to expire and was then rejected). | A leaked, still-valid token — this is a bearer-token model, so possession is proof of scope. Also: one shared HMAC secret signs every tenant's tokens, so a secret leak compromises all three at once. | The `JWT_SECRET` value itself never leaves the gateway's environment. |
| Test-phase gating (`status != "concluded"`) | Blue team reading a test's prompt/response while red team's attack is still active. Verified live: reads return 403 before conclusion, 200 after. | Nothing once a test is concluded — release is all-or-nothing per test, not gradual or redacted. | Red team alone controls when a test concludes, and does so honestly for the PoC's purposes. |
| Hash-chained audit log | Silent editing or deleting of a past entry — verified: editing one field of one historical entry, or deleting an entry outright, both cause `verify()` to report the chain broken at that exact point. | An attacker who can rewrite the *entire* log file from scratch produces a self-consistent chain — there's no external anchor for the head hash yet. | The log service/volume itself isn't compromised, and nobody with that access is also an adversary being tested. |
| cgroup resource limits (`mem_limit`/`cpus` per service) | A single noisy tenant consuming the whole host's CPU/memory. | **Not yet independently verified.** The isolation test suite doesn't cover this; a dedicated fairness test exists but its first runs gave contradictory readings (the supposedly-maxed container showed near-0% CPU) — most likely an artifact of gVisor's slower `exec` startup under a virtualized host outpacing the test's own timing, but this hasn't been confirmed. Treat this line as "configured, not yet proven" until the fairness test reliably shows the load actually running before it measures anything. | — |
| gVisor (`runsc`) sandboxing, sandboxed netstack | Container syscalls being handled by an emulated kernel rather than passed straight to the host's. Verified via `dmesg` showing gVisor's own kernel messages inside a test container. | Any exploit that stays entirely within what the sandboxed netstack faithfully emulates. Also: Docker's embedded DNS server doesn't work under gVisor's default network mode — worked around with static per-network IPs (a config decision, not a security hole) rather than switching to `runsc --network=host`, which would have fixed DNS by handing network syscalls straight to the host kernel and given up exactly this isolation layer. | gVisor's own emulation is itself free of exploitable gaps — this is inherently something the project can document a mitigation for, not prove absent. |
| Stateless mock LLM (fresh request, no history/cache) | Cross-session leakage through a shared KV-cache or conversation history — there is none to leak, by construction. | This sidesteps the shared-batch-inference leakage problem named in the brief rather than solving it. A real model served with batching would need to re-address this from scratch. | The PoC's mock LLM is representative enough of the threat surface for evaluation purposes; a production model would not be this simple. |

## Deliberately out of scope for this PoC

- Rotating or per-tenant signing keys (currently one shared JWT secret).
- Redacting or partially releasing test results (it's all-or-nothing per test).
- Anchoring the audit log's head hash somewhere outside the gateway's own reach.
- Timing/padding side-channel mitigation on the gateway's responses.
- Observability/anomaly detection beyond the audit log itself (planned, not yet built).

## Residual risk, summarized

The architecture's guarantees hold up to and including the gateway process
itself. Every claim above that's marked "verified" was tested against the
actual running system, not assumed from the design. The two open items —
proving cgroup fairness under real load, and hardening the audit log against
a full-file rewrite — are the honest gaps, not the polished parts.
