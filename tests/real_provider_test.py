#!/usr/bin/env python3
"""OPT-IN integration test against a REAL provider. Skipped (exit 0) unless explicitly enabled.

    BAYORA_REAL_PROVIDER=1 BAYORA_REAL_MODEL=llama3.2 python3 tests/real_provider_test.py

Environment
    BAYORA_REAL_PROVIDER   must be "1" to run at all (CI leaves it unset -> SKIPPED)
    BAYORA_REAL_MODEL      the provider's model name, e.g. llama3.2 (required)
    BAYORA_REAL_ENDPOINT   default http://127.0.0.1:11434/v1  (Ollama's OpenAI-compatible API)
    BAYORA_REAL_PROVIDER_TYPE  "ollama" (default) or "openai" (any other OpenAI-compatible server)
    BAYORA_REAL_API_KEY    optional bearer key for servers that need one (never printed or stored)
    BAYORA_REAL_TIMEOUT    per-request timeout in seconds, default 180 (a cold CPU model can be slow)

It runs the gateway IN-PROCESS (no Docker) with the real provider as the only model and drives the existing
Evaluation Engine over the gateway's own routes. It asserts INTEGRATION invariants only: the provider is
reachable and has the model, the run completes, every gateway control passes, every attack got a real reply,
audit/DB consistency holds, metadata says REAL, and no secret leaked. It does NOT assert whether the model
resists any attack: that is the model's property, reported informationally at the end.
Success here is the only evidence that the integration works against that provider; the fake-provider tests
(tests/provider_test.py) do not count as such.
"""
import asyncio, importlib, json, os, sys, tempfile, time, warnings
warnings.filterwarnings("ignore")

if os.environ.get("BAYORA_REAL_PROVIDER") != "1":
    print("SKIPPED real_provider_test: set BAYORA_REAL_PROVIDER=1 (and BAYORA_REAL_MODEL) to run it against a real provider.")
    sys.exit(0)

MODEL = os.environ.get("BAYORA_REAL_MODEL", "")
if not MODEL:
    sys.exit("BAYORA_REAL_MODEL is required (e.g. llama3.2)")
ENDPOINT = os.environ.get("BAYORA_REAL_ENDPOINT", "http://127.0.0.1:11434/v1")
KIND = os.environ.get("BAYORA_REAL_PROVIDER_TYPE", "ollama")
KEY = os.environ.get("BAYORA_REAL_API_KEY", "")
TIMEOUT = float(os.environ.get("BAYORA_REAL_TIMEOUT", "180"))
if KIND not in ("ollama", "openai"):
    sys.exit("BAYORA_REAL_PROVIDER_TYPE must be 'ollama' or 'openai'")

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp()
JWT = "real-provider-test-signing-secret-0123456789"
cfg = {"id": "real", "provider": KIND, "name": f"Real {KIND}", "model": MODEL, "endpoint": ENDPOINT, "timeout_s": TIMEOUT}
if KEY:
    cfg["api_key_env"] = "BAYORA_REAL_API_KEY"
json.dump({"default": "real", "models": [cfg]}, open(TMP + "/models.json", "w"))
os.environ.update(JWT_SECRET=JWT, AUDIT_PATH=TMP + "/audit.jsonl", MODELS_CONFIG=TMP + "/models.json")
os.environ.pop("DB_PATH", None)
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx, jwt  # noqa: E402
gw = importlib.import_module("main")

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)[:400]))

def tok(role): return {"Authorization": "Bearer " + jwt.encode({"sub": role, "scope": gw.DEMO_SCOPES[role], "exp": int(time.time()) + 3600}, JWT, "HS256")}
EV, RED = tok("evaluator"), tok("red")

async def main():
    print(f"== real provider: {KIND} model {MODEL!r} (endpoint is not printed)")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw", timeout=None) as c:
        h = (await c.get("/models/real/health", headers=EV)).json()
        check("health: provider reachable, credentials accepted, model present", h.get("ok") is True and h.get("status") in ("ok", "ok_unverified"),
              f"{h.get('status')}: {h.get('detail')}  -> start the provider, make sure the endpoint is reachable from this machine, and the model is pulled (for Ollama: ollama pull {MODEL})")
        if not h.get("ok"):
            print(f"\nResult: {PASS} passed, {FAIL} failed (stopping: nothing else can be tested without a healthy provider)"); sys.exit(1)
        print(f"        health status={h['status']} model_verified={h['model_verified']} latency={h['latency_ms']} ms")
        m = {x["id"]: x for x in (await c.get("/models", headers=RED)).json()}["real"]
        check("GET /models: origin 'real', no endpoint or key in the output", m["origin"] == "real" and ENDPOINT not in json.dumps(m) and (not KEY or KEY not in json.dumps(m)))

        t0 = time.time()
        r = await c.post("/red/tests", headers=RED, json={"prompt": "Reply with one short sentence about the sky.", "model": "real"})
        check("one prompt through /red/tests gets a non-empty reply from the real model", r.status_code == 200 and len(r.json().get("response", "").strip()) > 0, f"{r.status_code} {r.text[:200]}")
        print(f"        first request (may include model load): {time.time() - t0:.1f}s")

        print("== full evaluation (builtin-core) on the real provider")
        r = await c.post("/evaluations", headers=EV, json={"suite_id": "builtin-core", "model": "real"})
        check("POST /evaluations accepted", r.status_code == 202, r.text)
        rid = r.json()["run_id"]
        await gw.runner.wait()
        run = (await c.get(f"/evaluations/{rid}", headers=EV)).json()
        rows = (await c.get(f"/evaluations/{rid}/results", headers=EV)).json()
        sm = run["summary"] or {}
        check("run completed (not failed/interrupted)", run["status"] == "completed", run.get("error") or run["status"])
        check("25 cases recorded", len(rows) == 25 and run["done"] == 25)
        det = [x for x in rows if x["judge"] == "deterministic"]
        att = [x for x in rows if x["judge"] == "heuristic"]
        check("all 12 deterministic gateway controls pass with a real model behind them", len(det) == 12 and all(x["status"] == "pass" for x in det), [(x["case_id"], x["status"]) for x in det if x["status"] != "pass"])
        check("every attack got a real reply: no 'error' rows (if timeouts, raise BAYORA_REAL_TIMEOUT)", all(x["status"] in ("pass", "fail") for x in att), [(x["case_id"], x["status"], x["detail"]) for x in att if x["status"] not in ("pass", "fail")])
        check("no 'blocked' rows (no limit was hit)", sm.get("blocked") == 0)
        check("attack rows have measured latency > 0, reply hash, reply length and test id", all((x["latency_ms"] or 0) > 0 and x["response_sha256"] and x["response_len"] > 0 and x["test_id"] for x in att))
        check("every attack's submission is in the audit log with a matching hash ('recorded')", all(x["audit_status"] == "recorded" for x in att))
        check("run metadata says REAL: provider, provider model, kind, suite, health", (run["provider"], run["provider_model"], run["provider_kind"]) == (KIND, MODEL, "real") and run["suite"]["id"] == "builtin-core" and run["health"]["ok"] is True)
        check("every result row carries the same provider/model/suite metadata", all(x["provider_kind"] == "real" and x["provider_model"] == MODEL and x["suite_id"] == "builtin-core" for x in rows))
        check("audit chain verified; stored results match the audit log", run["integrity"]["audit"]["ok"] is True and run["db_check"]["digest_matches_audit"] is True and run["db_check"]["digest_matches_run_record"] is True)
        blobs = json.dumps([run, rows]) + open(TMP + "/audit.jsonl").read() + open(gw.store.path, "rb").read().decode("latin-1")
        check("no signing secret, bearer token or provider key anywhere (run, results, audit log, SQLite file)", JWT not in blobs and "eyJ" not in blobs and (not KEY or KEY not in blobs))
        check("the endpoint is not stored in results or audit", ENDPOINT not in json.dumps([run, rows]) and ENDPOINT not in open(TMP + "/audit.jsonl").read())

        print("== informational (NOT asserted: this is the model's behaviour, judged by heuristics)")
        lat = sm.get("latency_ms") or {}
        print(f"        heuristic verdicts: {sm['by_judge']['heuristic']}   latency p50={lat.get('p50')} ms p95={lat.get('p95')} ms max={lat.get('max')} ms")
        for x in att:
            if x["status"] == "fail":
                print(f"        flagged (heuristic) {x['case_id']}: {x['detail'][:100]}")

    print(f"\nResult: {PASS} passed, {FAIL} failed")
    if not FAIL:
        from urllib.parse import urlparse
        print(f"PASSED against {KIND} / {MODEL} at {urlparse(ENDPOINT).netloc}. Note: this script cannot tell a real model server from a fake one; "
              "it only proves the integration for the endpoint you pointed it at.")
    sys.exit(1 if FAIL else 0)

asyncio.run(main())
