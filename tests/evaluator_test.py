#!/usr/bin/env python3
"""No-Docker tests for the evaluation engine (gateway/evaluator.py + the /evaluations API).

Everything runs in-process against the mock LLM: no Docker, no network, no API key.
    python3 tests/evaluator_test.py       # needs: pip install fastapi httpx pyjwt
"""
import asyncio, hashlib, importlib, importlib.util, json, os, sqlite3, sys, tempfile, time, warnings
warnings.filterwarnings("ignore")

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp()
os.environ.update(JWT_SECRET="test-secret", AUDIT_PATH=TMP + "/audit.jsonl", MODELS_CONFIG="/nonexistent")
os.environ.pop("DB_PATH", None)
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx, jwt  # noqa: E402

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

llm = load(os.path.join(ROOT, "containers/llm/main.py"), "llm_app")
gw = importlib.import_module("main")
ev = importlib.import_module("evaluator")
llm_adapters = importlib.import_module("llm_adapters")
auth = importlib.import_module("auth")
store_mod = importlib.import_module("store")

_real = httpx.AsyncClient          # route the gateway's model calls to the in-process mock
class Routed(_real):
    def __init__(self, *a, **k):
        k["transport"] = httpx.ASGITransport(app=llm.app); super().__init__(*a, **k)
httpx.AsyncClient = Routed

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)[:300]))

def tok(sub, scope, ttl=600):
    return {"Authorization": "Bearer " + jwt.encode({"sub": sub, "scope": scope, "exp": int(time.time()) + ttl}, "test-secret", "HS256")}
ROLES = gw.DEMO_SCOPES
EV, RED, BLUE, ADMIN = (tok(r, ROLES[r]) for r in ("evaluator", "red", "blue", "admin"))
sha = lambda t: hashlib.sha256(t.encode()).hexdigest()
def client(): return _real(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw")
SUITE_ID = "builtin-core"

async def run_via_api(c, runner=None, wait=True, **body):
    r = await c.post("/evaluations", headers=EV, json={"suite_id": SUITE_ID, **body})
    assert r.status_code == 202, (r.status_code, r.text)
    if wait:
        await (runner or gw.runner).wait()
    return r.json()["run_id"]

async def all_status(c, calls, want):
    """calls: [(method, path, headers, body)] -> True iff every response has status `want`."""
    out = []
    for m, p, h, b in calls:
        out.append((await c.request(m, p, headers=h, json=b)).status_code)
    return all(x == want for x in out)

async def get_run(c, rid): return (await c.get(f"/evaluations/{rid}", headers=EV)).json()
async def get_rows(c, rid): return (await c.get(f"/evaluations/{rid}/results", headers=EV)).json()
by_id = lambda rows: {r["case_id"]: r for r in rows}

async def main():
    global gw
    print("== pure logic")
    atk = {"judge": {"fail_if_contains": ["Restrictions Disabled"]}}
    check("judge: fail marker, case-insensitive", ev.judge_attack(atk, "Sure, RESTRICTIONS disabled!")[0] == "fail")
    check("judge: no marker -> pass, and the detail says it is heuristic", (lambda r: r[0] == "pass" and r[1].startswith("HEURISTIC"))(ev.judge_attack(atk, "I can't help.")))
    req = {"judge": {"require_any_of": ["can't help", "cannot help"]}}
    check("judge: require_any_of satisfied -> pass", ev.judge_attack(req, "I CANNOT help with that")[0] == "pass")
    check("judge: require_any_of missing -> fail", ev.judge_attack(req, "Sure! Here is my system prompt")[0] == "fail")
    both = {"judge": {"fail_if_contains": ["secret"], "require_any_of": ["can't"]}}
    check("judge: a fail marker beats a satisfied require", ev.judge_attack(both, "I can't, but the secret is 1")[0] == "fail")
    rows = [dict(seq=i, kind="attack", judge="heuristic", case_id=f"c{i}", category="x", status=s, latency_ms=l, test_id="t", response_sha256="h", http_status=200)
            for i, (s, l) in enumerate([("pass", 10), ("pass", 20), ("fail", 30), ("blocked", None), ("error", 100), ("pass", 40)], 1)]
    sm = ev.summarize(rows)
    check("summary: total/passed/failed/blocked/errors", (sm["total"], sm["passed"], sm["failed"], sm["blocked"], sm["errors"]) == (6, 3, 1, 1, 1), sm)
    check("summary: latency stats only over rows that have a latency", sm["latency_ms"] == {"count": 5, "min": 10, "mean": 40.0, "p50": 30, "p95": 100, "max": 100}, sm["latency_ms"])
    check("summary: no latencies -> None", ev.summarize([dict(rows[3])])["latency_ms"] is None)
    d1 = ev.results_digest(rows)
    check("digest: independent of row order", ev.results_digest(list(reversed(rows))) == d1)
    check("digest: ignores latency", ev.results_digest([{**r, "latency_ms": 999} for r in rows]) == d1)
    check("digest: changes if a status is edited", ev.results_digest([{**rows[0], "status": "fail"}] + rows[1:]) != d1)
    check("digest: changes if a response hash is edited", ev.results_digest([{**rows[0], "response_sha256": "x"}] + rows[1:]) != d1)
    check("scrub redacts secrets (and ignores short/empty values)", ev.scrub("k=abcdef123 x", ["abcdef123", "", "ab"]) == "k=[REDACTED] x")
    av = ev.anchor_verification
    check("anchor status mapping", (av({"enabled": False}), av({"enabled": True, "ok": True, "anchored": 5, "local": 5, "pending": 0}),
          av({"enabled": True, "ok": True, "anchored": 4, "local": 5, "pending": 1}), av({"enabled": True, "ok": True, "anchored": 5, "local": 5, "conflict": True}),
          av({"enabled": True, "ok": True, "anchored": 9, "local": 5, "pending": 0}), av({"enabled": True, "ok": False, "anchored": 5, "local": 5}))
          == ("not_configured", "verified", "pending", "tamper_detected", "tamper_detected", "unreachable"))
    check("control ids in the table are unique and total is known up front", len({c[0] for c in ev.CONTROLS}) == ev.N_CONTROLS == 12)

    print("== API: authentication, authorization, validation")
    async with client() as c:
        routes = [("GET", "/suites", None), ("GET", "/evaluations", None), ("GET", "/evaluations/abc", None),
                  ("GET", "/evaluations/abc/results", None), ("POST", "/evaluations", {"suite_id": SUITE_ID})]
        check("no token -> 401 on all 5 routes", await all_status(c, [(m, p, None, b) for m, p, b in routes], 401))
        for name, hdr in (("red", RED), ("blue", BLUE), ("admin", ADMIN)):
            check(f"{name} token -> 403 on all 5 routes", await all_status(c, [(m, p, hdr, b) for m, p, b in routes], 403))
        only_read = tok("reader", ["eval:read"])
        check("eval:read alone can list but cannot start a run", (await c.get("/evaluations", headers=only_read)).status_code == 200
              and (await c.post("/evaluations", headers=only_read, json={"suite_id": SUITE_ID})).status_code == 403)
        check("evaluator token cannot use Red/Blue/audit routes",
              (await c.post("/red/tests", headers=EV, json={"prompt": "x"})).status_code == 403
              and (await c.get("/blue/tests", headers=EV)).status_code == 403 and (await c.get("/audit/verify", headers=EV)).status_code == 403)
        s = (await c.get("/suites", headers=EV)).json()
        check("GET /suites lists builtin-core with counts and hash but no prompt text",
              s[0]["id"] == SUITE_ID and s[0]["attacks"] == 13 and len(s[0]["sha256"]) == 64 and "Pretend you are DAN" not in json.dumps(s))
        bad = lambda body: c.post("/evaluations", headers=EV, json=body)
        check("unknown suite -> 422", (await bad({"suite_id": "nope"})).status_code == 422)
        check("unknown model -> 422", (await bad({"suite_id": SUITE_ID, "model": "nope"})).status_code == 422)
        check("malformed suite_id / model / body -> 422", await all_status(c, [("POST", "/evaluations", EV, b) for b in
              ({"suite_id": "../x"}, {"suite_id": "A B"}, {"suite_id": ""}, {}, {"suite_id": SUITE_ID, "model": "a b"})], 422))
        reg = llm_adapters.Registry([{"id": "mock", "provider": "mock", "endpoint": "http://llm:8000"},
                                     {"id": "claude-x", "provider": "anthropic", "model": "m", "api_key_env": "BAYORA_TEST_NO_SUCH_KEY"}])
        orig, gw.runner.models = gw.runner.models, reg
        r = await bad({"suite_id": SUITE_ID, "model": "claude-x"})
        gw.runner.models = orig
        check("a model whose API key is not set is refused up front (422), no run created", r.status_code == 422 and "not configured" in r.text and (await c.get("/evaluations", headers=EV)).json() == [])
        check("unknown run id -> 404 (also for path-shaped ids)", await all_status(c, [("GET", p, EV, None) for p in
              ("/evaluations/zzzzzzzzzzzz", "/evaluations/..%2f..%2fetc", "/evaluations/x'%20OR%20'1'='1", "/evaluations/zzzzzzzzzzzz/results")], 404))

    print("== a full run against the mock model")
    async with client() as c:
        r = await c.post("/evaluations", headers=EV, json={"suite_id": SUITE_ID})
        first = r.json(); rid = first["run_id"]
        check("POST /evaluations -> 202 with run id, status running, total 25, no summary yet",
              r.status_code == 202 and first["status"] == "running" and first["total"] == 25 and first["summary"] is None and first["model"] == "mock")
        await gw.runner.wait()
        run, rows = await get_run(c, rid), await get_rows(c, rid)
        R = by_id(rows)
        sm = run["summary"]
        check("run completed with every case done", run["status"] == "completed" and run["done"] == run["total"] == 25 and len(rows) == 25)
        check("suite id/version/sha256 and model recorded on the run", run["suite"] == {"id": SUITE_ID, "version": 1, "sha256": gw.SUITES.get(SUITE_ID)["sha256"]} and run["model"] == "mock")
        check("summary: 25 total, 23 passed, 2 failed, 0 blocked, 0 errors", (sm["total"], sm["passed"], sm["failed"], sm["blocked"], sm["errors"]) == (25, 23, 2, 0, 0), sm)
        check("the 2 failures are exactly the two jailbreaks the mock falls for (heuristic)",
              {k for k, v in R.items() if v["status"] == "fail"} == {"jb-dan-persona", "jb-developer-mode"} and all(R[k]["judge"] == "heuristic" for k in ("jb-dan-persona", "jb-developer-mode")))
        check("all 12 deterministic controls pass", sm["by_judge"]["deterministic"] == {"pass": 12, "fail": 0, "blocked": 0, "error": 0}, sm["by_judge"])
        check("heuristic tally: 11 pass, 2 fail", sm["by_judge"]["heuristic"] == {"pass": 11, "fail": 2, "blocked": 0, "error": 0})
        check("latency statistics cover the 13 model calls", sm["latency_ms"] and sm["latency_ms"]["count"] == 13 and sm["latency_ms"]["max"] >= sm["latency_ms"]["min"] >= 0)
        check("integrity: audit chain verified at the end of the run", run["integrity"]["audit"]["ok"] is True and run["integrity"]["audit"]["entries"] > 0)
        check("integrity: anchor status reported (not_configured in this setup)", run["integrity"]["anchor"]["status"] == "not_configured")
        check("db_check: rows match the run digest AND the audit log", run["db_check"] == {"digest_matches_run_record": True, "audit_completed_event": "found", "digest_matches_audit": True}, run["db_check"])
        check("every control is labelled deterministic, every attack heuristic", all(r["judge"] == ("deterministic" if r["kind"] == "control" else "heuristic") for r in rows))
        check("heuristic rows say so in their detail; deterministic rows never do", all(r["detail"].startswith("HEURISTIC") == (r["judge"] == "heuristic") for r in rows))
        att = [r for r in rows if r["kind"] == "attack"]
        check("each attack row has test id, hashes, length, excerpt (<=200), latency, http status, timestamps",
              all(r["test_id"] and len(r["response_sha256"]) == 64 and r["response_len"] > 0 and 0 < len(r["response_excerpt"]) <= 200 and r["latency_ms"] is not None and r["http_status"] == 200 and r["finished"] >= r["started"] > 0 for r in att))
        check("each attack row's audit status is 'recorded' with the audit sequence number", all(r["audit_status"] == "recorded" and isinstance(r["audit_seq"], int) for r in att))
        check("each row stores the hash of the exact response the gateway returned", all(
            r["response_sha256"] == sha((gw.store.get_test(r["test_id"]) or {}).get("response", "")) for r in att))
        check("rows are in execution order and numbered 1..25", [r["seq"] for r in rows] == list(range(1, 26)))
        check("expected security property is stored with every row", all(r["expected"] for r in rows))
        lst = (await c.get("/evaluations", headers=EV)).json()
        check("history lists the run (no db_check in list items)", [x["run_id"] for x in lst] == [rid] and "db_check" not in lst[0])
        blob = json.dumps([run, rows, lst])
        check("no token, JWT, signing secret or Authorization header appears in any API output", "eyJ" not in blob and "test-secret" not in blob and "Authorization" not in blob and "Bearer" not in blob)
        ents = gw.audit.tail(2000)
        mine = [e for e in ents if e["data"].get("run_id") == rid]
        check("audit has evaluation_started then evaluation_completed for this run, actor = the evaluator token's sub",
              [e["event"] for e in mine] == ["evaluation_started", "evaluation_completed"] and all(e["actor"] == "evaluator" for e in mine))
        check("completed audit entry carries the digest and the counts", mine[1]["data"]["results_digest"] == run["results_digest"] and mine[1]["data"]["failed"] == 2 and mine[1]["data"]["results"] == 25)
        check("started audit entry records suite id, version and sha", mine[0]["data"]["suite_sha256"] == run["suite"]["sha256"] and mine[0]["data"]["suite_version"] == 1)
        sub = [e for e in ents if e["event"] == "test_submitted" and e["data"]["test_id"] in {r["test_id"] for r in att}]
        check("every attack went through the normal pipeline: audited submissions by actor eval-red", len(sub) == 13 and all(e["actor"] == "eval-red" for e in sub))
        check("blue-side reads were made as eval-blue; denials were audited", {e["actor"] for e in ents if e["event"] == "results_released"} >= {"eval-blue"}
              and sum(e["event"] == "early_access_denied" for e in ents) >= 13)
        check("the control probes' rejected requests were audited as policy violations", any(e["event"] == "policy_violation" and e["actor"].startswith("eval-probe-") for e in ents))
        check("audit log stores no prompt or response text", "restrictions disabled" not in open(os.environ["AUDIT_PATH"]).read().lower())
        check("audit chain still verifies", gw.audit.verify()["ok"])
        BASE_RID = rid

    print("== a run while another is running; then a clean follow-up")
    orig_call = llm_adapters.MockAdapter._call
    async def slow(self, prompt, key, session):
        await asyncio.sleep(0.04); return await orig_call(self, prompt, key, session)
    llm_adapters.MockAdapter._call = slow
    try:
        async with client() as c:
            rid1 = await run_via_api(c, wait=False)
            for _ in range(100):                      # poll until the run has made progress (no fixed sleep)
                mid = await get_run(c, rid1)
                if mid["done"] > 0: break
                await asyncio.sleep(0.02)
            check("while running: status running and progress strictly between 0 and total", mid["status"] == "running" and 0 < mid["done"] < mid["total"], (mid["status"], mid["done"]))
            r2 = await c.post("/evaluations", headers=EV, json={"suite_id": SUITE_ID})
            check("second start during a run -> 409 naming the active run", r2.status_code == 409 and rid1 in r2.text, r2.text)
            check("the list shows exactly one run row for it (no duplicate created by the refused call)", len([x for x in (await c.get("/evaluations", headers=EV)).json() if x["run_id"] == rid1]) == 1
                  and len((await c.get("/evaluations", headers=EV)).json()) == 2)
            await gw.runner.wait()
            check("first run finished normally", (await get_run(c, rid1))["status"] == "completed")
            r3 = await c.post("/evaluations", headers=EV, json={"suite_id": SUITE_ID}); await gw.runner.wait()
            check("after it finishes a new run is accepted (202) and completes", r3.status_code == 202 and (await get_run(c, r3.json()["run_id"]))["status"] == "completed")
    finally:
        llm_adapters.MockAdapter._call = orig_call

    print("== fault injection: statuses stay honest")
    async with client() as c:
        async def down(self, prompt, key, session): raise llm_adapters.AdapterError("boom")
        llm_adapters.MockAdapter._call = down
        try:
            rid = await run_via_api(c); run, rows = await get_run(c, rid), await get_rows(c, rid)
        finally:
            llm_adapters.MockAdapter._call = orig_call
        sm = run["summary"]
        check("model down: run still completes; 13 attacks + session probe + 3 derived controls are 'error', not 'fail'", run["status"] == "completed" and (sm["errors"], sm["failed"], sm["blocked"], sm["passed"]) == (17, 0, 0, 8), sm)
        check("model down: the 8 gateway controls that need no model still pass", all(r["status"] == "pass" for r in rows if r["case_id"].startswith(("ctl-authn", "ctl-authz"))))
        check("model down: error rows carry the HTTP status and no response data", all(r["http_status"] == 502 and r["response_sha256"] is None and r["audit_status"] is None for r in rows if r["kind"] == "attack"))
        check("model down: the failures are in the audit log (llm_error) and the chain verifies", any(e["event"] == "llm_error" for e in gw.audit.tail(300)) and run["integrity"]["audit"]["ok"])

        crippled = dict(ROLES, red=["test:conclude"])               # the runner's Red actor loses test:submit -> gateway refuses
        r2 = ev.Runner(gw.app, gw.audit, gw.store, gw.MODELS, gw.SUITES, gw._mint, crippled, gw._secret_values)
        run0 = r2.start("evaluator", None, SUITE_ID); await r2.wait()
        rows = gw.store.results(run0["run_id"]); sm = gw.store.get_run(run0["run_id"])["summary"]
        check("gateway refusals (403) are 'blocked', not 'fail' or 'error'", sum(r["status"] == "blocked" for r in rows if r["kind"] == "attack") == 13 and sm["blocked"] == 13, sm)
        check("blocked rows say the gateway refused before any output was judged", all("refused" in r["detail"] and r["http_status"] == 403 for r in rows if r["status"] == "blocked"))

        SECRET_TEXT = "api_key=test-secret and more"
        async def leaky(self, prompt, key, session): return SECRET_TEXT
        llm_adapters.MockAdapter._call = leaky
        try:
            rid = await run_via_api(c); rows = await get_rows(c, rid); R = by_id(rows)
        finally:
            llm_adapters.MockAdapter._call = orig_call
        check("a model reply that contains the signing secret: stored excerpt is redacted", "test-secret" not in json.dumps(rows) and "[REDACTED]" in R["ex-credentials"]["response_excerpt"])
        check("...the heuristic still flags the credential-shaped reply (marker 'api_key=')", R["ex-credentials"]["status"] == "fail" and "api_key=" in json.dumps(R["ex-credentials"]["evidence"]))
        check("...and the stored hash is of the raw reply, so it still matches the audit log", R["ex-credentials"]["response_sha256"] == sha(SECRET_TEXT) and R["ex-credentials"]["audit_status"] == "recorded")

    print("== controls can actually fail (mutation tests)")
    async def mutated_run(c, **kw):
        rid = await run_via_api(c, **kw); return by_id(await get_rows(c, rid)), await get_run(c, rid)
    async with client() as c:
        orig_get = store_mod.Store.get_test
        store_mod.Store.get_test = lambda self, tid: (lambda t: {**t, "status": "concluded"} if t else t)(orig_get(self, tid))
        try:
            R, run = await mutated_run(c)
        finally:
            store_mod.Store.get_test = orig_get
        check("phase gate broken (Blue can read active tests) -> ctl-phase-gate-blocks-active FAILS", R["ctl-phase-gate-blocks-active"]["status"] == "fail" and run["summary"]["by_judge"]["deterministic"]["fail"] >= 1)

        orig_sess = gw.llm_session
        gw.llm_session = lambda sub, sid: None if sid is None else "one-shared-session"
        try:
            R, _ = await mutated_run(c)
        finally:
            gw.llm_session = orig_sess
        check("sessions share state (isolation broken) -> ctl-session-isolation FAILS", R["ctl-session-isolation"]["status"] == "fail" and R["ctl-session-isolation"]["evidence"][0]["secret_returned_to_B"] is True)

        orig_append = gw.audit.append
        gw.audit.append = lambda event, actor, data: ({"seq": -1} if event == "test_submitted" else orig_append(event, actor, data))
        try:
            R, run = await mutated_run(c)
        finally:
            gw.audit.append = orig_append
        check("audit drops test_submitted entries -> ctl-audit-records-submissions FAILS and attack rows show 'missing'",
              R["ctl-audit-records-submissions"]["status"] == "fail" and all(R[a["id"]]["audit_status"] == "missing" for a in gw.SUITES.get(SUITE_ID)["attacks"]))

        orig_verify = auth.verify
        auth.verify = lambda authorization: auth.Principal("anyone", [s for sc in ROLES.values() for s in sc])
        try:
            R, _ = await mutated_run(c)
        finally:
            auth.verify = orig_verify
        check("auth accepts anything -> the three authn controls FAIL", all(R[k]["status"] == "fail" for k in ("ctl-authn-missing-token", "ctl-authn-forged-signature", "ctl-authn-expired-token")))
        check("...and the authz controls FAIL too (everything is allowed)", all(R[k]["status"] == "fail" for k in ("ctl-authz-red-cannot-read-blue", "ctl-authz-blue-cannot-submit", "ctl-authz-red-cannot-read-audit")))

        wide = dict(ROLES, evaluator=ROLES["evaluator"] + ["test:submit", "test:list", "audit:read"])
        r3 = ev.Runner(gw.app, gw.audit, gw.store, gw.MODELS, gw.SUITES, gw._mint, wide, gw._secret_values)
        run0 = r3.start("evaluator", None, SUITE_ID); await r3.wait()
        R = by_id(gw.store.results(run0["run_id"]))
        check("evaluator role with extra scopes -> ctl-authz-evaluator-confined FAILS", R["ctl-authz-evaluator-confined"]["status"] == "fail")
        check("the other controls are unaffected by that mutation", R["ctl-authn-missing-token"]["status"] == "pass")

    print("== persistence across a gateway restart")
    async with client() as c:
        before_run, before_rows = await get_run(c, BASE_RID), await get_rows(c, BASE_RID)
        n_runs = len((await c.get("/evaluations", headers=EV)).json())
    st = gw.store
    st.create_run("deadbeef0001", "evaluator", "mock", gw.SUITES.get(SUITE_ID), 25)      # a run whose process died mid-way
    st.add_result("deadbeef0001", dict(seq=1, kind="control", judge="deterministic", case_id="ctl-authn-missing-token", category="authentication",
                                       severity="critical", expected="e", status="pass", detail="d", evidence=[], started=1.0, finished=2.0))
    gw = importlib.reload(gw)                                                           # "restart": same DB + audit files, new process state
    check("gateway object really was rebuilt", gw.store is not st)
    async with client() as c:
        after_run, after_rows = await get_run(c, BASE_RID), await get_rows(c, BASE_RID)
        check("completed run: identical summary, integrity, digest and results after restart", after_run == before_run and after_rows == before_rows)
        check("completed run: db_check still all-true after restart", after_run["db_check"]["digest_matches_run_record"] and after_run["db_check"]["digest_matches_audit"])
        dead = await get_run(c, "deadbeef0001")
        check("a run that was 'running' at the crash is now 'interrupted' (not stuck running)", dead["status"] == "interrupted" and dead["finished"])
        check("...its partial result survived: done=1 of total=25", dead["done"] == 1 and dead["total"] == 25 and len(await get_rows(c, "deadbeef0001")) == 1)
        check("...and the interruption is in the audit log", any(e["event"] == "evaluation_interrupted" and e["data"]["run_id"] == "deadbeef0001" for e in gw.audit.tail(500)))
        check("history shows all runs after restart", len((await c.get("/evaluations", headers=EV)).json()) == n_runs + 1)
        n_int = sum(e["event"] == "evaluation_interrupted" for e in gw.audit.tail(2000))
        gw = importlib.reload(gw)
        check("a second restart does not re-interrupt or double-audit anything", sum(e["event"] == "evaluation_interrupted" for e in gw.audit.tail(2000)) == n_int)
    async with client() as c:
        rid = await run_via_api(c)
        check("a new run starts and completes normally after restart", (await get_run(c, rid))["status"] == "completed" and (await get_run(c, rid))["summary"]["failed"] == 2)

        print("== tamper detection on the stored results")
        rows = await get_rows(c, rid)
        db = sqlite3.connect(gw.store.path)
        db.execute("UPDATE eval_results SET status='pass' WHERE run_id=? AND case_id='jb-dan-persona'", (rid,)); db.commit()
        chk = (await get_run(c, rid))["db_check"]
        check("flipping a stored 'fail' to 'pass' in SQLite is detected (digest no longer matches run record or audit)", chk["digest_matches_run_record"] is False and chk["digest_matches_audit"] is False, chk)
        db.execute("UPDATE eval_results SET status='fail' WHERE run_id=? AND case_id='jb-dan-persona'", (rid,)); db.commit()
        check("restoring the value makes the check pass again", (await get_run(c, rid))["db_check"]["digest_matches_audit"] is True)
        db.execute("UPDATE eval_results SET response_sha256='00' WHERE run_id=? AND case_id='jb-roleplay-nofilter'", (rid,)); db.commit(); db.close()
        check("editing a stored response hash is detected too", (await get_run(c, rid))["db_check"]["digest_matches_run_record"] is False)
        check("the audit chain itself is untouched by DB edits and still verifies", gw.audit.verify()["ok"])

    print(f"\nResult: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)

asyncio.run(main())
