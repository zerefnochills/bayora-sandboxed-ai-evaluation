#!/usr/bin/env python3
"""No-Docker tests for evidence bundles, scripts/verify_evidence.py and the printable report.
    python3 tests/evidence_test.py        # needs: pip install fastapi httpx pyjwt
"""
import asyncio, copy, hashlib, importlib, importlib.util, json, os, re, socket, subprocess, sys, tempfile, time, warnings
warnings.filterwarnings("ignore")

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp()
with socket.socket() as _s:
    _s.bind(("127.0.0.1", 0)); DEAD = _s.getsockname()[1]
json.dump({"default": "mock", "models": [{"id": "mock", "provider": "mock", "name": "Mock LLM", "kind": "mock"},
           {"id": "dead", "provider": "ollama", "model": "llama3.2", "endpoint": f"http://127.0.0.1:{DEAD}/v1", "timeout_s": 5}]}, open(TMP + "/models.json", "w"))
os.environ.update(JWT_SECRET="test-secret", AUDIT_PATH=TMP + "/audit.jsonl", MODELS_CONFIG=TMP + "/models.json")
os.environ.pop("DB_PATH", None)
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx, jwt  # noqa: E402

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

llm = load(os.path.join(ROOT, "containers/llm/main.py"), "llm_app")
verifier = load(os.path.join(ROOT, "scripts/verify_evidence.py"), "verify_evidence")
gw = importlib.import_module("main")
evidence = importlib.import_module("evidence")
evaluator = importlib.import_module("evaluator")
_real = httpx.AsyncClient
class Dispatch(httpx.AsyncBaseTransport):
    """model calls go to the in-process mock LLM; the 'dead' provider's port refuses connections like a real closed port"""
    def __init__(self): self.llm = httpx.ASGITransport(app=llm.app)
    async def handle_async_request(self, request):
        if request.url.port == DEAD: raise httpx.ConnectError("connection refused", request=request)
        return await self.llm.handle_async_request(request)
class Routed(_real):
    def __init__(self, *a, **k):
        k["transport"] = Dispatch(); super().__init__(*a, **k)
httpx.AsyncClient = Routed

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)[:300]))

def tok(sub, scope): return {"Authorization": "Bearer " + jwt.encode({"sub": sub, "scope": scope, "exp": int(time.time()) + 600}, "test-secret", "HS256")}
R = gw.DEMO_SCOPES
EV, RED, BLUE, ADMIN = (tok(r, R[r]) for r in ("evaluator", "red", "blue", "admin"))
sha = lambda t: hashlib.sha256(t.encode()).hexdigest()
def client(): return _real(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw")

async def run_eval(c, model="mock"):
    r = await c.post("/evaluations", headers=EV, json={"suite_id": "builtin-core", "model": model}); assert r.status_code == 202, r.text
    await gw.runner.wait(); return r.json()["run_id"]

def reseal(b):
    """what a careful forger does: recompute the bundle digest after editing"""
    b["digest"] = evidence.bundle_digest(b); return b
def results(b): return {r["check"]: r["result"] for r in verifier.verify(b)}
def failing(b): return sorted(k for k, v in results(b).items() if v == "FAIL")
def text_of(page):
    body = page.split("<main>")[1]
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))

async def main():
    global gw
    async with client() as c:
        rid = await run_eval(c)
        print("== routes")
        routes = [f"/evaluations/{rid}/evidence", f"/evaluations/{rid}/report"]
        for name, hdr in (("no token", {}), ("red", RED), ("blue", BLUE), ("admin", ADMIN)):
            codes = [(await c.get(p, headers=hdr)).status_code for p in routes]
            check(f"{name}: {'401' if name == 'no token' else '403'} on evidence and report", codes == ([401, 401] if name == "no token" else [403, 403]), codes)
        check("unknown or malformed run id -> 404 on both routes", [(await c.get(p, headers=EV)).status_code for p in
              ("/evaluations/zzzzzzzzzzzz/evidence", "/evaluations/zzzzzzzzzzzz/report", "/evaluations/..%2fx/evidence", "/evaluations/x'%20OR%201=1/report")] == [404] * 4)
        r2 = await c.post("/evaluations", headers=EV, json={"suite_id": "builtin-core"})
        running = [(await c.get(f"/evaluations/{r2.json()['run_id']}/{x}", headers=EV)).status_code for x in ("evidence", "report")]
        await gw.runner.wait()
        check("a run that is still running -> 409 on both routes (no half-finished evidence)", running == [409, 409], running)
        e = await c.get(routes[0], headers=EV); rep = await c.get(routes[1], headers=EV)
        check("evidence: 200 JSON download, no-store, nosniff, named after the run", e.status_code == 200 and e.headers["content-type"].startswith("application/json") and e.headers["cache-control"] == "no-store"
              and e.headers["x-content-type-options"] == "nosniff" and rid in e.headers["content-disposition"] and "attachment" in e.headers["content-disposition"])
        check("report: 200 HTML with the CSP header, no-store, nosniff, no-referrer", rep.status_code == 200 and rep.headers["content-type"].startswith("text/html") and rep.headers["content-security-policy"] == evidence.CSP
              and rep.headers["cache-control"] == "no-store" and rep.headers["x-content-type-options"] == "nosniff" and rep.headers["referrer-policy"] == "no-referrer")
        B = e.json(); BASE = copy.deepcopy(B)

        print("== bundle content")
        check("format, generator, digest are present", B["format"] == "bayora.evidence/1" and B["generator"]["name"] == "bayora-gateway" and len(B["digest"]) == 64 and B["digest"] == evidence.bundle_digest(B))
        check("run metadata: model, provider kind mock, suite id/version/hash, completed, summary and integrity included", B["run"]["model"] == "mock" and B["run"]["provider_kind"] == "mock" and B["run"]["suite"]["id"] == "builtin-core"
              and B["run"]["status"] == "completed" and B["run"]["summary"]["total"] == 25 and B["run"]["integrity"]["audit"]["ok"] is True)
        check("all 25 result rows with the full fields (hashes, excerpt, evidence, audit status)", len(B["results"]) == 25 and all({"response_sha256", "audit_status", "evidence", "detail", "expected"} <= set(x) for x in B["results"]))
        check("the exact suite definition is embedded and hashes to the recorded suite hash", B["suite"]["definition"] is not None and
              hashlib.sha256(json.dumps(B["suite"]["definition"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest() == B["run"]["suite"]["sha256"] and len(B["suite"]["definition"]["attacks"]) == 13)
        check("verification block states what was checked at generation time and that it is not re-derivable", B["verification"]["audit_chain_ok"] is True and "cannot be re-derived" in B["verification"]["note"])
        ents = B["audit"]["entries"]
        tids = {x["test_id"] for x in B["results"] if x["test_id"]}
        check("audit excerpt: only this run's entries (run events, its tests' events, its control probes), each with prev and hash",
              all(x["data"].get("run_id") == rid or x["data"].get("test_id") in tids or x["actor"].startswith("eval-probe-") for x in ents) and all(len(x["hash"]) == 64 and len(x["prev"]) == 64 for x in ents))
        check("excerpt includes start, completion, every submission, denial, conclusion and release", {"evaluation_started", "evaluation_completed", "test_submitted", "early_access_denied", "test_concluded", "results_released"} <= {x["event"] for x in ents})

        await c.post("/red/tests", headers=RED, json={"prompt": "manual red-team prompt by another user"})
        rid_b = await run_eval(c)
        B2 = (await c.get(f"/evaluations/{rid_b}/evidence", headers=EV)).json(); tids2 = {x["test_id"] for x in B2["results"] if x["test_id"]}
        again = (await c.get(routes[0], headers=EV)).json()
        check("another user's manual test and the second run never appear in the first run's excerpt (privacy)", not ({x["data"].get("test_id") for x in again["audit"]["entries"]} & tids2)
              and all(x["data"].get("run_id") in (rid, None) for x in again["audit"]["entries"]) and not any("manual" in json.dumps(x) for x in again["audit"]["entries"]))
        check("asking twice gives identical results and audit excerpts (reading evidence writes nothing)", again["results"] == B["results"] and again["audit"] == B["audit"])
        check("no token, JWT or signing secret in the bundle or report", "eyJ" not in e.text and "test-secret" not in e.text and "eyJ" not in rep.text and "test-secret" not in rep.text)

        print("== verifier on the real bundle")
        r = verifier.verify(B)
        check("every check passes", all(x["result"] in ("PASS", "INFO") for x in r) and sum(x["result"] == "PASS" for x in r) >= 14, [x for x in r if x["result"] == "FAIL"])
        check("the continuity/anchor line is INFO, never PASS (we do not overclaim)", [x["result"] for x in r if "continuity" in x["check"]] == ["INFO"])
        path = TMP + "/bundle.json"; json.dump(B, open(path, "w"))
        cli = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/verify_evidence.py"), path], capture_output=True, text=True)
        check("CLI: exit 0 and 'ALL CHECKS PASSED'", cli.returncode == 0 and "ALL CHECKS PASSED" in cli.stdout, cli.stdout[-300:])
        cj = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/verify_evidence.py"), path, "--json"], capture_output=True, text=True)
        check("CLI --json: valid JSON with ok=true", json.loads(cj.stdout)["ok"] is True)
        check("the verifier needs no gateway code: it runs with an empty PYTHONPATH from another directory", subprocess.run([sys.executable, os.path.join(ROOT, "scripts/verify_evidence.py"), path], capture_output=True, text=True, cwd=TMP, env={"PATH": os.environ["PATH"]}).returncode == 0)
        open(TMP + "/junk.json", "w").write("{not json"); json.dump({"format": "other"}, open(TMP + "/other.json", "w")); json.dump({"format": "bayora.evidence/1"}, open(TMP + "/partial.json", "w"))
        codes = [subprocess.run([sys.executable, os.path.join(ROOT, "scripts/verify_evidence.py"), TMP + "/" + f], capture_output=True, text=True).returncode for f in ("junk.json", "other.json", "partial.json", "missing.json")]
        check("CLI: unreadable / wrong-format / partial / missing file -> exit 2 (never a false pass)", codes == [2, 1, 2, 2], codes)

        print("== tampering is caught (the forger even recomputes the bundle digest)")
        def mut(f, seal=True):
            b = copy.deepcopy(BASE); f(b); return reseal(b) if seal else b
        row = lambda b, cid: next(x for x in b["results"] if x["case_id"] == cid)
        aud = lambda b, ev, key=None: next(x for x in b["audit"]["entries"] if x["event"] == ev and (key is None or x["data"].get("test_id") == key))
        check("edit without resealing: the digest check fails", "bundle digest matches its content" in failing(mut(lambda b: row(b, "jb-dan-persona").update(status="pass"), seal=False)))
        f = failing(mut(lambda b: row(b, "jb-dan-persona").update(status="pass")))
        check("hide a flagged probe (fail->pass), digest resealed: results digest AND summary checks fail", {"results digest matches the result rows", "summary counts match the result rows"} <= set(f), f)
        f = failing(mut(lambda b: aud(b, "test_submitted").update(data={**aud(b, "test_submitted")["data"], "response_sha256": "0" * 64})))
        check("edit an audit entry's content: its own hash fails (and the reply-hash link breaks)", "every audit entry's hash matches its own content" in f and "every attack's reply hash matches its audit entry" in f, f)
        def forge_entry(b):
            e = aud(b, "test_submitted"); e["data"] = {**e["data"], "response_sha256": "0" * 64}
            e["hash"] = verifier.audit_digest(e["prev"], e["seq"], e["ts"], e["event"], e["actor"], e["data"])
        f = failing(mut(forge_entry))
        check("edit an entry AND fix its hash: the link to the result row still breaks", f == ["every attack's reply hash matches its audit entry"], f)
        def drop_done(b): b["audit"]["entries"] = [x for x in b["audit"]["entries"] if x["event"] != "evaluation_completed"]
        check("delete the completion entry: 'audit seals the same results digest' fails", "audit seals the same results digest" in failing(mut(drop_done)))
        def edit_digest_in_audit(b):
            e = aud(b, "evaluation_completed"); e["data"] = {**e["data"], "results_digest": "f" * 64}
            e["hash"] = verifier.audit_digest(e["prev"], e["seq"], e["ts"], e["event"], e["actor"], e["data"])
        check("audit says a different results digest (hash fixed): seal check fails", "audit seals the same results digest" in failing(mut(edit_digest_in_audit)))
        f = failing(mut(lambda b: b["suite"]["definition"]["attacks"][0].update(prompt="a friendlier prompt")))
        check("rewrite a prompt in the suite definition: suite content hash fails", "suite content hash matches the hash recorded with the run" in f, f)
        f = failing(mut(lambda b: row(b, "jb-dan-persona").update(expected="Anything goes.")))
        check("rewrite a row's expected property: it no longer matches the suite definition (and the results digest does not cover it, so only this check sees it)", f == ["every attack row matches the suite definition"], f)
        f = failing(mut(lambda b: b["run"]["summary"].update(passed=25, failed=0)))
        check("edit only the summary: the summary check fails, and so does the cross-check with the audit entry's counts", f == ["audit counts match the summary", "summary counts match the result rows"], f)
        f = failing(mut(lambda b: row(b, "jb-dan-persona").update(judge="deterministic")))
        check("relabel a heuristic row as deterministic: caught", "every row is labelled with the judge that produced it" in failing(mut(lambda b: row(b, "jb-dan-persona").update(judge="deterministic"))))
        f = failing(mut(lambda b: b["results"].pop(3)))
        check("delete a result row: numbering, summary and digest checks fail", {"result rows are numbered 1..n without gaps", "summary counts match the result rows", "results digest matches the result rows"} <= set(f), f)
        f = failing(mut(lambda b: b["audit"]["entries"].reverse()))
        check("reorder audit entries: ordering check fails", "audit entries are in strictly increasing order" in f, f)
        def swap_gate(b):
            tid = next(x["test_id"] for x in b["results"] if x["test_id"])
            den, rel = aud(b, "early_access_denied", tid), aud(b, "results_released", tid)
            den["seq"], rel["seq"] = rel["seq"], den["seq"]
            for e in (den, rel): e["hash"] = verifier.audit_digest(e["prev"], e["seq"], e["ts"], e["event"], e["actor"], e["data"])
            b["audit"]["entries"].sort(key=lambda x: x["seq"])
        check("make Blue's release come before the denial (hashes fixed): gate-order check fails", "phase gate order holds: denied while active, then concluded, then released" in failing(mut(swap_gate)))
        def full_forgery(b):
            """edit the row, its audit entry, the entry hash, the results digest, the run record AND the bundle digest consistently"""
            r_ = row(b, "jb-dan-persona"); r_["response_sha256"] = "1" * 64
            e = aud(b, "test_submitted", r_["test_id"]); e["data"] = {**e["data"], "response_sha256"
            : "1" * 64}; e["hash"] = verifier.audit_digest(e["prev"], e["seq"], e["ts"], e["event"], e["actor"], e["data"])
            d = verifier.sha256(verifier.canonical([{k: x.get(k) for k in verifier.ROW_KEYS} for x in sorted(b["results"], key=lambda x: x["seq"])]))
            b["run"]["results_digest"] = d; aud(b, "evaluation_completed")["data"]["results_digest"] = d
            e2 = aud(b, "evaluation_completed"); e2["hash"] = verifier.audit_digest(e2["prev"], e2["seq"], e2["ts"], e2["event"], e2["actor"], e2["data"])
        fb = mut(full_forgery); rr = results(fb)
        check("KNOWN LIMIT: a fully coherent forgery of the sparse excerpt is not detectable offline; the verifier still reports chain continuity and the anchor only as INFO", not [k for k, v in rr.items() if v == "FAIL"] and [v for k, v in rr.items() if "continuity" in k] == ["INFO"])
        check("...which is why the gateway's live check of the full chain and the independent anchor remain the authority (documented in the bundle's own note)", "cannot be re-derived" in fb["verification"]["note"])

        print("== suite changed after the run")
        orig = gw.SUITES.suites["builtin-core"]
        gw.SUITES.suites["builtin-core"] = {**orig, "sha256": "e" * 64, "version": 2}
        B3 = (await c.get(routes[0], headers=EV)).json()
        gw.SUITES.suites["builtin-core"] = orig
        check("a suite file that changed since: definition omitted with an explanatory note, never silently substituted", B3["suite"]["definition"] is None and "changed or was removed" in B3["suite"]["note"] and B3["run"]["suite"]["sha256"] == BASE["run"]["suite"]["sha256"])
        rr = results(B3)
        check("verifier: everything else still passes; suite definition is INFO", not [k for k, v in rr.items() if v == "FAIL"] and rr["suite definition"] == "INFO")

        print("== a run that failed at the provider health check")
        rid_f = await run_eval(c, "dead")
        Bf = (await c.get(f"/evaluations/{rid_f}/evidence", headers=EV)).json()
        check("failed-run bundle: status failed, error stage provider_health, zero result rows, no summary", Bf["run"]["status"] == "failed" and Bf["run"]["error"]["stage"] == "provider_health" and Bf["results"] == [] and Bf["run"]["summary"] is None)
        rr = results(Bf)
        check("verifier passes it and checks the audit recorded how the run ended", not [k for k, v in rr.items() if v == "FAIL"] and rr.get("audit records how the run ended (failed)") == "PASS", rr)
        Pf = (await c.get(f"/evaluations/{rid_f}/report", headers=EV)).text; Tf = text_of(Pf)
        check("report: 'Infrastructure failure', 'No attacks were sent', says it is not a verdict, no results tables", "Infrastructure failure" in Tf and "No attacks were sent to the model" in Tf and "not a verdict about the model" in Tf and "Gateway controls (deterministic)" not in Tf and "Potential downsides" not in Tf)
        check("report: labelled REAL PROVIDER (configured ollama) and still has the limitations section", "REAL PROVIDER" in Pf and "Limitations" in Tf)

        print("== the printable report")
        P = rep.text; T = text_of(P)
        order = ["Evaluation report", "Summary", "Potential downsides", "Coverage by category", "Gateway controls (deterministic)", "Attack probes (heuristic)", "Evidence and integrity", "Limitations"]
        pos = [T.find(x) for x in order]
        check("all eight sections present and in reading order", all(p >= 0 for p in pos) and pos == sorted(pos), pos)
        check("mock run: the MOCK MODEL banner says it describes nothing about any real model", "MOCK MODEL" in P and "says nothing about any real model" in T)
        check("summary numbers: 12 of 12 controls passed, 11 of 13 probes passed, 2 flagged", "12 gateway controls passed, of 12" in T and "11 probes passed, of 13" in T and "2 probes flagged" in T, T[T.find("Summary"):T.find("Summary") + 200])
        check("downsides: both flagged jailbreaks listed with severity, expected property, what happened, why it matters, what to consider",
              all(x in T for x in ("jb-dan-persona", "jb-developer-mode", "Expected:", "What happened:", "Why it matters:", "What to consider:")) and "Harden the system prompt" in T and "human review, not a confirmed flaw" in T)
        check("the heuristic nature is stated, and probes are labelled FLAGGED not 'failed the model'", "heuristic" in T.lower() and "FLAGGED" in T and "not proof" in T)
        check("coverage table: jailbreak 3 probes / 2 flagged", re.search(r"jailbreak 3 2 0", T) is not None)
        check("limitations: heuristic, small suite, single run, configuration-specific, not a certification", all(x in T for x in ("heuristic substring screens", "suite is small", "sent once", "not transfer to other versions", "not a security certification")))
        check("integrity block shows the chain verified, anchor status, digests and verifier command", "verified" in T and "not configured" in T and BASE["digest"][:16] in P or "Bundle digest" in T)
        check("one inline script only (the print button), inside a page whose CSP allows exactly that script's hash", P.count("<script") == 1 and "script-src &#x27;sha256-" in P)
        inline = re.search(r"<script>(.*?)</script>", P, re.S).group(1)
        check("the CSP hash is the real hash of that script", evidence.CSP.count(evidence.SCRIPT_HASH) == 1 and "sha256-" + __import__("base64").b64encode(hashlib.sha256(inline.encode()).digest()).decode() == evidence.SCRIPT_HASH)
        check("meta CSP equals the header CSP (so it survives being opened from a blob URL)", f'content="{evidence.CSP}"'.replace("'", "&#x27;") in P)
        check("no external resources: no http(s) URLs, no @import, no remote fonts/images/scripts", not re.search(r"(src|href)=[\"']?https?:|@import|url\(", P))
        check("print styles: @page, a no-print class for the toolbar, white background, black text", "@page" in P and "@media print" in P and "noprint" in P and "background:#fff" in P and "color:#000" in P)

        print("== report edge cases and hostile input")
        def rendered(f):
            b = copy.deepcopy(BASE); f(b); return evidence.render_report(b)
        HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)>"\'><svg/onload=alert(3)>'
        def poison(b):
            b["run"].update(model=HOSTILE, created_by=HOSTILE, provider=HOSTILE, provider_model=HOSTILE)
            for r_ in b["results"]:
                r_.update(case_id=HOSTILE + r_["case_id"], detail=HOSTILE, expected=HOSTILE, response_excerpt=HOSTILE, severity=r_["severity"])
            b["run"]["error"] = {"stage": HOSTILE, "status": HOSTILE, "detail": HOSTILE}
        H = rendered(poison)
        check("hostile strings in every model-controlled and user-controlled field are escaped everywhere", "<script>alert" not in H and "<img src=x" not in H and "<svg/onload" not in H and 'onerror=alert(2)>' not in H.replace("&lt;img src=x onerror=alert(2)&gt;", "") and "&lt;script&gt;alert(1)&lt;/script&gt;" in H, H[:200])
        check("...and the page still has exactly one script tag (ours)", H.count("<script") == 1 and H.count("</script>") == 1)
        check("a real provider is labelled REAL PROVIDER with its model", "REAL PROVIDER: ollama, model llama3.2" in rendered(lambda b: b["run"].update(provider="ollama", provider_model="llama3.2", provider_kind="real")))
        check("a run made before provider tracking is labelled PROVIDER UNKNOWN (not guessed)", "PROVIDER UNKNOWN" in rendered(lambda b: b["run"].update(provider_kind=None)))
        def noflag(b):
            for r_ in b["results"]:
                if r_["status"] == "fail": r_["status"] = "pass"
            b["run"]["summary"]["failed"], b["run"]["summary"]["passed"] = 0, 25
            b["run"]["summary"]["by_judge"]["heuristic"] = {"pass": 13, "fail": 0, "blocked": 0, "error": 0}
        Tn = text_of(rendered(noflag))
        check("no flagged probes: says so, and immediately warns it does not show the model is safe", "No probes were flagged. That does not show the model is safe" in Tn)
        def defect(b):
            row(b, "ctl-session-isolation").update(status="fail")
        Td = text_of(rendered(defect))
        check("a failed deterministic control is reported as a PLATFORM defect, loudly and by name", "1 gateway control(s) FAILED" in Td and "defects in the platform, not the model" in Td and "ctl-session-isolation" in Td)
        def infra(b):
            row(b, "ex-system-prompt").update(status="error", detail="the model or gateway failed (HTTP 502)")
            row(b, "pb-release-results").update(status="blocked")
        check("errors and blocked cases are called out as 'no verdict' and not counted as passes", "did not produce a verdict" in text_of(rendered(infra)) and "not counted as passes" in text_of(rendered(infra)))
        check("report rendering never raises on a run with no summary and no rows (e.g. interrupted at the start)",
              bool(rendered(lambda b: (b["run"].update(status="interrupted", summary=None, integrity=None), b.update(results=[])))))
        f = evidence.findings(BASE)
        check("findings(): flagged probes sorted by severity, defects and infra lists empty on a clean run", [r["case_id"] for r in f["flagged"]] == ["jb-dan-persona", "jb-developer-mode"] and f["defects"] == [] and f["infra"] == [])
        Ts = text_of(rendered(lambda b: (row(b, "jb-roleplay-nofilter").update(status="fail", severity="critical", category="made_up_category", detail="x"), None)))
        check("an unknown category still renders with generic guidance; critical sorts before high", "Review the answer manually" in Ts and Ts.find("jb-roleplay-nofilter") < Ts.find("jb-dan-persona"))

        print("== persistence")
        gw = importlib.reload(gw)
    async with client() as c:
        e2 = (await c.get(routes[0], headers=EV)).json()
        check("after a gateway restart the same run still produces a verifiable bundle with identical results", e2["results"] == BASE["results"] and all(x["result"] != "FAIL" for x in verifier.verify(e2)))

    print(f"\nResult: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)

asyncio.run(main())
