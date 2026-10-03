#!/usr/bin/env python3
"""No-Docker static security checks for the /app page and its headers.
    python3 tests/app_page_test.py        # needs: pip install fastapi httpx pyjwt
"""
import asyncio, base64, hashlib, importlib, os, re, sys, tempfile, warnings
warnings.filterwarnings("ignore")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp()
os.environ.update(JWT_SECRET="test-secret", AUDIT_PATH=TMP + "/audit.jsonl", MODELS_CONFIG="/nonexistent")
os.environ.pop("DB_PATH", None)
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx  # noqa: E402
gw = importlib.import_module("main")

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)[:300]))

async def main():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw") as c:
        r = await c.get("/app"); page, csp = r.text, r.headers.get("content-security-policy", "")
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", page, re.S)
    js = scripts[0] if scripts else ""
    check("GET /app is public (it holds no data), 200 HTML", r.status_code == 200 and r.headers["content-type"].startswith("text/html"))
    check("headers: no-store, nosniff, DENY framing, no-referrer", r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer")
    check("exactly one script, and the CSP allows exactly that script's sha256", len(scripts) == 1 and csp.count("sha256-") == 1 and "script-src 'sha256-" + base64.b64encode(hashlib.sha256(js.encode()).digest()).decode() + "'" in csp)
    check("CSP: default-src 'none', no unsafe-eval, no 'unsafe-inline' for scripts, connect only to self, no framing, no base tag", "default-src 'none'" in csp and "unsafe-eval" not in csp and "script-src 'unsafe-inline'" not in csp and "connect-src 'self'" in csp and "frame-ancestors 'none'" in csp and "base-uri 'none'" in csp)
    check("no inline event-handler attributes in the HTML (they would be blocked, and are an XSS smell)", not re.search(r"<[a-z][^>]*\son[a-z]+\s*=", page.split("<script>")[0], re.I))
    check("script never uses innerHTML, outerHTML, insertAdjacentHTML, document.write, eval or new Function", not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function", js))
    check("no external resources: no http(s):// URLs, no @import, no remote fonts or scripts", not re.search(r"https?://(?!www\.w3\.org/2000/svg)|@import", page))   # the only URL-shaped string is the SVG xmlns in the favicon
    check("tokens are never put in a URL or logged: no localStorage, no console.log, no location.search/hash use", not re.search(r"localStorage|console\.|location\.(search|hash)", js))
    check("the session token lives in sessionStorage/memory only and is cleared on sign-out", "sessionStorage.removeItem('bayora_token')" in js and "localStorage" not in js)
    check("a 401 anywhere signs the user out", "Your session ended" in js)
    check("the page labels MOCK and REAL providers and the heuristic nature of probe verdicts", "MOCK MODEL" in js and "REAL PROVIDER" in js and "heuristic" in js.lower())
    check("the setup hint tells the operator how to obtain the code and never embeds one", "bootstrap_code" in js and not re.search(r"[0-9a-f]{20}", js))
    print(f"\nResult: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
asyncio.run(main())
