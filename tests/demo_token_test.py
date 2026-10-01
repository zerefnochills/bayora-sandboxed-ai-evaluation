#!/usr/bin/env python3
"""No-Docker tests for the minted demo tokens (/ui/demo-tokens). Run from repo root:
    python3 tests/demo_token_test.py        # needs: pip install fastapi httpx pyjwt
"""
import importlib, importlib.util, os, sys, tempfile, time, warnings
warnings.filterwarnings("ignore")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SENTINEL = "STATIC-ENV-TOKEN-MUST-NOT-BE-RETURNED"
os.environ.update(JWT_SECRET="test-secret", AUDIT_PATH=tempfile.mkdtemp() + "/audit.jsonl", DEMO_UI="1",
                  RED_TOKEN=SENTINEL, BLUE_TOKEN=SENTINEL, ADMIN_TOKEN=SENTINEL, MODELS_CONFIG="/nonexistent")
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import jwt  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402
gw = importlib.import_module("main")

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
setup_env = load(os.path.join(ROOT, "scripts/setup_env.py"), "setup_env")

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)))

host = TestClient(gw.app, client=("172.28.9.1", 5555))          # the VM side (admin-net / published port)
def bearer(t): return {"Authorization": "Bearer " + t}
dec = lambda t: jwt.decode(t, "test-secret", algorithms=["HS256"])

print("== guards (unchanged behaviour)")
os.environ.pop("DEMO_UI"); check("DEMO_UI unset -> 404", host.get("/ui/demo-tokens").status_code == 404)
os.environ["DEMO_UI"] = "1"
for net in ("172.28.1.3", "172.28.2.3", "172.28.3.2"):
    check(f"caller on tenant net {net} -> 404", TestClient(gw.app, client=(net, 1)).get("/ui/demo-tokens").status_code == 404)

print("== minted tokens")
r = host.get("/ui/demo-tokens"); t1 = r.json()
check("200 with red/blue/admin/evaluator (exact set)", r.status_code == 200 and set(t1) == {"red", "blue", "admin", "evaluator"})
check("NOT the static env tokens", SENTINEL not in r.text)
check("Cache-Control: no-store", r.headers.get("cache-control") == "no-store")
check("scopes identical to scripts/setup_env.py (drift guard)", {k: dec(v)["scope"] for k, v in t1.items()} == setup_env.SCOPES, {k: dec(v)["scope"] for k, v in t1.items()})
check("sub matches role", all(dec(v)["sub"] == k for k, v in t1.items()))
c = dec(t1["admin"]); check("short-lived: exp - iat == 900s default", c["exp"] - c["iat"] == 900, c)
t2 = host.get("/ui/demo-tokens").json()
check("every request mints different tokens (even in the same second)", all(t1[k] != t2[k] for k in t1))
os.environ["DEMO_TOKEN_TTL"] = "1"; check("TTL clamped to >= 5s", dec(host.get("/ui/demo-tokens").json()["red"])["exp"] - dec(host.get("/ui/demo-tokens").json()["red"])["iat"] == 5)
os.environ["DEMO_TOKEN_TTL"] = "junk"; check("junk TTL falls back to 900", dec(host.get("/ui/demo-tokens").json()["red"])["exp"] - int(time.time()) > 800)
os.environ["DEMO_TOKEN_TTL"] = "99999"; check("TTL clamped to <= 3600s", dec(host.get("/ui/demo-tokens").json()["red"])["exp"] - int(time.time()) <= 3601)
os.environ.pop("DEMO_TOKEN_TTL")

print("== real auth still applies to minted tokens")
T = host.get("/ui/demo-tokens").json(); A = lambda k: bearer(T[k])
check("admin token -> /audit/verify 200", host.get("/audit/verify", headers=A("admin")).status_code == 200)
rs = host.post("/red/tests", headers=A("red"), json={"prompt": "hi"}).status_code
check("red token passes authorization on /red/tests (502 here = no LLM in this unit test; full submit is covered on the real stack)", rs not in (401, 403), rs)
check("blue lists tests", host.get("/blue/tests", headers=A("blue")).status_code == 200)
check("red -> blue route = 403 (not over-permissive)", host.get("/blue/tests", headers=A("red")).status_code == 403)
check("blue -> submit = 403", host.post("/red/tests", headers=A("blue"), json={"prompt": "x"}).status_code == 403)
check("admin -> submit = 403; red -> audit = 403", host.post("/red/tests", headers=A("admin"), json={"prompt": "x"}).status_code == 403 and host.get("/audit/verify", headers=A("red")).status_code == 403)
forged = jwt.encode({**dec(T["admin"])}, "not-the-secret", algorithm="HS256")
check("a token signed with another secret is still rejected (401)", host.get("/audit/verify", headers=bearer(forged)).status_code == 401)

print("== expiry and refresh (real 5s TTL)")
os.environ["DEMO_TOKEN_TTL"] = "5"; short = host.get("/ui/demo-tokens").json()
check("fresh short token works", host.get("/audit/verify", headers=bearer(short["admin"])).status_code == 200)
time.sleep(6.5)
r = host.get("/audit/verify", headers=bearer(short["admin"]))
check("after TTL the old token is rejected: 401 token expired", r.status_code == 401 and "expired" in r.text, r.text)
fresh = host.get("/ui/demo-tokens").json()
check("re-fetched token differs and works", fresh["admin"] != short["admin"] and host.get("/audit/verify", headers=bearer(fresh["admin"])).status_code == 200)
print(f"\nResult: {PASS} passed, {FAIL} failed"); sys.exit(1 if FAIL else 0)
