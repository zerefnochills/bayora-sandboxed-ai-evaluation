#!/usr/bin/env python3
"""No-Docker tests for user accounts: login, roles, token invalidation, run ownership, admin routes.
    python3 tests/accounts_test.py        # needs: pip install fastapi httpx pyjwt
"""
import asyncio, importlib, importlib.util, json, os, sqlite3, sys, tempfile, time, warnings
warnings.filterwarnings("ignore")

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp()
os.environ.update(JWT_SECRET="test-secret", AUDIT_PATH=TMP + "/audit.jsonl", MODELS_CONFIG="/nonexistent")
os.environ.pop("DB_PATH", None); os.environ.pop("ALLOW_SIGNUP", None)
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx, jwt  # noqa: E402

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

llm = load(os.path.join(ROOT, "containers/llm/main.py"), "llm_app")
verifier = load(os.path.join(ROOT, "scripts/verify_evidence.py"), "verify_evidence")
gw = importlib.import_module("main")
users = importlib.import_module("users")
la = importlib.import_module("llm_adapters")
_real = httpx.AsyncClient
class Routed(_real):
    def __init__(self, *a, **k):
        k["transport"] = httpx.ASGITransport(app=llm.app); super().__init__(*a, **k)
httpx.AsyncClient = Routed

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)[:300]))

PW = {"admin": "Admin-pass-2026!", "alice": "violet rain tomorrow 1", "bob": "granite window 22", "carol": "copper lantern 333"}
def tok(sub, scope): return {"Authorization": "Bearer " + jwt.encode({"sub": sub, "scope": scope, "exp": int(time.time()) + 600}, "test-secret", "HS256")}
H = lambda t: {"Authorization": "Bearer " + t}
EVT, RED, BLUE, AUD = (tok(r, gw.DEMO_SCOPES[r]) for r in ("evaluator", "red", "blue", "admin"))
def client(): return _real(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw")
async def login(c, u, p): return await c.post("/auth/login", json={"username": u, "password": p})
def claims(t): return jwt.decode(t, "test-secret", algorithms=["HS256"])
def events(ev): return [e for e in gw.audit.tail(20000) if e["event"] == ev]

def unit():
    print("== policy, hashing, throttling (unit)")
    ok = lambda f, *a: (f(*a), True)[1]
    def bad(f, *a):
        try: f(*a); return False
        except users.PolicyError: return True
    check("valid usernames accepted", all(ok(users.check_username, n) for n in ("abc", "a.b-c_d", "user123", "x" * 32)))
    check("invalid usernames rejected: uppercase, short, long, symbols, leading dash, spaces, unicode, non-string",
          all(bad(users.check_username, n) for n in ("Alice", "ab", "x" * 33, "a@b", "-abc", "a b c", "álice", "", None, 5)))
    check("reserved names rejected (red, blue, admin, evaluator, gateway, root, eval-red...)", all(bad(users.check_username, n) for n in ("red", "blue", "admin", "evaluator", "gateway", "root", "eval-red", "eval-x")))
    check("password policy: 10-128 chars, not repetitive, must not contain the username", ok(users.check_password, "long enough pw", "bob") and all(bad(users.check_password, p, "bob") for p in ("short", "x" * 129, "aaaaaaaaaaaa", "my-bob-password", None, 12345678901)))
    h = users.hash_password("correct horse battery")
    check("hash format is scrypt$n$r$p$salt$hash and never contains the password", h.startswith("scrypt$16384$8$1$") and "correct" not in h)
    check("verify: right password True, wrong False", users.verify_password("correct horse battery", h) and not users.verify_password("correct horse batterz", h))
    check("two hashes of the same password differ (random salt)", users.hash_password("correct horse battery") != h)
    check("malformed or tampered stored hashes verify False and never raise", not any(users.verify_password("x", s) for s in ("", "garbage", "scrypt$1$2", "md5$1$1$1$AA==$AA==", h[:-4] + "AAAA", h.replace("scrypt$16384", "scrypt$abc"))))
    check("the dummy hash used for unknown users is a real scrypt hash that rejects everything", users.DUMMY_HASH.startswith("scrypt$") and not users.verify_password("anything", users.DUMMY_HASH))
    check("bootstrap code: 20 hex chars, deterministic, depends on the secret", users.bootstrap_code("a") == users.bootstrap_code("a") and users.bootstrap_code("a") != users.bootstrap_code("b") and len(users.bootstrap_code("a")) == 20)
    check("a user cannot hold admin scopes; an admin has user scopes plus management scopes", set(users.ROLE_SCOPES["user"]) == {"eval:run", "eval:read"} and {"eval:admin", "user:admin", "audit:read"} <= set(users.ROLE_SCOPES["admin"]) and set(users.ROLE_SCOPES["user"]) <= set(users.ROLE_SCOPES["admin"]))
    t = [0.0]; g = users.LoginGuard(3, 100, clock=lambda: t[0])
    g.fail("k"); g.fail("k"); allowed = g.check("k") == 0; g.fail("k")
    check("guard: allows 2 failures, locks at 3 with a positive wait, other keys unaffected", allowed and g.check("k") > 0 and g.check("other") == 0)
    t[0] = 101
    check("guard: the window expires and the key unlocks", g.check("k") == 0)
    g.fail("k"); g.fail("k"); g.clear("k")
    check("guard: clear() forgets failures", g.check("k") == 0 and "k" not in g._f)
    g = users.LoginGuard(3, 100, max_keys=5, clock=lambda: t[0])
    for i in range(50): g.fail("key%d" % i)
    check("guard: memory is bounded (max_keys)", len(g._f) <= 5)

async def main():
    global gw
    unit()
    async with client() as c:
        print("== first-run bootstrap")
        check("status: bootstrap needed, signup closed", (await c.get("/auth/status")).json() == {"bootstrap_needed": True, "signup_open": False})
        check("before setup, an account-gated route is simply 401 (no token)", (await c.get("/auth/me")).status_code == 401)
        r = await c.post("/auth/bootstrap", json={"code": "wrong", "username": "admin1", "password": PW["admin"]})
        check("wrong setup code -> 403, audited, no account created", r.status_code == 403 and events("bootstrap_failed") and (await c.get("/auth/status")).json()["bootstrap_needed"] is True)
        gw.GUARD_IP = users.LoginGuard(3, 900)
        codes = [(await c.post("/auth/bootstrap", json={"code": "wrong%d" % i, "username": "admin1", "password": PW["admin"]})).status_code for i in range(5)]
        check("repeated wrong codes are throttled (403, 403, 403, then 429)", codes == [403, 403, 403, 429, 429], codes)
        gw.GUARD_IP = users.LoginGuard(30, 900)
        good = users.bootstrap_code("test-secret")
        for body, why in (({"username": "Admin1", "password": "x"}, "short password"), ({"username": "a", "password": PW["admin"]}, "short username"), ({"username": "root", "password": PW["admin"]}, "reserved username"), ({"username": "admin1", "password": "has-admin1-in-it"}, "password contains the username")):
            r = await c.post("/auth/bootstrap", json={"code": good, **body})
            check(f"bootstrap policy: {why} -> 422 with a reason", r.status_code == 422 and r.json()["detail"], r.text)
        r = await c.post("/auth/bootstrap", json={"code": good, "username": "Admin1", "password": PW["admin"]})
        j = r.json(); tA = j["token"]; c1 = claims(tA)
        check("bootstrap with the right code creates the first admin and logs them in (username lower-cased)", r.status_code == 200 and j["user"] == {"username": "admin1", "role": "admin"} and j["expires_in"] == 3600)
        check("token: sub user:admin1, role admin, admin scopes, ver 1, jti, exp about 1h", c1["sub"] == "user:admin1" and c1["role"] == "admin" and set(c1["scope"]) == set(users.ROLE_SCOPES["admin"]) and c1["ver"] == 1 and c1["jti"] and 3500 < c1["exp"] - time.time() <= 3600)
        r = await c.post("/auth/bootstrap", json={"code": good, "username": "other1", "password": PW["admin"]})
        check("bootstrap is closed once an account exists (409), even with the right code", r.status_code == 409 and (await c.get("/auth/status")).json()["bootstrap_needed"] is False)
        check("bootstrap creation is audited without any password", any(e["data"].get("username") == "admin1" for e in events("user_created")) and PW["admin"] not in open(os.environ["AUDIT_PATH"]).read())

        print("== admin creates accounts")
        mk = lambda u, role="user", t=tA: c.post("/admin/users", headers=H(t), json={"username": u, "password": PW[u], "role": role})
        r = await mk("alice")
        check("admin creates alice -> 201 with public fields only", r.status_code == 201 and set(r.json()) == {"username", "role", "active", "created", "created_by", "last_login"} and r.json()["created_by"] == "user:admin1")
        await mk("bob"); await mk("carol", "admin")
        check("duplicate username -> 409", (await mk("alice")).status_code == 409)
        check("policy violations -> 422", (await c.post("/admin/users", headers=H(tA), json={"username": "dave", "password": "short"})).status_code == 422 and (await c.post("/admin/users", headers=H(tA), json={"username": "x", "password": "long enough pw"})).status_code == 422)
        check("role must be user or admin (422 otherwise)", (await c.post("/admin/users", headers=H(tA), json={"username": "dave1", "password": "long enough pw", "role": "root"})).status_code == 422)
        L = (await c.get("/admin/users", headers=H(tA))).json()
        check("list: 4 accounts, never any password or hash field", [u["username"] for u in L] == ["admin1", "alice", "bob", "carol"] and "password" not in json.dumps(L) and "scrypt" not in json.dumps(L))

        print("== login")
        r = await login(c, "alice", PW["alice"]); tAl = r.json()["token"]
        check("alice logs in: role user, user scopes only, ver 1", r.status_code == 200 and claims(tAl)["scope"] == ["eval:run", "eval:read"] and claims(tAl)["role"] == "user" and claims(tAl)["ver"] == 1)
        check("login is audited as user_login by user:alice; last_login recorded", any(e["actor"] == "user:alice" for e in events("user_login")) and gw.store.get_user("alice")["last_login"])
        check("username is case-insensitive and trimmed", (await login(c, "  ALICE ", PW["alice"])).status_code == 200)
        wrong = await login(c, "alice", "nope nope nope"); unk = await login(c, "nobody1", "nope nope nope")
        await c.patch("/admin/users/bob", headers=H(tA), json={"active": False}); dis = await login(c, "bob", PW["bob"])
        await c.patch("/admin/users/bob", headers=H(tA), json={"active": True})
        check("wrong password, unknown user and DISABLED user are indistinguishable to the caller (same 401 and body)", wrong.status_code == unk.status_code == dis.status_code == 401 and wrong.json() == unk.json() == dis.json() == {"detail": "invalid username or password"})
        check("failures are audited as login_failed by 'anonymous' with a reason, never the password", {e["data"]["reason"] for e in events("login_failed")} >= {"bad credentials", "disabled"} and all(e["actor"] == "anonymous" for e in events("login_failed")) and "nope nope" not in open(os.environ["AUDIT_PATH"]).read())
        check("input validation: empty / oversize fields -> 422; missing body -> 422", all([(await c.post("/auth/login", json=b)).status_code == 422 for b in ({"username": "", "password": "x"}, {"username": "a", "password": ""}, {"username": "a", "password": "x" * 257}, {"username": "x" * 65, "password": "x"}, {})]))
        calls = []; orig = users.verify_password
        users.verify_password = lambda pw, st: (calls.append(st), orig(pw, st))[1]
        await login(c, "nobody2", "whatever whatever"); users.verify_password = orig
        check("an unknown username still costs one scrypt verification (timing does not reveal existence)", calls == [users.DUMMY_HASH], calls)

        print("== lockout (applies to real and unknown usernames alike)")
        gw.GUARD_USER, gw.GUARD_IP = users.LoginGuard(5, 900), users.LoginGuard(1000, 900)
        rs = [await login(c, "carol", "bad bad bad bad") for _ in range(6)]
        check("5 failures then 429 with Retry-After for a real account", [r.status_code for r in rs] == [401] * 5 + [429] and int(rs[5].headers["retry-after"]) > 0)
        r = await login(c, "carol", PW["carol"])
        check("while locked even the CORRECT password is refused (429)", r.status_code == 429)
        rs = [await login(c, "ghost.user", "bad bad bad bad") for _ in range(6)]
        check("an unknown username locks out identically (no way to tell which accounts exist)", [r.status_code for r in rs] == [401] * 5 + [429] and rs[5].json() == (await login(c, "carol", "x")).json())
        check("other accounts are not affected by that lockout", (await login(c, "alice", PW["alice"])).status_code == 200)
        gw.GUARD_USER = users.LoginGuard(5, 900)
        for _ in range(4): await login(c, "alice", "bad bad bad bad")
        await login(c, "alice", PW["alice"])
        rs = [await login(c, "alice", "bad bad bad bad") for _ in range(4)]
        check("a successful login resets the failure counter (4 + success + 4 never locks)", [r.status_code for r in rs] == [401] * 4)
        gw.GUARD_IP, gw.GUARD_USER = users.LoginGuard(3, 900), users.LoginGuard(1000, 900)
        rs = [await login(c, "name%d" % i, "bad bad bad bad") for i in range(5)]
        check("many different usernames from one address are throttled by the address guard", [r.status_code for r in rs] == [401, 401, 401, 429, 429])
        gw.GUARD_IP, gw.GUARD_USER = users.LoginGuard(30, 900), users.LoginGuard(5, 900)

        print("== account token and role separation")
        me = (await c.get("/auth/me", headers=H(tAl))).json()
        check("/auth/me returns the account, role and scopes", me["username"] == "alice" and me["role"] == "user" and me["scope"] == ["eval:read", "eval:run"] and "password" not in json.dumps(me))
        check("a tenant token is not an account: /auth/me -> 403", (await c.get("/auth/me", headers=EVT)).status_code == 403)
        forbidden = [("POST", "/red/tests", {"prompt": "x"}), ("GET", "/blue/tests", None), ("GET", "/audit/verify", None), ("GET", "/admin/users", None), ("GET", "/admin/overview", None),
                     ("POST", "/admin/users", {"username": "zed1", "password": "long enough pw"}), ("PATCH", "/admin/users/bob", {"active": False}), ("POST", "/admin/users/bob/reset-password", {"new_password": "long enough pw"})]
        rs = [(await c.request(m, p, headers=H(tAl), json=b)).status_code for m, p, b in forbidden]
        check("a normal user is refused (403) on Red, Blue, audit and every admin route", rs == [403] * len(forbidden), rs)
        check("those attempts are audited as policy violations by user:alice", any(e["actor"] == "user:alice" for e in events("policy_violation")))
        check("the existing tenant tokens cannot use the admin routes either (the 'admin' tenant is an auditor)", [(await c.get("/admin/users", headers=h)).status_code for h in (RED, BLUE, AUD, EVT)] == [403] * 4)
        check("an admin account can read the audit log but has no Red/Blue scopes", (await c.get("/audit/verify", headers=H(tA))).status_code == 200 and (await c.post("/red/tests", headers=H(tA), json={"prompt": "x"})).status_code == 403)

        print("== token invalidation")
        r = await c.patch("/admin/users/alice", headers=H(tA), json={"active": False})
        check("disabling alice: her EXISTING token stops working at once (401)", r.status_code == 200 and (await c.get("/auth/me", headers=H(tAl))).status_code == 401)
        await c.patch("/admin/users/alice", headers=H(tA), json={"active": True})
        check("re-enabling does NOT revive the old token (token_version moved on)", (await c.get("/auth/me", headers=H(tAl))).status_code == 401 and gw.store.get_user("alice")["token_version"] == 3)
        tAl = (await login(c, "alice", PW["alice"])).json()["token"]
        r = await c.post("/auth/change-password", headers=H(tAl), json={"old_password": "wrong wrong wrong", "new_password": "a brand new password"})
        check("change password with a wrong current password -> 401, audited, nothing changed", r.status_code == 401 and events("password_change_failed") and (await login(c, "alice", PW["alice"])).status_code == 200)
        check("change password policy enforced (422), including 'contains username'", (await c.post("/auth/change-password", headers=H(tAl), json={"old_password": PW["alice"], "new_password": "alice-is-in-here"})).status_code == 422)
        r = await c.post("/auth/change-password", headers=H(tAl), json={"old_password": PW["alice"], "new_password": "a brand new password"}); tNew = r.json()["token"]
        check("change password: returns a NEW session token; the old token and the old password are dead", r.status_code == 200 and (await c.get("/auth/me", headers=H(tAl))).status_code == 401 and (await c.get("/auth/me", headers=H(tNew))).status_code == 200 and (await login(c, "alice", PW["alice"])).status_code == 401 and (await login(c, "alice", "a brand new password")).status_code == 200)
        check("password changes are audited without passwords", events("password_changed") and "a brand new password" not in open(os.environ["AUDIT_PATH"]).read())
        PW["alice"] = "a brand new password"; tAl = tNew
        check("tenant tokens cannot use change-password", (await c.post("/auth/change-password", headers=EVT, json={"old_password": "x" * 10, "new_password": "y" * 12})).status_code == 403)
        r = await c.post("/admin/users/bob/reset-password", headers=H(tA), json={"new_password": "granite reset 4444"}); tBob = (await login(c, "bob", PW["bob"])).status_code
        check("admin password reset works: old password rejected, new accepted, audited", r.status_code == 200 and tBob == 401 and (await login(c, "bob", "granite reset 4444")).status_code == 200 and events("password_reset"))
        PW["bob"] = "granite reset 4444"
        tCar = (await login(c, "carol", PW["carol"])).json()["token"]
        await c.patch("/admin/users/carol", headers=H(tA), json={"role": "user"})
        check("demoting an admin kills their old (admin) token immediately; a fresh login has user scopes only", (await c.get("/admin/users", headers=H(tCar))).status_code == 401 and claims((await login(c, "carol", PW["carol"])).json()["token"])["scope"] == ["eval:run", "eval:read"])
        await c.patch("/admin/users/carol", headers=H(tA), json={"role": "admin"})
        check("a forged account token (valid signature, claims that do not match the account) is refused", (await c.get("/auth/me", headers={"Authorization": "Bearer " + jwt.encode({"sub": "user:alice", "scope": users.ROLE_SCOPES["admin"], "role": "admin", "ver": 99, "exp": int(time.time()) + 600}, "test-secret", "HS256")})).status_code == 401)
        check("a token for an account that does not exist is refused", (await c.get("/auth/me", headers={"Authorization": "Bearer " + jwt.encode({"sub": "user:ghost", "scope": ["eval:read"], "role": "user", "ver": 1, "exp": int(time.time()) + 600}, "test-secret", "HS256")})).status_code == 401)
        check("a user token that claims admin scopes beyond its role is refused", (await c.get("/auth/me", headers={"Authorization": "Bearer " + jwt.encode({"sub": "user:alice", "scope": users.ROLE_SCOPES["admin"], "role": "user", "ver": gw.store.get_user("alice")["token_version"], "exp": int(time.time()) + 600}, "test-secret", "HS256")})).status_code == 401)

        print("== admin rules")
        check("unknown or malformed username -> 404 on patch and reset", all([(await c.request(m, p, headers=H(tA), json=b)).status_code == 404 for m, p, b in (("PATCH", "/admin/users/nobody1", {"active": False}), ("PATCH", "/admin/users/..%2fx", {"active": False}), ("POST", "/admin/users/Bad%20Name/reset-password", {"new_password": "long enough pw"}))]))
        check("invalid patch bodies -> 422", all([(await c.patch("/admin/users/alice", headers=H(tA), json=b)).status_code == 422 for b in ({"role": "root"}, {"active": "maybe"})]))
        await c.patch("/admin/users/carol", headers=H(tA), json={"active": False})
        r1 = await c.patch("/admin/users/admin1", headers=H(tA), json={"role": "user"}); r2 = await c.patch("/admin/users/admin1", headers=H(tA), json={"active": False})
        check("the LAST active admin cannot be demoted or disabled (409), even by themselves", r1.status_code == r2.status_code == 409 and gw.store.count_active_admins() == 1)
        await c.patch("/admin/users/carol", headers=H(tA), json={"active": True})
        check("with a second active admin, demotion is allowed", (await c.patch("/admin/users/carol", headers=H(tA), json={"role": "user"})).status_code == 200)
        await c.patch("/admin/users/carol", headers=H(tA), json={"role": "admin"})
        check("user changes are audited with who did what", any(e["actor"] == "user:admin1" and e["data"].get("username") == "carol" for e in events("user_updated")))
        ov = (await c.get("/admin/overview", headers=H(tA))).json()
        check("overview: user counts, run counts, audit chain ok, anchor status, models", ov["users"] == {"total": 4, "active": 4, "admins": 2} and ov["audit"]["ok"] is True and "status" in ov["audit"]["anchor"] and ov["models"][0]["id"] == "mock" and "by_status" in ov["runs"])

        print("== run ownership")
        tBo = (await login(c, "bob", PW["bob"])).json()["token"]; tAl = (await login(c, "alice", PW["alice"])).json()["token"]
        r = await c.post("/evaluations", headers=H(tAl), json={"suite_id": "builtin-core"}); rid = r.json()["run_id"]; await gw.runner.wait()
        run = (await c.get(f"/evaluations/{rid}", headers=H(tAl))).json()
        check("alice's run is recorded as created by user:alice and completes normally", r.status_code == 202 and run["created_by"] == "user:alice" and run["status"] == "completed" and run["summary"]["total"] == 25)
        st = [e for e in events("evaluation_started") if e["data"]["run_id"] == rid][0]
        check("audit: evaluation_started by user:alice; the attack traffic itself is still the eval-red actor", st["actor"] == "user:alice" and any(e["actor"] == "eval-red" for e in gw.audit.tail(300) if e["event"] == "test_submitted"))
        paths = [f"/evaluations/{rid}", f"/evaluations/{rid}/results", f"/evaluations/{rid}/evidence", f"/evaluations/{rid}/report"]
        check("alice can read her run, results, evidence and report", [(await c.get(p, headers=H(tAl))).status_code for p in paths] == [200] * 4)
        check("bob gets 404 (not 403) for all four: another user's run id cannot even be confirmed", [(await c.get(p, headers=H(tBo))).status_code for p in paths] == [404] * 4)
        check("bob's list is empty; alice's has her run; the old evaluator service token sees none of hers", (await c.get("/evaluations", headers=H(tBo))).json() == [] and [x["run_id"] for x in (await c.get("/evaluations", headers=H(tAl))).json()] == [rid] and (await c.get("/evaluations", headers=EVT)).json() == [])
        check("an admin sees every run, with its owner", [x["created_by"] for x in (await c.get("/evaluations", headers=H(tA))).json()] == ["user:alice"] and (await c.get(paths[2], headers=H(tA))).status_code == 200)
        check("the evaluator service token is also locked out of alice's run by id (404)", [(await c.get(p, headers=EVT)).status_code for p in paths] == [404] * 4)
        B = (await c.get(paths[2], headers=H(tAl))).json(); P = (await c.get(paths[3], headers=H(tAl))).text
        check("alice's evidence verifies offline and her report names her as the starter", all(x["result"] != "FAIL" for x in verifier.verify(B)) and "user:alice" in P)
        check("no account password or hash appears in any evidence or report output", "scrypt$" not in json.dumps(B) + P and not any(v in json.dumps(B) + P for v in PW.values()))

        orig_call = la.MockAdapter._call
        async def slow(self, prompt, key, session):
            await asyncio.sleep(0.05); return await orig_call(self, prompt, key, session)
        la.MockAdapter._call = slow
        try:
            rB = await c.post("/evaluations", headers=H(tBo), json={"suite_id": "builtin-core"})
            for _ in range(200):
                if (await c.get(f"/evaluations/{rB.json()['run_id']}", headers=H(tBo))).json()["done"] > 0: break
                await asyncio.sleep(0.02)
            ra = await c.post("/evaluations", headers=H(tAl), json={"suite_id": "builtin-core"}); rb = await c.post("/evaluations", headers=H(tBo), json={"suite_id": "builtin-core"}); rad = await c.post("/evaluations", headers=H(tA), json={"suite_id": "builtin-core"})
            await gw.runner.wait()
        finally:
            la.MockAdapter._call = orig_call
        bid = rB.json()["run_id"]
        check("one evaluation at a time: a second start is 409 for everyone", ra.status_code == rb.status_code == rad.status_code == 409)
        check("the 409 names the active run only to its owner and to admins; alice is told nothing about bob's run", bid in rb.text and bid in rad.text and bid not in ra.text and "try again shortly" in ra.text, (ra.text, rb.text))

        print("== signup")
        check("signup is closed by default: /auth/register -> 404", (await c.post("/auth/register", json={"username": "newbie", "password": "sunrise harbor 55"})).status_code == 404)
        gw.SIGNUP_OPEN = True; gw.GUARD_SIGNUP = users.LoginGuard(3, 3600)
        check("status advertises signup only when it is open", (await c.get("/auth/status")).json()["signup_open"] is True)
        r = await c.post("/auth/register", json={"username": "newbie", "password": "sunrise harbor 55"})
        check("signup creates a plain user (never an admin) and logs them in", r.status_code == 201 and r.json()["user"] == {"username": "newbie", "role": "user"} and claims(r.json()["token"])["scope"] == ["eval:run", "eval:read"])
        check("signup: taken -> 409, weak -> 422", (await c.post("/auth/register", json={"username": "newbie", "password": "sunrise harbor 55"})).status_code == 409 and (await c.post("/auth/register", json={"username": "newb2", "password": "short"})).status_code == 422)
        check("signup is throttled per address (429)", (await c.post("/auth/register", json={"username": "newb3", "password": "sunrise harbor 55"})).status_code == 429)
        gw.SIGNUP_OPEN = False

        print("== secrets and storage")
        db = open(gw.store.path, "rb").read().decode("latin-1"); au = open(os.environ["AUDIT_PATH"]).read()
        allpw = list(PW.values()) + ["sunrise harbor 55", "a brand new password", "granite reset 4444"]
        check("no plaintext password anywhere: SQLite file or audit log", not any(p in db or p in au for p in allpw))
        check("stored credentials are scrypt hashes only", all(r[0].startswith("scrypt$") for r in sqlite3.connect(gw.store.path).execute("SELECT password_hash FROM users")))
        con = sqlite3.connect(gw.store.path)
        try: con.execute("INSERT INTO users (username, password_hash, role, created) VALUES ('zz', 'h', 'root', 1)"); bad_role = False
        except sqlite3.IntegrityError: bad_role = True
        try: con.execute("INSERT INTO users (username, password_hash, role, created) VALUES ('alice', 'h', 'user', 1)"); dup = False
        except sqlite3.IntegrityError: dup = True
        check("database refuses an unknown role and a duplicate username", bad_role and dup)
        con.close()

        print("== restart")
        before = (await c.get("/admin/users", headers=H(tA))).json()
        gw = importlib.reload(gw)
    async with client() as c:
        check("after a gateway restart: accounts persist and an existing session token still works", (await c.get("/admin/users", headers=H(tA))).json() == before and (await c.get("/auth/me", headers=H(tAl))).status_code == 200)
        check("login works after the restart; the old password does not", (await login(c, "alice", PW["alice"])).status_code == 200 and (await login(c, "alice", "violet rain tomorrow 1")).status_code == 401)
        check("bootstrap stays closed after the restart", (await c.post("/auth/bootstrap", json={"code": users.bootstrap_code("test-secret"), "username": "again1", "password": "long enough pw"})).status_code == 409)
        check("alice's run is still hers after the restart (bob 404, alice 200)", (await c.get(f"/evaluations/{rid}", headers=H(tBo))).status_code == 404 and (await c.get(f"/evaluations/{rid}", headers=H(tAl))).status_code == 200)

    print(f"\nResult: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)

asyncio.run(main())
