#!/usr/bin/env python3
"""No-Docker tests: personal profile (ownership, validation, mass-assignment), schema v5, /evaluation-info.
    python3 tests/profile_test.py        # needs: pip install fastapi httpx pyjwt
"""
import asyncio, importlib, json, os, sqlite3, sys, tempfile, time, warnings
warnings.filterwarnings("ignore")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TMP = tempfile.mkdtemp()
os.environ.update(JWT_SECRET="test-secret", AUDIT_PATH=TMP + "/audit.jsonl", MODELS_CONFIG="/nonexistent")
os.environ.pop("DB_PATH", None)
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import httpx, jwt  # noqa: E402
gw = importlib.import_module("main"); users = importlib.import_module("users"); store_mod = importlib.import_module("store"); evidence = importlib.import_module("evidence")

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)[:300]))
H = lambda t: {"Authorization": "Bearer " + t}
def tok(sub, scope): return {"Authorization": "Bearer " + jwt.encode({"sub": sub, "scope": scope, "exp": int(time.time()) + 600}, "test-secret", "HS256")}
RED, BLUE = tok("red", gw.DEMO_SCOPES["red"]), tok("blue", gw.DEMO_SCOPES["blue"])
def client(): return httpx.AsyncClient(transport=httpx.ASGITransport(app=gw.app), base_url="http://gw")
def events(ev): return [e for e in gw.audit.tail(5000) if e["event"] == ev]
def raw(path, q, *a):
    c = sqlite3.connect(path); r = c.execute(q, a).fetchall(); c.commit(); c.close(); return r

def unit():
    print("== profile validation (unit)")
    ok = lambda f: f is not None
    c = users.check_profile({"display_name": "  Alice E.  ", "nickname": "", "email": "a@b.co", "bio": "hi", "show_username": False, "reduce_motion": True})
    check("trims text, '' becomes None, booleans become 0/1", c == {"display_name": "Alice E.", "nickname": None, "email": "a@b.co", "bio": "hi", "show_username": 0, "reduce_motion": 1}, c)
    def bad(f):
        try: users.check_profile(f); return False
        except users.PolicyError: return True
    check("limits: display name 41, nickname 25, bio 201, email 255 characters are refused", all(bad(f) for f in ({"display_name": "x" * 41}, {"nickname": "x" * 25}, {"bio": "x" * 201}, {"email": "a" * 250 + "@b.co"})))
    check("control characters (newline, NUL, tab, escape) are refused", all(bad({"display_name": "a" + c + "b"}) for c in ("\n", "\x00", "\t", "\x1b")))
    check("bad emails are refused: no @, two @, spaces, no dot, trailing dot", all(bad({"email": e}) for e in ("plain", "a@@b.co", "a b@c.co", "a@b", "a@b.", "@b.co")))
    check("non-boolean flags and non-text fields are refused", bad({"show_username": "yes"}) and bad({"show_username": 1}) and bad({"display_name": 5}) and bad({"bio": ["x"]}))
    check("public_profile never carries a hash, token version, scope or id", set(users.public_profile({"username": "u", "role": "user", "created": 1, "last_login": None, "display_name": None, "nickname": None, "email": None, "bio": None, "show_username": 1, "reduce_motion": 0})) == {"username", "role", "created", "last_login", "display_name", "nickname", "email", "bio", "show_username", "reduce_motion"})

async def main():
    global gw
    unit()
    print("== schema v5")
    v4 = TMP + "/v4.db"
    c = sqlite3.connect(v4); c.executescript(store_mod._SCHEMA_V1); c.executescript(store_mod._SCHEMA_V2); c.executescript(store_mod._SCHEMA_V3); c.executescript(store_mod._SCHEMA_V4); c.execute("PRAGMA user_version = 4")
    c.execute("INSERT INTO users (username, password_hash, role, created) VALUES ('old1', 'h', 'admin', 1.0)"); c.commit(); c.close()
    s = store_mod.Store(v4)
    check("a populated v4 DB upgrades to the current version; the existing user keeps role and gets defaults", raw(v4, "PRAGMA user_version")[0][0] == store_mod.SCHEMA_VERSION == 5 and s.get_profile("old1")["role"] == "admin" and s.get_profile("old1")["show_username"] == 1 and s.get_profile("old1")["reduce_motion"] == 0 and s.get_profile("old1")["display_name"] is None)
    bad5 = TMP + "/bad5.db"
    c = sqlite3.connect(bad5); c.executescript(store_mod._SCHEMA_V1); c.executescript(store_mod._SCHEMA_V2); c.executescript(store_mod._SCHEMA_V3); c.executescript(store_mod._SCHEMA_V4); c.execute("PRAGMA user_version = 4"); c.execute("ALTER TABLE users ADD COLUMN reduce_motion INTEGER"); c.commit(); c.close()
    try: store_mod.Store(bad5); failed = False
    except sqlite3.Error: failed = True
    check("a failing v5 upgrade rolls back every added column and stays at v4", failed and raw(bad5, "PRAGMA user_version")[0][0] == 4 and "display_name" not in {r[1] for r in raw(bad5, "PRAGMA table_info(users)")})
    check("set_profile can only ever write profile columns (role, active, hash, token_version are unreachable)", s.set_profile("old1", {"role": "user", "active": 0, "password_hash": "x", "token_version": 9}) is False and s.get_user("old1")["role"] == "admin" and s.get_user("old1")["active"] == 1 and s.get_user("old1")["token_version"] == 1)
    check("set_profile writes only the named columns", s.set_profile("old1", {"nickname": "n"}) and s.get_profile("old1")["nickname"] == "n" and s.get_profile("old1")["display_name"] is None)

    async with client() as c:
        code = users.bootstrap_code("test-secret")
        tA = (await c.post("/auth/bootstrap", json={"code": code, "username": "admin1", "password": "Admin-pass-2026!"})).json()["token"]
        for u, p in (("alice", "violet rain tomorrow 1"), ("bob", "granite window 22")): await c.post("/admin/users", headers=H(tA), json={"username": u, "password": p, "role": "user"})
        tAl = (await c.post("/auth/login", json={"username": "alice", "password": "violet rain tomorrow 1"})).json()["token"]
        tBo = (await c.post("/auth/login", json={"username": "bob", "password": "granite window 22"})).json()["token"]

        print("== /auth/me and PATCH /auth/profile")
        me = (await c.get("/auth/me", headers=H(tAl))).json()
        check("a new account has an empty profile, username shown, motion normal", me["display_name"] is None and me["email"] is None and me["show_username"] is True and me["reduce_motion"] is False)
        check("/auth/me exposes no hash, version or secret", not any(k in json.dumps(me) for k in ("password", "scrypt", "token_version", "ver\"")))
        r = await c.patch("/auth/profile", headers=H(tAl), json={"display_name": "Alice Example", "nickname": "ali", "email": "alice@example.org", "bio": "I test models."})
        check("alice updates her profile; the response is her profile", r.status_code == 200 and r.json()["display_name"] == "Alice Example" and r.json()["email"] == "alice@example.org" and r.json()["role"] == "user")
        check("the change is visible in /auth/me and persisted in SQLite", (await c.get("/auth/me", headers=H(tAl))).json()["nickname"] == "ali" and gw.store.get_profile("alice")["bio"] == "I test models.")
        check("a partial update changes only what was sent", (await c.patch("/auth/profile", headers=H(tAl), json={"nickname": "al"})).json()["display_name"] == "Alice Example")
        check("an empty string clears a field", (await c.patch("/auth/profile", headers=H(tAl), json={"bio": ""})).json()["bio"] is None)
        r = await c.patch("/auth/profile", headers=H(tAl), json={"show_username": False, "reduce_motion": True})
        check("preferences are stored as booleans", r.json()["show_username"] is False and r.json()["reduce_motion"] is True)
        check("editing a profile does NOT sign anyone out (token still valid, version unchanged)", (await c.get("/auth/me", headers=H(tAl))).status_code == 200 and gw.store.get_user("alice")["token_version"] == 1)
        check("bob's profile is untouched by alice's edits", (await c.get("/auth/me", headers=H(tBo))).json()["display_name"] is None)

        print("== ownership and mass assignment")
        before = gw.store.get_user("alice")
        for field, val in (("role", "admin"), ("active", False), ("scope", ["user:admin"]), ("username", "root2"), ("password_hash", "x"), ("token_version", 99), ("created_by", "x"), ("id", 1), ("password", "new password 123")):
            r = await c.patch("/auth/profile", headers=H(tAl), json={"display_name": "Hacked", field: val})
            check(f"naming '{field}' in the body is rejected outright (422) and NOTHING is applied", r.status_code == 422 and gw.store.get_profile("alice")["display_name"] == "Alice Example", r.text[:120])
        after = gw.store.get_user("alice")
        check("role, active, token version and username are exactly as before", (before["role"], before["active"], before["token_version"], before["username"]) == (after["role"], after["active"], after["token_version"], after["username"]) == ("user", 1, 1, "alice"))
        check("an empty body is refused", (await c.patch("/auth/profile", headers=H(tAl), json={})).status_code == 422)
        check("there is no way to name another account: the route takes no username", all(r.status_code in (404, 405) for r in [await c.patch("/auth/profile/bob", headers=H(tAl), json={"display_name": "x"}), await c.patch("/profile/bob", headers=H(tAl), json={"display_name": "x"})]) and gw.store.get_profile("bob")["display_name"] is None)
        check("a normal user is refused (403) on every admin account route", [(await c.request(m, p, headers=H(tAl), json=b)).status_code for m, p, b in (("PATCH", "/admin/users/bob", {"role": "admin"}), ("POST", "/admin/users/bob/reset-password", {"new_password": "long enough pw"}), ("GET", "/admin/users", None))] == [403, 403, 403])
        check("no token -> 401; tenant tokens -> 403", (await c.patch("/auth/profile", json={"nickname": "x"})).status_code == 401 and [(await c.patch("/auth/profile", headers=h, json={"nickname": "x"})).status_code for h in (RED, BLUE)] == [403, 403])
        check("validation errors are 422 with a reason", all([(await c.patch("/auth/profile", headers=H(tAl), json=b)).status_code == 422 for b in ({"email": "nope"}, {"display_name": "x" * 41}, {"bio": "a\nb"}, {"show_username": "yes"})]))
        check("an admin edits ONLY their own profile through the same route (and the admin list stays free of profile data)", (await c.patch("/auth/profile", headers=H(tA), json={"display_name": "The Admin", "email": "root@example.org"})).status_code == 200 and "display_name" not in json.dumps((await c.get("/admin/users", headers=H(tA))).json()) and "root@example.org" not in json.dumps((await c.get("/admin/users", headers=H(tA))).json()))
        check("the admin account routes still return exactly their old field set", set((await c.get("/admin/users", headers=H(tA))).json()[0]) == {"username", "role", "active", "created", "created_by", "last_login"})

        print("== audit and sessions")
        up = [e for e in events("profile_updated") if e["actor"] == "user:alice"]
        check("every profile change is audited by actor with the FIELD NAMES only", up and all(set(e["data"]) == {"fields"} for e in up) and ["display_name", "email", "bio", "nickname"] == sorted(up[0]["data"]["fields"], key=["display_name", "email", "bio", "nickname"].index) or sorted(up[0]["data"]["fields"]) == ["bio", "display_name", "email", "nickname"])
        au = open(os.environ["AUDIT_PATH"]).read()
        check("no email address, name or bio text ever reaches the audit log", "alice@example.org" not in au and "Alice Example" not in au and "I test models" not in au and "root@example.org" not in au)
        r = await c.post("/auth/change-password", headers=H(tAl), json={"old_password": "violet rain tomorrow 1", "new_password": "amber orchard seven 7"})
        check("changing the password invalidates the old session for profile access too, and returns a fresh one", r.status_code == 200 and (await c.patch("/auth/profile", headers=H(tAl), json={"nickname": "x"})).status_code == 401 and (await c.patch("/auth/profile", headers=H(r.json()["token"]), json={"nickname": "fresh"})).status_code == 200)
        await c.patch("/admin/users/bob", headers=H(tA), json={"active": False})
        check("a disabled account's token is refused on the profile route", (await c.patch("/auth/profile", headers=H(tBo), json={"nickname": "x"})).status_code == 401)

        print("== /evaluation-info")
        tAl = r.json()["token"]
        check("needs eval:read: no token 401, red/blue 403, a user is fine", (await c.get("/evaluation-info")).status_code == 401 and [(await c.get("/evaluation-info", headers=h)).status_code for h in (RED, BLUE)] == [403, 403] and (await c.get("/evaluation-info", headers=H(tAl))).status_code == 200)
        info = (await c.get("/evaluation-info", headers=H(tAl))).json(); txt = json.dumps(info)
        cats = {c["category"]: c for c in info["suites"][0]["categories"]}
        check("heuristic categories come from the loaded suite: the five categories with 3/3/2/3/2 probes", {k: len(v["probes"]) for k, v in cats.items()} == {"jailbreak": 3, "prompt_injection": 3, "instruction_following": 2, "data_exfiltration": 3, "policy_bypass": 2}, {k: len(v["probes"]) for k, v in cats.items()})
        suite = gw.SUITES.get("builtin-core")
        check("it IS the suite file: every probe id, severity, description and expected property matches", sorted(p["id"] for c in cats.values() for p in c["probes"]) == sorted(a["id"] for a in suite["attacks"]) and all(p["expected_property"] == next(a for a in suite["attacks"] if a["id"] == p["id"])["expected_property"] for c in cats.values() for p in c["probes"]))
        check("why-it-matters and what-to-consider are the report's own text (one source of truth)", all(c["why_it_matters"] == evidence.RISK[k][0] and c["what_to_consider"] == evidence.RISK[k][1] for k, c in cats.items()))
        ctl = {g["category"]: g["controls"] for g in info["controls"]}
        check("deterministic controls: authentication, authorization, session isolation, phase gating, audit, 12 checks in all", set(ctl) == {"authentication", "authorization", "session_isolation", "phase_gating", "audit"} and sum(map(len, ctl.values())) == 12)
        check("it does not expose attack prompts or judge markers", "Pretend you are DAN" not in txt and "fail_if_contains" not in txt and "hunter2" not in txt and "prompt" not in {k for c in cats.values() for p in c["probes"] for k in p})
        gw.SUITES.suites["extra"] = {**suite, "id": "extra", "name": "Extra", "attacks": suite["attacks"][:2], "sha256": "e" * 64}
        info2 = (await c.get("/evaluation-info", headers=H(tAl))).json(); del gw.SUITES.suites["extra"]
        check("a newly loaded suite shows up with its own categories (nothing is hard-coded)", {s["id"] for s in info2["suites"]} == {"builtin-core", "extra"} and [len(sum([c["probes"] for c in s["categories"]], [])) for s in info2["suites"] if s["id"] == "extra"] == [2])
        gw = importlib.reload(gw)
    async with client() as c:
        tAl2 = (await c.post("/auth/login", json={"username": "alice", "password": "amber orchard seven 7"})).json()["token"]
        check("after a restart the profile is still there", (await c.get("/auth/me", headers=H(tAl2))).json()["nickname"] == "fresh" and (await c.get("/auth/me", headers=H(tAl2))).json()["email"] == "alice@example.org")
    print(f"\nResult: {PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
asyncio.run(main())
