#!/usr/bin/env python3
"""No-Docker tests for the evaluation tables in gateway/store.py (schema v2).
    python3 tests/eval_store_test.py        # stdlib only
"""
import os, sqlite3, sys, tempfile, time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import store as store_mod  # noqa: E402

TMP = tempfile.mkdtemp()
PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)))

def raw(path, q, *a):
    c = sqlite3.connect(path); r = c.execute(q, a).fetchall(); c.commit(); c.close(); return r

def raises(f, exc=Exception):
    try:
        f()
    except exc:
        return True
    return False

SUITE = {"id": "s1", "version": 3, "sha256": "ab" * 32}
def result(seq, **kw):
    base = dict(seq=seq, kind="attack", judge="heuristic", case_id=f"c{seq}", category="jailbreak", severity="high",
                expected="e", status="pass", detail="d", evidence=[{"k": "v"}], http_status=200, latency_ms=5,
                test_id="t", response_sha256="h", response_len=3, response_excerpt="abc", audit_event="test_submitted",
                audit_seq=7, audit_status="recorded", started=1.0, finished=2.0)
    return {**base, **kw}

print("== migration from a populated v1 database")
v1 = TMP + "/v1.db"
c = sqlite3.connect(v1); c.executescript(store_mod._SCHEMA_V1); c.execute("PRAGMA user_version = 1")
c.execute("INSERT INTO tests VALUES ('old1','concluded','p','r',1.0,'mock',3)")
c.execute("INSERT INTO defenses (test_id, note, created) VALUES ('old1','note',2.0)"); c.commit(); c.close()
s = store_mod.Store(v1)
check("opening a v1 DB upgrades it to the current schema version", raw(v1, "PRAGMA user_version")[0][0] == store_mod.SCHEMA_VERSION == 2)
check("v1 rows survive untouched", s.get_test("old1")["prompt"] == "p" and raw(v1, "SELECT note FROM defenses")[0][0] == "note")
check("new tables exist", {r[0] for r in raw(v1, "SELECT name FROM sqlite_master WHERE type='table'")} >= {"tests", "defenses", "eval_runs", "eval_results"})
store_mod.Store(v1); store_mod.Store(v1)
check("re-opening is idempotent (no error, data intact)", len(raw(v1, "SELECT * FROM tests")) == 1)
fresh = TMP + "/fresh.db"; store_mod.Store(fresh)
check("a brand-new DB lands on the same version", raw(fresh, "PRAGMA user_version")[0][0] == 2)

print("== a failed upgrade rolls back completely")
bad = TMP + "/bad.db"
c = sqlite3.connect(bad); c.executescript(store_mod._SCHEMA_V1); c.execute("PRAGMA user_version = 1")
c.execute("INSERT INTO tests VALUES ('keep','active','p','r',1.0,'mock',3)")
c.execute("CREATE TABLE eval_results (x INTEGER)")        # collides with the v2 DDL half-way through
c.commit(); c.close()
check("upgrade over a conflicting table raises", raises(lambda: store_mod.Store(bad), sqlite3.Error))
check("...and the DB is still v1", raw(bad, "PRAGMA user_version")[0][0] == 1)
check("...with no eval_runs table left behind (all-or-nothing)", raw(bad, "SELECT name FROM sqlite_master WHERE name='eval_runs'") == [])
check("...and the old data is intact", raw(bad, "SELECT test_id FROM tests") == [("keep",)])
fut = TMP + "/future.db"; store_mod.Store(fut); raw(fut, "PRAGMA user_version = 3")
check("a newer schema version refuses to start (fail closed)", raises(lambda: store_mod.Store(fut), RuntimeError))

print("== run lifecycle")
db = TMP + "/run.db"; s = store_mod.Store(db)
s.create_run("r1", "evaluator", "mock", SUITE, 3)
r = s.get_run("r1")
check("new run: status running, suite id/version/sha recorded, 0 results done",
      r["status"] == "running" and r["suite_id"] == "s1" and r["suite_version"] == 3 and r["suite_sha256"] == SUITE["sha256"] and r["done"] == 0 and r["total"] == 3 and r["finished"] is None)
check("created_by and model recorded", r["created_by"] == "evaluator" and r["model"] == "mock")
check("duplicate run_id rejected", raises(lambda: s.create_run("r1", "x", "m", SUITE, 1), sqlite3.IntegrityError))
ids = [s.add_result("r1", result(i)) for i in (2, 1, 3)]
check("results come back ordered by seq, evidence round-trips as JSON", [x["seq"] for x in s.results("r1")] == [1, 2, 3] and s.results("r1")[0]["evidence"] == [{"k": "v"}])
check("done counts stored results", s.get_run("r1")["done"] == 3)
check("duplicate (run, seq) rejected", raises(lambda: s.add_result("r1", result(2)), sqlite3.IntegrityError))
check("result for an unknown run is rejected (foreign key enforced)", raises(lambda: s.add_result("nope", result(9)), sqlite3.IntegrityError))
check("defense for an unknown test is rejected too (v1 table, now enforced)", raises(lambda: s.add_defense("nope", "n"), sqlite3.IntegrityError))
for col, val in (("status", "maybe"), ("judge", "vibes"), ("kind", "other")):
    check(f"CHECK constraint rejects bad {col}", raises(lambda col=col, val=val: s.add_result("r1", result(50, **{col: val})), sqlite3.IntegrityError))
s.set_result_audit(ids[0], 99, "mismatch")
check("set_result_audit updates only audit columns", [x for x in s.results("r1") if x["seq"] == 2][0]["audit_status"] == "mismatch")
s.finish_run("r1", "completed", {"passed": 3}, {"audit": {"ok": True}}, "dig")
r = s.get_run("r1")
check("finish_run stores summary/integrity as JSON, digest, finished time", r["status"] == "completed" and r["summary"] == {"passed": 3} and r["integrity"] == {"audit": {"ok": True}} and r["results_digest"] == "dig" and r["finished"])
s.finish_run("r1", "failed", {}, {}, "other")
check("a finished run can't be overwritten", s.get_run("r1")["status"] == "completed" and s.get_run("r1")["results_digest"] == "dig")
check("unknown run -> None", s.get_run("zzz") is None and s.results("zzz") == [])

print("== history and restart recovery")
time.sleep(0.01); s.create_run("r2", "evaluator", "mock", SUITE, 1); s.add_result("r2", result(1))
time.sleep(0.01); s.create_run("r3", "evaluator", "mock", SUITE, 1)
check("list_runs is newest first", [x["run_id"] for x in s.list_runs()] == ["r3", "r2", "r1"])
check("list_runs honours limit", len(s.list_runs(limit=2)) == 2)
check("interrupt_running returns only the running ones", sorted(s.interrupt_running()) == ["r2", "r3"])
check("...they become 'interrupted' with a finish time; partial results kept",
      all(s.get_run(i)["status"] == "interrupted" and s.get_run(i)["finished"] for i in ("r2", "r3")) and s.get_run("r2")["done"] == 1)
check("...and the completed run is untouched", s.get_run("r1")["status"] == "completed")
check("a second call finds nothing to interrupt", s.interrupt_running() == [])
s2 = store_mod.Store(db)
check("everything is still there after reopening the file (restart)", [x["run_id"] for x in s2.list_runs()] == ["r3", "r2", "r1"] and len(s2.results("r1")) == 3)

print(f"\nResult: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
