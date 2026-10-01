#!/usr/bin/env python3
"""No-Docker tests for the attack-suite format (gateway/suites.py + gateway/suites/*.json).
    python3 tests/suites_test.py        # stdlib only
"""
import copy, json, os, sys, tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "gateway")]
import suites  # noqa: E402

PASS = FAIL = 0
def check(name, cond, extra=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(cond), FAIL + (not cond)
    print(("  PASS  " if cond else "  FAIL  ") + name + ("" if cond else "  " + str(extra)))

def rejects(doc, fragment=""):
    try:
        suites.validate(doc)
    except suites.SuiteError as e:
        return fragment in str(e)
    return False

BUILTIN = os.path.join(ROOT, "gateway", "suites")
raw = json.load(open(os.path.join(BUILTIN, "builtin-core.json")))

print("== built-in suite")
reg = suites.SuiteRegistry.load(BUILTIN)
s = reg.get("builtin-core")
check("builtin-core loads and validates", s is not None and s["version"] == 1)
check("covers the five required categories", {a["category"] for a in s["attacks"]} ==
      {"jailbreak", "prompt_injection", "instruction_following", "data_exfiltration", "policy_bypass"})
need = {"id", "category", "prompt", "description", "expected_property", "severity"}
check("every attack has id, category, prompt, description, expected property, severity", all(need <= set(a) for a in s["attacks"]))
check("public() lists the suite but exposes no attack prompt text", reg.public()[0]["attacks"] == 13 and not any(a["prompt"] in json.dumps(reg.public()) for a in s["attacks"]))

print("== hash and import/export")
check("sha256 is 64 hex chars", len(s["sha256"]) == 64)
reordered = json.loads(json.dumps(raw)); reordered = {k: reordered[k] for k in reversed(list(reordered))}
check("same content, different key order -> same sha256", suites.validate(reordered)["sha256"] == s["sha256"])
edited = copy.deepcopy(raw); edited["attacks"][0]["prompt"] += " please"
check("one changed character of a prompt -> different sha256", suites.validate(edited)["sha256"] != s["sha256"])
exported = {k: v for k, v in s.items() if k != "sha256"}
with tempfile.TemporaryDirectory() as d:
    json.dump(exported, open(d + "/copy.json", "w"))
    again = suites.SuiteRegistry.load(d).get("builtin-core")
check("export -> import round-trips to an identical suite and hash", again == s)

print("== strict validation (each of these must be rejected)")
def mut(f):
    d = copy.deepcopy(raw); f(d); return d
check("wrong format string", rejects(mut(lambda d: d.update(format="bayora.suite/2")), "unsupported format"))
check("unknown top-level key", rejects(mut(lambda d: d.update(extra=1)), "unknown keys"))
check("bad suite id", rejects(mut(lambda d: d.update(id="Bad Id!")), "'id'"))
check("version 0 / non-integer / bool", all(rejects(mut(lambda d, v=v: d.update(version=v)), "version") for v in (0, "1", True, 1.5)))
check("empty attack list", rejects(mut(lambda d: d.update(attacks=[])), "attacks"))
check(f"more than {suites.MAX_ATTACKS} attacks", rejects(mut(lambda d: d.update(attacks=[d["attacks"][0]] * 0 + [dict(d["attacks"][0], id=f"a{i}") for i in range(suites.MAX_ATTACKS + 1)])), "attacks"))
check("duplicate attack id", rejects(mut(lambda d: d["attacks"].append(dict(d["attacks"][0]))), "duplicate"))
for field in ("id", "category", "severity", "prompt", "description", "expected_property", "judge"):
    check(f"attack missing '{field}'", rejects(mut(lambda d, f=field: d["attacks"][0].pop(f))))
check("unknown attack key", rejects(mut(lambda d: d["attacks"][0].update(url="http://x")), "unknown keys"))
check("bad severity", rejects(mut(lambda d: d["attacks"][0].update(severity="urgent")), "severity"))
check("prompt over the gateway's 4000-char limit", rejects(mut(lambda d: d["attacks"][0].update(prompt="x" * 4001)), "prompt"))
check("empty / whitespace prompt", rejects(mut(lambda d: d["attacks"][0].update(prompt="   ")), "prompt"))
check("non-string prompt", rejects(mut(lambda d: d["attacks"][0].update(prompt=["a"])), "prompt"))
check("judge with no markers", rejects(mut(lambda d: d["attacks"][0].update(judge={})), "at least one marker"))
check("judge with unknown key (no regex/eval smuggling)", rejects(mut(lambda d: d["attacks"][0].update(judge={"regex": ".*"})), "judge"))
check("judge marker too long / empty / wrong type", all(rejects(mut(lambda d, m=m: d["attacks"][0].update(judge={"fail_if_contains": [m]}))) for m in ("x" * 101, "", 5)))
check("not an object", rejects([1, 2]))

print("== registry")
try:
    suites.SuiteRegistry([s, s]); dup = False
except suites.SuiteError:
    dup = True
check("duplicate suite ids rejected", dup)
with tempfile.TemporaryDirectory() as d:
    open(d + "/bad.json", "w").write("{not json")
    try:
        suites.SuiteRegistry.load(d); loud = False
    except suites.SuiteError as e:
        loud = "bad.json" in str(e)
check("a malformed suite file fails loudly at load (names the file)", loud)
with tempfile.TemporaryDirectory() as d:
    open(d + "/notes.txt", "w").write("ignored")
    check("non-.json files are ignored; missing dir -> empty registry", suites.SuiteRegistry.load(d).suites == {} and suites.SuiteRegistry.load(d + "/nope").suites == {})

print(f"\nResult: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
