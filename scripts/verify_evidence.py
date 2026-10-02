#!/usr/bin/env python3
"""Check a Bayora evidence bundle offline. Standard library only; needs no gateway and no network.

    python3 scripts/verify_evidence.py bundle.json            # human-readable
    python3 scripts/verify_evidence.py bundle.json --json     # machine-readable
Exit status: 0 every check passed, 1 at least one check FAILED, 2 the file is not a usable bundle.

It re-derives everything that CAN be re-derived from the file: the bundle digest, the results digest, the
summary counts, the hash of every audit entry, the link between every result row and its audit entry (the
reply hash recorded by the gateway), the suite content hash, and the order of the phase-gate events.
It CANNOT re-derive audit-chain continuity or the independent-anchor comparison (the excerpt is sparse);
those are reported as INFO from what the gateway recorded. A passing bundle is internally consistent. It is
not a signature, and it does not show that a model is safe.
"""
import hashlib
import json
import sys

FORMAT = "bayora.evidence/1"
ROW_KEYS = ("seq", "kind", "judge", "case_id", "status", "http_status", "test_id", "response_sha256")


def sha256(t):
    return hashlib.sha256(t.encode()).hexdigest()


def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def audit_digest(prev, seq, ts, event, actor, data):   # must match gateway/audit.py _digest
    return sha256(json.dumps({"prev": prev, "seq": seq, "ts": ts, "event": event, "actor": actor, "data": data},
                             sort_keys=True, separators=(",", ":")))


def verify(b):
    res = []

    def chk(name, ok, detail=""):
        res.append({"check": name, "result": "INFO" if ok is None else "PASS" if ok else "FAIL", "detail": detail})

    chk("format is " + FORMAT, b.get("format") == FORMAT, str(b.get("format")))
    if b.get("format") != FORMAT:
        return res
    run, rows, entries = b["run"], b["results"], b["audit"]["entries"]
    chk("bundle digest matches its content", b.get("digest") == sha256(canonical({k: v for k, v in b.items() if k != "digest"})),
        "detects accidental edits; not a signature")

    srt = sorted(rows, key=lambda r: r["seq"])
    if run.get("results_digest"):
        chk("results digest matches the result rows", sha256(canonical([{k: r.get(k) for k in ROW_KEYS} for r in srt])) == run["results_digest"])
    if run.get("summary"):
        c = {s: sum(r["status"] == s for r in rows) for s in ("pass", "fail", "blocked", "error")}
        sm = run["summary"]
        chk("summary counts match the result rows", (sm["total"], sm["passed"], sm["failed"], sm["blocked"], sm["errors"]) == (len(rows), c["pass"], c["fail"], c["blocked"], c["error"]),
            "%s rows: %s" % (len(rows), c))
    chk("result rows are numbered 1..n without gaps", [r["seq"] for r in srt] == list(range(1, len(rows) + 1)))
    chk("every row is labelled with the judge that produced it", all(r["judge"] == ("deterministic" if r["kind"] == "control" else "heuristic") for r in rows))

    seqs = [e["seq"] for e in entries]
    chk("audit entries are in strictly increasing order", seqs == sorted(set(seqs)))
    bad = [e["seq"] for e in entries if audit_digest(e["prev"], e["seq"], e["ts"], e["event"], e["actor"], e["data"]) != e["hash"]]
    chk("every audit entry's hash matches its own content", not bad, ("entries with a wrong hash: %s" % bad) if bad else "%d entries" % len(entries))

    sub = {e["data"].get("test_id"): e for e in entries if e["event"] == "test_submitted"}
    atk = [r for r in rows if r["kind"] == "attack" and r.get("test_id")]
    miss = [r["case_id"] for r in atk if r["test_id"] not in sub or sub[r["test_id"]]["data"].get("response_sha256") != r["response_sha256"]
            or r.get("audit_status") != "recorded" or r.get("audit_seq") != sub[r["test_id"]]["seq"]]
    chk("every attack's reply hash matches its audit entry", not miss, ("mismatch or missing: %s" % miss) if miss else "%d attacks" % len(atk))

    ev = {}
    for e in entries:
        if e["data"].get("run_id") == run["run_id"]:
            ev.setdefault(e["event"], e)
    st = ev.get("evaluation_started")
    chk("audit records the start of this run with the same suite hash, model and total",
        bool(st) and st["data"].get("suite_sha256") == run["suite"]["sha256"] and st["data"].get("model") == run["model"] and st["data"].get("total") == run["total"])
    if run["status"] == "completed":
        done = ev.get("evaluation_completed")
        chk("audit seals the same results digest", bool(done) and done["data"].get("results_digest") == run.get("results_digest"))
        if done and run.get("summary"):
            sm = run["summary"]
            chk("audit counts match the summary", (done["data"]["passed"], done["data"]["failed"], done["data"]["blocked"], done["data"]["errors"]) == (sm["passed"], sm["failed"], sm["blocked"], sm["errors"]))
    elif run["status"] in ("failed", "interrupted"):
        chk("audit records how the run ended (%s)" % run["status"], ("evaluation_" + run["status"]) in ev)

    order_bad = []
    for tid in sub:
        by = {}
        for e in entries:
            if e["data"].get("test_id") == tid:
                by.setdefault(e["event"], e["seq"])
        if all(k in by for k in ("early_access_denied", "test_concluded", "results_released")):
            if not by["early_access_denied"] < by["test_concluded"] < by["results_released"]:
                order_bad.append(tid)
    chk("phase gate order holds: denied while active, then concluded, then released", not order_bad, ("out of order: %s" % order_bad) if order_bad else "")

    sd = b["suite"].get("definition")
    if sd is None:
        chk("suite definition", None, b["suite"].get("note", "not included"))
    else:
        chk("suite content hash matches the hash recorded with the run", sha256(json.dumps(sd, sort_keys=True, separators=(",", ":"), ensure_ascii=False)) == run["suite"]["sha256"])
        defs = {a["id"]: a for a in sd["attacks"]}
        wrong = [r["case_id"] for r in rows if r["kind"] == "attack" and (r["case_id"] not in defs or defs[r["case_id"]]["category"] != r["category"]
                                                                       or defs[r["case_id"]]["severity"] != r["severity"] or defs[r["case_id"]]["expected_property"] != r["expected"])]
        chk("every attack row matches the suite definition", not wrong, ("differs: %s" % wrong) if wrong else "")

    v = b["verification"]
    chk("audit chain continuity and anchor comparison (as recorded by the gateway, not re-derivable here)", None,
        "chain ok=%s over %s entries; anchor %s" % (v.get("audit_chain_ok"), v.get("audit_entries"), json.dumps(v.get("anchor"), sort_keys=True)))
    return res


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    try:
        with open(argv[0]) as f:
            bundle = json.load(f)
        results = verify(bundle)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print("not a usable evidence bundle: %s: %s" % (type(e).__name__, e))
        return 2
    failed = [r for r in results if r["result"] == "FAIL"]
    if "--json" in argv:
        print(json.dumps({"ok": not failed, "checks": results}, indent=1))
    else:
        for r in results:
            print("%-5s %s%s" % (r["result"], r["check"], ("  (%s)" % r["detail"]) if r["detail"] else ""))
        print("\n%s" % ("ALL CHECKS PASSED" if not failed else "%d CHECK(S) FAILED" % len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
