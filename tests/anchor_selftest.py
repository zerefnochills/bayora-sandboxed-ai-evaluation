#!/usr/bin/env python3
"""End-to-end self-test of the audit anchor. No Docker needed: it starts the
real anchor service as a subprocess on localhost and drives the real
gateway/audit.py against it. Run from the repo root:  python3 tests/anchor_selftest.py
"""
import json, os, shutil, socket, subprocess, sys, tempfile, time, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "gateway"))
from audit import AuditLog, _digest, GENESIS  # noqa: E402

TOKEN = "selftest-token"
tmp = tempfile.mkdtemp()
adata, gdata = os.path.join(tmp, "anchor"), os.path.join(tmp, "gw")
sock = socket.socket(); sock.bind(("127.0.0.1", 0)); PORT = sock.getsockname()[1]; sock.close()
URL = "http://127.0.0.1:%d" % PORT
proc = None
results = []


def start():
    global proc
    env = dict(os.environ, ANCHOR_DATA=adata, ANCHOR_TOKEN=TOKEN, ANCHOR_PORT=str(PORT))
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "anchor", "anchor_service.py")],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            urllib.request.urlopen(URL + "/health", timeout=1); return
        except Exception:
            time.sleep(0.1)
    raise SystemExit("anchor did not start")


def stop():
    global proc
    if proc:
        proc.kill(); proc.wait(); proc = None


def check(name, cond):
    results.append(cond)
    print(("PASS  " if cond else "FAIL  ") + name)


def anchor_entries():
    with open(os.path.join(adata, "anchor.jsonl")) as f:
        return {json.loads(l)["seq"]: json.loads(l) for l in f if l.strip()}


def http(method, path, body=None, token=TOKEN):
    req = urllib.request.Request(URL + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


try:
    start()
    path = os.path.join(gdata, "audit.jsonl")

    log = AuditLog(path, URL, TOKEN)
    for i in range(5):
        log.append("submit", "red", {"i": i})
    st = log.anchor_status()
    check("5 entries appended -> 5 anchored, healthy", st["ok"] and st["anchored"] == 5 and st["pending"] == 0)

    log = AuditLog(path, URL, TOKEN)  # simulate a gateway rebuild/restart
    for i in range(3):
        log.append("read", "blue", {"i": i})
    st = log.anchor_status()
    check("survives gateway restart: 8 local, 8 anchored", st["anchored"] == 8 and log.verify()["entries"] == 8)

    stop(); start()  # anchor restart keeps its own history
    check("anchor restart keeps history (count=8)", len(anchor_entries()) == 8 and log.append("x", "red", {})["seq"] == 8)

    check("wrong token rejected (401)", http("GET", "/head", token="nope") == 401)
    check("no update/delete verbs (404/501)", http("DELETE", "/append") in (404, 501))
    check("forked entry for anchored seq rejected (409)",
          http("POST", "/append", dict(anchor_entries()[0], hash="f" * 64)) == 409)

    # Full-file rewrite: forge a brand-new self-consistent chain in the gateway's file.
    forged, prev = [], GENESIS
    for i in range(9):
        ts = time.time(); d = _digest(prev, i, ts, "submit", "red", {"forged": i})
        forged.append({"seq": i, "ts": ts, "event": "submit", "actor": "red",
                       "data": {"forged": i}, "prev": prev, "hash": d}); prev = d
    with open(path, "w") as f:
        f.write("".join(json.dumps(e, sort_keys=True) + "\n" for e in forged))
    disk = {e["seq"]: e for e in forged}
    check("verify() alone is FOOLED by the forged chain (the gap)", AuditLog(path).verify()["ok"] is True)
    anc = anchor_entries()
    check("anchor cross-check catches all 9 forged entries",
          sum(1 for s in disk if s in anc and disk[s] != anc[s]) == 9)
    fl = AuditLog(path, URL, TOKEN)
    check("forged gateway cannot get its chain accepted (conflict flagged)",
          fl.anchor_status()["conflict"] and not fl.anchor_status()["ok"])
    check("anchor still holds the original history untouched", len(anchor_entries()) == 9)

    # Truncation: drop the tail of the real log.
    real = [anchor_entries()[s] for s in sorted(anchor_entries())]
    check("truncation detectable (anchor holds seqs the disk lacks)", len(real) > 4 and len(real[:4]) < len(real))

    # Anchor down: fail-open but loud, backlog flushed on recovery.
    shutil.rmtree(gdata); os.makedirs(gdata)
    stop(); shutil.rmtree(adata)
    start()
    log = AuditLog(path, URL, TOKEN)
    for i in range(2):
        log.append("submit", "red", {"i": i})
    stop()
    e = log.append("submit", "red", {"during": "outage"})
    st = log.anchor_status()
    check("anchor down: request still succeeds, degraded + pending shown",
          e["seq"] == 2 and st["ok"] is False and st["pending"] == 1)
    start()
    log.append("submit", "red", {"after": "recovery"})
    st = log.anchor_status()
    check("anchor back: backlog flushed, healthy again", st["ok"] and st["pending"] == 0 and len(anchor_entries()) == 4)

    # Backfill: existing local log, empty anchor.
    stop(); shutil.rmtree(adata); start()
    log = AuditLog(path, URL, TOKEN)
    check("backfill: pre-existing local log synced to a fresh anchor", log.anchor_status()["anchored"] == 4)
finally:
    stop(); shutil.rmtree(tmp, ignore_errors=True)

print("\n%d/%d passed" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
