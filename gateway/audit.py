"""Append-only, hash-chained audit log (JSON lines).

Each entry commits to the previous entry's hash, so editing or deleting any
past entry breaks every hash after it. verify() recomputes the whole chain.

Known limit: an attacker who can rewrite the *entire* file (or truncate the
tail) produces a self-consistent chain. Mitigation for later: periodically
anchor the head hash somewhere the gateway cannot write.
"""
import hashlib
import json
import os
import threading
import time

GENESIS = "0" * 64


def _digest(prev, seq, ts, event, actor, data):
    payload = json.dumps(
        {"prev": prev, "seq": seq, "ts": ts, "event": event, "actor": actor, "data": data},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._seq, self._last = self._load_state()

    def _entries(self):
        if not os.path.exists(self.path):
            return
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def _load_state(self):
        seq, last = 0, GENESIS
        for e in self._entries():
            seq, last = e["seq"] + 1, e["hash"]
        return seq, last

    def append(self, event, actor, data):
        with self._lock:
            ts = time.time()
            h = _digest(self._last, self._seq, ts, event, actor, data)
            entry = {"seq": self._seq, "ts": ts, "event": event, "actor": actor,
                     "data": data, "prev": self._last, "hash": h}
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._seq += 1
            self._last = h
            return entry

    def verify(self):
        prev, n = GENESIS, 0
        for e in self._entries():
            expected = _digest(prev, e["seq"], e["ts"], e["event"], e["actor"], e["data"])
            if e["prev"] != prev or e["hash"] != expected or e["seq"] != n:
                return {"ok": False, "entries": n, "broken_at": n}
            prev, n = e["hash"], n + 1
        return {"ok": True, "entries": n, "head": prev, "broken_at": None}

    def tail(self, limit=50):
        return list(self._entries())[-limit:]
