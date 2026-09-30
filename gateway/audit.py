"""Append-only, hash-chained audit log (JSON lines) with an external anchor.

Each entry commits to the previous entry's hash, so editing or deleting any
past entry breaks every hash after it. verify() recomputes the whole chain.

Anchor: an attacker who controls this container can rewrite the whole file
into a new, self-consistent chain, which verify() alone cannot catch. So every
entry is also POSTed to a separate append-only sidecar (audit-anchor) that
has its own volume and lifecycle, survives gateway rebuilds, and rejects any
entry that doesn't extend its chain. Configured purely by environment
(ANCHOR_URL, ANCHOR_TOKEN); with neither set, the log works as before.

Failure policy: fail-open but loud. If the anchor is unreachable the request
still succeeds and the entry is written locally, but anchor health flips to
degraded (visible in verify()) and the backlog is re-sent on the next append.
"""
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request

GENESIS = "0" * 64


def _digest(prev, seq, ts, event, actor, data):
    payload = json.dumps(
        {"prev": prev, "seq": seq, "ts": ts, "event": event, "actor": actor, "data": data},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self, path, anchor_url=None, anchor_token=None, anchor_timeout=2.0):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._seq, self._last = self._load_state()

        self.anchor_url = (anchor_url or os.environ.get("ANCHOR_URL", "")).rstrip("/")
        self.anchor_token = anchor_token or os.environ.get("ANCHOR_TOKEN", "")
        self.anchor_timeout = anchor_timeout
        self._anchor_next = 0        # next seq the anchor is expected to accept
        self._anchor_ok = None       # None = never tried / not configured
        self._anchor_err = ""
        self._anchor_conflict = False
        if self.anchor_enabled:
            with self._lock:
                self._sync_anchor()

    # ---- local file -------------------------------------------------
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

    # ---- anchor client ----------------------------------------------
    @property
    def anchor_enabled(self):
        return bool(self.anchor_url and self.anchor_token)

    def _req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.anchor_url + path, data=data, method=method,
            headers={"Authorization": "Bearer " + self.anchor_token,
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.anchor_timeout) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}

    def _sync_anchor(self):
        """Push every local entry the anchor doesn't hold yet. Caller holds the lock."""
        try:
            code, head = self._req("GET", "/head")
            if code != 200:
                raise RuntimeError("anchor /head returned %d" % code)
            self._anchor_next = head["next_seq"]
            tip_seen = self._anchor_next == 0
            for e in self._entries():
                if e["seq"] == self._anchor_next - 1:
                    # The local chain must pass through the anchor's head.
                    if e["hash"] != head["head"]:
                        self._anchor_conflict = True
                        raise RuntimeError("local chain DIVERGES from anchor at seq %d" % e["seq"])
                    tip_seen = True
                if e["seq"] < self._anchor_next:
                    continue
                code, body = self._req("POST", "/append", e)
                if code in (200, 201):
                    self._anchor_next = e["seq"] + 1
                elif code == 409:
                    self._anchor_conflict = True
                    raise RuntimeError("anchor REJECTED seq %d: %s" % (e["seq"], body.get("error")))
                else:
                    raise RuntimeError("anchor returned %d at seq %d" % (code, e["seq"]))
            if not tip_seen:
                self._anchor_conflict = True
                raise RuntimeError("local log is SHORTER than the anchor (truncated?)")
            self._anchor_conflict = False
            self._anchor_ok, self._anchor_err = True, ""
        except Exception as ex:  # network down, anchor restarting, conflict...
            self._anchor_ok, self._anchor_err = False, str(ex)[:200]

    def anchor_status(self):
        if not self.anchor_enabled:
            return {"enabled": False}
        return {"enabled": True, "ok": bool(self._anchor_ok),
                "anchored": self._anchor_next, "local": self._seq,
                "pending": max(0, self._seq - self._anchor_next),
                "conflict": self._anchor_conflict, "error": self._anchor_err}

    # ---- public API -------------------------------------------------
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
            if self.anchor_enabled:
                self._sync_anchor()
            return entry

    def verify(self):
        prev, n = GENESIS, 0
        for e in self._entries():
            expected = _digest(prev, e["seq"], e["ts"], e["event"], e["actor"], e["data"])
            if e["prev"] != prev or e["hash"] != expected or e["seq"] != n:
                return {"ok": False, "entries": n, "broken_at": n, "anchor": self.anchor_status()}
            prev, n = e["hash"], n + 1
        return {"ok": True, "entries": n, "head": prev, "broken_at": None,
                "anchor": self.anchor_status()}

    def tail(self, limit=50):
        return list(self._entries())[-limit:]
