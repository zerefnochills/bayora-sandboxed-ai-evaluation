"""Durable store for red-team tests and blue-team defenses (SQLite, stdlib only).

Replaces the gateway's in-memory TESTS/DEFENSES dicts so state survives a
restart. The audit log is unchanged and stays the tamper-evident record: this
store is mutable, so the audit entries hold sha256 of every prompt/response
and can be used to check what is stored here.

One short-lived connection per call keeps it safe across FastAPI's threadpool.
Default rollback-journal mode (not WAL) on purpose: WAL needs shared memory,
which is a risk under gVisor. Journal files land next to the DB, on the same
writable volume as the audit log.
"""
import contextlib
import sqlite3
import time

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE tests (
    test_id    TEXT PRIMARY KEY,
    status     TEXT NOT NULL CHECK (status IN ('active', 'concluded')),
    prompt     TEXT NOT NULL,
    response   TEXT NOT NULL,
    created    REAL NOT NULL,
    model      TEXT,
    latency_ms INTEGER
);
CREATE TABLE defenses (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL REFERENCES tests(test_id),
    note    TEXT NOT NULL,
    created REAL NOT NULL
);
"""


class Store:
    def __init__(self, path):
        self.path = path
        with self._conn() as c:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                c.executescript(_SCHEMA)
                c.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)
            elif version != SCHEMA_VERSION:
                # Fail closed: never run against a schema this code doesn't understand.
                raise RuntimeError("store schema version %d, expected %d" % (version, SCHEMA_VERSION))

    @contextlib.contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        try:
            with c:  # commit on success, roll back on error
                yield c
        finally:
            c.close()

    def create_test(self, test_id, prompt, response, model, latency_ms):
        with self._conn() as c:
            c.execute("INSERT INTO tests (test_id, status, prompt, response, created, model, latency_ms) "
                      "VALUES (?, 'active', ?, ?, ?, ?, ?)",
                      (test_id, prompt, response, time.time(), model, latency_ms))

    def get_test(self, test_id):
        with self._conn() as c:
            row = c.execute("SELECT * FROM tests WHERE test_id = ?", (test_id,)).fetchone()
        return dict(row) if row else None

    def list_tests(self):
        """Metadata only (id, status), oldest first. Never returns prompts or responses."""
        with self._conn() as c:
            rows = c.execute("SELECT test_id, status FROM tests ORDER BY rowid").fetchall()
        return [dict(r) for r in rows]

    def conclude(self, test_id):
        """True only if this call changed the test from active to concluded."""
        with self._conn() as c:
            cur = c.execute("UPDATE tests SET status = 'concluded' WHERE test_id = ? AND status = 'active'",
                            (test_id,))
            return cur.rowcount == 1

    def add_defense(self, test_id, note):
        with self._conn() as c:
            c.execute("INSERT INTO defenses (test_id, note, created) VALUES (?, ?, ?)",
                      (test_id, note, time.time()))
