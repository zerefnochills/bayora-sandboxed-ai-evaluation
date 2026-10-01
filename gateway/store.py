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
import json
import sqlite3
import time

SCHEMA_VERSION = 2

_SCHEMA_V1 = """
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

# v2: evaluation engine. Applied on top of v1 in ONE transaction (DDL is transactional in SQLite),
# so an interrupted upgrade leaves the old schema intact.
_SCHEMA_V2 = """
CREATE TABLE eval_runs (
    run_id        TEXT PRIMARY KEY,
    status        TEXT NOT NULL CHECK (status IN ('running', 'completed', 'interrupted', 'failed')),
    created       REAL NOT NULL,
    finished      REAL,
    created_by    TEXT NOT NULL,
    model         TEXT NOT NULL,
    suite_id      TEXT NOT NULL,
    suite_version INTEGER NOT NULL,
    suite_sha256  TEXT NOT NULL,
    total         INTEGER NOT NULL,
    summary       TEXT,
    integrity     TEXT,
    results_digest TEXT
);
CREATE TABLE eval_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES eval_runs(run_id),
    seq             INTEGER NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('control', 'attack')),
    judge           TEXT NOT NULL CHECK (judge IN ('deterministic', 'heuristic')),
    case_id         TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        TEXT NOT NULL,
    expected        TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pass', 'fail', 'blocked', 'error')),
    detail          TEXT,
    evidence        TEXT,
    http_status     INTEGER,
    latency_ms      INTEGER,
    test_id         TEXT,
    response_sha256 TEXT,
    response_len    INTEGER,
    response_excerpt TEXT,
    audit_event     TEXT,
    audit_seq       INTEGER,
    audit_status    TEXT,
    started         REAL NOT NULL,
    finished        REAL NOT NULL,
    UNIQUE (run_id, seq)
);
"""


class Store:
    def __init__(self, path):
        self.path = path
        with self._conn() as c:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                c.executescript(_SCHEMA_V1)
                c.execute("PRAGMA user_version = 1")
                version = 1
            if version == 1:
                c.executescript("BEGIN;" + _SCHEMA_V2 + "PRAGMA user_version = 2; COMMIT;")
            elif version != SCHEMA_VERSION:
                # Fail closed: never run against a schema this code doesn't understand.
                raise RuntimeError("store schema version %d, expected %d" % (version, SCHEMA_VERSION))

    @contextlib.contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")   # off by default in SQLite; makes the REFERENCES real
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

    # ---- evaluation runs ------------------------------------------------
    def create_run(self, run_id, created_by, model, suite, total):
        with self._conn() as c:
            c.execute("INSERT INTO eval_runs (run_id, status, created, created_by, model, suite_id, suite_version, "
                      "suite_sha256, total) VALUES (?, 'running', ?, ?, ?, ?, ?, ?, ?)",
                      (run_id, time.time(), created_by, model, suite["id"], suite["version"], suite["sha256"], total))

    _RESULT_COLS = ("seq", "kind", "judge", "case_id", "category", "severity", "expected", "status", "detail",
                    "evidence", "http_status", "latency_ms", "test_id", "response_sha256", "response_len",
                    "response_excerpt", "audit_event", "audit_seq", "audit_status", "started", "finished")

    def add_result(self, run_id, r):
        """r: dict with the keys in _RESULT_COLS (evidence is a JSON-able value). Returns the row id."""
        row = {**r, "evidence": json.dumps(r.get("evidence", []), sort_keys=True)}
        with self._conn() as c:
            cur = c.execute("INSERT INTO eval_results (run_id, %s) VALUES (?, %s)" % (
                ", ".join(self._RESULT_COLS), ", ".join("?" * len(self._RESULT_COLS))),
                (run_id, *[row.get(k) for k in self._RESULT_COLS]))
            return cur.lastrowid

    def set_result_audit(self, row_id, audit_seq, audit_status):
        with self._conn() as c:
            c.execute("UPDATE eval_results SET audit_seq = ?, audit_status = ? WHERE id = ?",
                      (audit_seq, audit_status, row_id))

    def results(self, run_id):
        with self._conn() as c:
            rows = c.execute("SELECT * FROM eval_results WHERE run_id = ? ORDER BY seq", (run_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"] or "[]")
            out.append(d)
        return out

    def finish_run(self, run_id, status, summary, integrity, digest):
        with self._conn() as c:
            c.execute("UPDATE eval_runs SET status = ?, finished = ?, summary = ?, integrity = ?, results_digest = ? "
                      "WHERE run_id = ? AND status = 'running'",
                      (status, time.time(), json.dumps(summary, sort_keys=True), json.dumps(integrity, sort_keys=True),
                       digest, run_id))

    def _run(self, row):
        d = dict(row)
        for k in ("summary", "integrity"):
            d[k] = json.loads(d[k]) if d[k] else None
        return d

    def get_run(self, run_id):
        with self._conn() as c:
            row = c.execute("SELECT r.*, (SELECT COUNT(*) FROM eval_results e WHERE e.run_id = r.run_id) AS done "
                            "FROM eval_runs r WHERE run_id = ?", (run_id,)).fetchone()
        return self._run(row) if row else None

    def list_runs(self, limit=50):
        with self._conn() as c:
            rows = c.execute("SELECT r.*, (SELECT COUNT(*) FROM eval_results e WHERE e.run_id = r.run_id) AS done "
                             "FROM eval_runs r ORDER BY created DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        return [self._run(r) for r in rows]

    def interrupt_running(self):
        """Startup recovery: a run still 'running' belongs to a process that died. Returns their ids."""
        with self._conn() as c:
            ids = [r[0] for r in c.execute("SELECT run_id FROM eval_runs WHERE status = 'running'")]
            c.execute("UPDATE eval_runs SET status = 'interrupted', finished = ? WHERE status = 'running'", (time.time(),))
        return ids
