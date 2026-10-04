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

SCHEMA_VERSION = 5

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


# v3: which provider/model produced a run, whether it was the mock or a real provider, the pre-flight
# health result, and why a run failed. NULL on runs made before v3 (shown as UNKNOWN, never guessed).
_SCHEMA_V3 = """
ALTER TABLE eval_runs ADD COLUMN provider TEXT;
ALTER TABLE eval_runs ADD COLUMN provider_model TEXT;
ALTER TABLE eval_runs ADD COLUMN provider_kind TEXT CHECK (provider_kind IN ('mock', 'real'));
ALTER TABLE eval_runs ADD COLUMN health TEXT;
ALTER TABLE eval_runs ADD COLUMN error TEXT;
"""


# v4: user accounts. Passwords are stored only as salted scrypt hashes (see users.py). token_version lets an
# admin or a password change invalidate every token already issued to the account.
_SCHEMA_V4 = """
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    active        INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    token_version INTEGER NOT NULL DEFAULT 1,
    created       REAL NOT NULL,
    created_by    TEXT,
    last_login    REAL
);
"""


# v5: personal profile. Plain account information and preferences the owner may edit; nothing here grants
# access. Email is stored as information only (nothing sends or verifies email).
_SCHEMA_V5 = """
ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN nickname TEXT;
ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN bio TEXT;
ALTER TABLE users ADD COLUMN show_username INTEGER NOT NULL DEFAULT 1 CHECK (show_username IN (0, 1));
ALTER TABLE users ADD COLUMN reduce_motion INTEGER NOT NULL DEFAULT 0 CHECK (reduce_motion IN (0, 1));
"""
PROFILE_FIELDS = ("display_name", "nickname", "email", "bio", "show_username", "reduce_motion")


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
                version = 2
            if version == 2:
                c.executescript("BEGIN;" + _SCHEMA_V3 + "PRAGMA user_version = 3; COMMIT;")
                version = 3
            if version == 3:
                c.executescript("BEGIN;" + _SCHEMA_V4 + "PRAGMA user_version = 4; COMMIT;")
                version = 4
            if version == 4:
                c.executescript("BEGIN;" + _SCHEMA_V5 + "PRAGMA user_version = 5; COMMIT;")
                version = 5
            if version != SCHEMA_VERSION:
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
    def create_run(self, run_id, created_by, model, suite, total, provider=None, provider_model=None, provider_kind=None):
        with self._conn() as c:
            c.execute("INSERT INTO eval_runs (run_id, status, created, created_by, model, suite_id, suite_version, "
                      "suite_sha256, total, provider, provider_model, provider_kind) "
                      "VALUES (?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (run_id, time.time(), created_by, model, suite["id"], suite["version"], suite["sha256"], total,
                       provider, provider_model, provider_kind))

    def set_run_health(self, run_id, health):
        with self._conn() as c:
            c.execute("UPDATE eval_runs SET health = ? WHERE run_id = ?", (json.dumps(health, sort_keys=True), run_id))

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

    def finish_run(self, run_id, status, summary, integrity, digest, error=None):
        with self._conn() as c:
            c.execute("UPDATE eval_runs SET status = ?, finished = ?, summary = ?, integrity = ?, results_digest = ?, "
                      "error = ? WHERE run_id = ? AND status = 'running'",
                      (status, time.time(), json.dumps(summary, sort_keys=True), json.dumps(integrity, sort_keys=True),
                       digest, json.dumps(error, sort_keys=True) if error else None, run_id))

    def _run(self, row):
        d = dict(row)
        for k in ("summary", "integrity", "health", "error"):
            d[k] = json.loads(d[k]) if d[k] else None
        return d

    def get_run(self, run_id):
        with self._conn() as c:
            row = c.execute("SELECT r.*, (SELECT COUNT(*) FROM eval_results e WHERE e.run_id = r.run_id) AS done "
                            "FROM eval_runs r WHERE run_id = ?", (run_id,)).fetchone()
        return self._run(row) if row else None

    def list_runs(self, limit=50, owner=None):
        """Newest first. owner=None -> every run; otherwise only runs created by that principal."""
        where, args = ("WHERE created_by = ? ", (owner,)) if owner is not None else ("", ())
        with self._conn() as c:
            rows = c.execute("SELECT r.*, (SELECT COUNT(*) FROM eval_results e WHERE e.run_id = r.run_id) AS done "
                             "FROM eval_runs r " + where + "ORDER BY created DESC, rowid DESC LIMIT ?", (*args, limit)).fetchall()
        return [self._run(r) for r in rows]

    # ---- users ------------------------------------------------------------
    _USER_COLS = "id, username, role, active, token_version, created, created_by, last_login"

    def count_users(self):
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(self, username, password_hash, role, created_by):
        """True if created, False if the username is taken."""
        try:
            with self._conn() as c:
                c.execute("INSERT INTO users (username, password_hash, role, created, created_by) VALUES (?, ?, ?, ?, ?)",
                          (username, password_hash, role, time.time(), created_by))
            return True
        except sqlite3.IntegrityError as e:
            if "UNIQUE" in str(e):
                return False
            raise

    def get_user(self, username, with_hash=False):
        with self._conn() as c:
            row = c.execute("SELECT %s%s FROM users WHERE username = ?" % (self._USER_COLS, ", password_hash" if with_hash else ""),
                            (username,)).fetchone()
        return dict(row) if row else None

    def list_users(self):
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT %s FROM users ORDER BY id" % self._USER_COLS)]

    def set_user_fields(self, username, role=None, active=None):
        sets, args = [], []
        if role is not None:
            sets.append("role = ?"); args.append(role)
        if active is not None:
            sets.append("active = ?"); args.append(1 if active else 0)
        if not sets:
            return False
        sets.append("token_version = token_version + 1")        # any change to role/active invalidates old tokens
        with self._conn() as c:
            return c.execute("UPDATE users SET %s WHERE username = ?" % ", ".join(sets), (*args, username)).rowcount == 1

    def set_password(self, username, password_hash):
        with self._conn() as c:
            return c.execute("UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE username = ?",
                             (password_hash, username)).rowcount == 1

    def get_profile(self, username):
        with self._conn() as c:
            row = c.execute("SELECT username, role, created, last_login, %s FROM users WHERE username = ?" % ", ".join(PROFILE_FIELDS),
                            (username,)).fetchone()
        return dict(row) if row else None

    def set_profile(self, username, fields):
        """Only the PROFILE_FIELDS columns can ever be written here (role, active, hashes etc. are unreachable)."""
        cols = [k for k in fields if k in PROFILE_FIELDS]
        if not cols:
            return False
        with self._conn() as c:
            return c.execute("UPDATE users SET %s WHERE username = ?" % ", ".join(k + " = ?" for k in cols),
                             (*[fields[k] for k in cols], username)).rowcount == 1

    def touch_login(self, username):
        with self._conn() as c:
            c.execute("UPDATE users SET last_login = ? WHERE username = ?", (time.time(), username))

    def count_active_admins(self):
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]

    def interrupt_running(self):
        """Startup recovery: a run still 'running' belongs to a process that died. Returns their ids."""
        with self._conn() as c:
            ids = [r[0] for r in c.execute("SELECT run_id FROM eval_runs WHERE status = 'running'")]
            c.execute("UPDATE eval_runs SET status = 'interrupted', finished = ? WHERE status = 'running'", (time.time(),))
        return ids
