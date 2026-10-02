"""User accounts for the Bayora web app (standard library only).

Roles are account roles stored in SQLite, separate from the tenant tokens (red / blue / admin / evaluator)
the gateway already issues:

    user   eval:run, eval:read                        runs evaluations and reads ONLY their own runs
    admin  user + eval:admin, user:admin, audit:read  manages accounts, sees every run, system status

Account principals use the subject "user:<username>", so they can never collide with a tenant or runner
actor name such as "red" or "eval-red" in the audit log.

Passwords: salted scrypt (n=2^14, r=8, p=1), constant-time comparison, a work-equalising dummy hash for
unknown usernames, a length/shape policy, and sliding-window throttling of failed logins. Throttle state is
in memory (single gateway process, resets on restart); it applies to unknown usernames in exactly the same
way as to real ones so a lockout does not reveal which accounts exist.

The first admin is created through POST /auth/bootstrap with a code derived from the gateway's signing
secret (bootstrap_code()); the route is closed as soon as any account exists.
"""
import base64
import hashlib
import hmac
import os
import re
import time
from collections import deque

USER_PREFIX = "user:"
ROLE_SCOPES = {
    "user": ["eval:run", "eval:read"],
    "admin": ["eval:run", "eval:read", "eval:admin", "user:admin", "audit:read"],
}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
RESERVED = {"red", "blue", "admin", "evaluator", "gateway", "anonymous", "root", "system", "auditor"}
MIN_PASSWORD, MAX_PASSWORD = 10, 128
_N, _R, _P = 2 ** 14, 8, 1


class PolicyError(ValueError):
    """The username or password does not meet the policy (the message is safe to show)."""


def check_username(name):
    if not isinstance(name, str) or not USERNAME_RE.match(name):
        raise PolicyError("username must be 3 to 32 characters: lowercase letters, digits, dot, dash or underscore, starting with a letter or digit")
    if name in RESERVED or name.startswith("eval-"):
        raise PolicyError("that username is reserved")
    return name


def check_password(pw, username=""):
    if not isinstance(pw, str) or not MIN_PASSWORD <= len(pw) <= MAX_PASSWORD:
        raise PolicyError("password must be %d to %d characters" % (MIN_PASSWORD, MAX_PASSWORD))
    if len(set(pw)) < 5:
        raise PolicyError("password is too repetitive")
    if username and username.lower() in pw.lower():
        raise PolicyError("password must not contain the username")
    return pw


def hash_password(pw):
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32, maxmem=64 * 1024 * 1024)
    return "scrypt$%d$%d$%d$%s$%s" % (_N, _R, _P, base64.b64encode(salt).decode(), base64.b64encode(h).decode())


def verify_password(pw, stored):
    try:
        scheme, n, r, p, salt, want = stored.split("$")
        if scheme != "scrypt":
            return False
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32,
                             maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(got, base64.b64decode(want))
    except (ValueError, TypeError):
        return False


DUMMY_HASH = hash_password("dummy-password-for-timing")


def bootstrap_code(secret):
    """Proof that the caller can read the gateway's configuration (it is derived from the signing secret)."""
    return hmac.new(secret.encode(), b"bayora-bootstrap-v1", hashlib.sha256).hexdigest()[:20]


def public_user(u):
    return {k: u[k] for k in ("username", "role", "active", "created", "created_by", "last_login")}


class LoginGuard:
    """Sliding-window failure counter. check() -> seconds to wait (0 = allowed)."""

    def __init__(self, limit=5, window=900, max_keys=10000, clock=time.monotonic):
        self.limit, self.window, self.max_keys, self.clock = limit, window, max_keys, clock
        self._f = {}

    def _prune(self, key, now):
        q = self._f.get(key)
        while q and now - q[0] >= self.window:
            q.popleft()
        if q is not None and not q:
            del self._f[key]
        return self._f.get(key)

    def check(self, key):
        now = self.clock()
        q = self._prune(key, now)
        return int(self.window - (now - q[0])) + 1 if q and len(q) >= self.limit else 0

    def fail(self, key):
        now = self.clock()
        if key not in self._f and len(self._f) >= self.max_keys:   # bound memory: forget the oldest key
            self._f.pop(next(iter(self._f)))
        self._f.setdefault(key, deque()).append(now)

    def clear(self, key):
        self._f.pop(key, None)
