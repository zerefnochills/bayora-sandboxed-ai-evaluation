"""Scoped-JWT ABAC for the gateway.

Each token carries `sub` (which tenant issued it: red/blue/admin) and
`scope` (the specific actions it grants, e.g. "test:submit"). Every route
declares the scope it needs; the gateway checks the token's scope list, not
a hardcoded role name. That's the actual difference from week 1's static
per-tenant tokens: a token's *permissions* are data on the token, not an
identity lookup - so tightening or splitting a tenant's access later is a
change to what gets minted, not to the route logic.

Tokens are short-lived (12h default, see scripts/setup_env.py) and signed
with a single shared HMAC secret. That's a deliberate PoC simplification:
one trust root, one verifier. A production version would hand each tenant
its own signing identity so the gateway can revoke one without re-minting
the others.
"""
import os
import time
from typing import Optional

import jwt
from fastapi import HTTPException

ALGO = "HS256"
SECRET = os.environ["JWT_SECRET"]


class Principal:
    __slots__ = ("sub", "scope", "claims")

    def __init__(self, sub: str, scope: list, claims: Optional[dict] = None):
        self.sub = sub
        self.scope = set(scope)
        self.claims = claims or {}


def verify(authorization: Optional[str]) -> Principal:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization[7:]
    try:
        claims = jwt.decode(token, SECRET, algorithms=[ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "invalid token")
    sub = claims.get("sub")
    scope = claims.get("scope")
    if not sub or not isinstance(scope, list):
        raise HTTPException(401, "malformed token")
    return Principal(sub, scope, claims)


def require(authorization: Optional[str], needed_scope: str, audit=None) -> Principal:
    p = verify(authorization)
    if needed_scope not in p.scope:
        if audit is not None:
            audit.append("policy_violation", p.sub, {"needed_scope": needed_scope, "held_scope": sorted(p.scope)})
        raise HTTPException(403, "token lacks required scope: " + needed_scope)
    return p
