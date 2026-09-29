#!/usr/bin/env python3
"""Generate .env with a fresh JWT secret and one scoped token per tenant.

Usage:
    pip install pyjwt --break-system-packages   # once
    python3 scripts/setup_env.py [--hours 12]

Re-run any time to rotate the secret and re-mint all tokens (e.g. once the
default 12h expiry has passed) - existing containers need a restart after,
since they only read .env at startup.
"""
import argparse
import secrets
import time

import jwt

SCOPES = {
    "red":   ["test:submit", "test:conclude"],
    "blue":  ["test:list", "test:read", "test:defend"],
    "admin": ["audit:read"],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=12, help="token lifetime")
    args = ap.parse_args()

    secret = secrets.token_hex(32)
    now = int(time.time())
    lines = [f"JWT_SECRET={secret}", "SANDBOX_RUNTIME=runsc"]
    for tenant, scope in SCOPES.items():
        claims = {"sub": tenant, "scope": scope, "iat": now, "exp": now + int(args.hours * 3600)}
        token = jwt.encode(claims, secret, algorithm="HS256")
        lines.append(f"{tenant.upper()}_TOKEN={token}")

    with open(".env", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote .env - tokens valid for {args.hours} hours.")
    print("Run `docker compose up -d --build` (or `restart`) to pick it up.")


if __name__ == "__main__":
    main()
