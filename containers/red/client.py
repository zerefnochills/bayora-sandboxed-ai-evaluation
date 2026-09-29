"""Red-team client. Runs inside the red container; can only reach the gateway.

  python client.py submit "<prompt>"
  python client.py conclude <test_id>
  python client.py peek-blue          # policy check: should be 403
"""
import json
import os
import sys

import httpx

GATEWAY = os.environ.get("GATEWAY_URL", "http://gateway:8080")
HEADERS = {"Authorization": f"Bearer {os.environ['RED_TOKEN']}"}


def call(method, path, **kw):
    r = httpx.request(method, GATEWAY + path, headers=HEADERS, timeout=20, **kw)
    try:
        body = r.json()
    except ValueError:
        body = r.text
    print(json.dumps({"status": r.status_code, "body": body}))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "submit":
        call("POST", "/red/tests", json={"prompt": " ".join(sys.argv[2:])})
    elif cmd == "conclude":
        call("POST", f"/red/tests/{sys.argv[2]}/conclude")
    elif cmd == "peek-blue":
        call("GET", "/blue/tests")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
