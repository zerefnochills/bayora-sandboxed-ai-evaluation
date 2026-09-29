"""Blue-team client. Runs inside the blue container; can only reach the gateway.

  python client.py list
  python client.py read <test_id>     # 403 until red concludes the test
  python client.py defend <test_id> "<note>"
  python client.py peek-red           # policy check: should be 403
"""
import json
import os
import sys

import httpx

GATEWAY = os.environ.get("GATEWAY_URL", "http://gateway:8080")
HEADERS = {"Authorization": f"Bearer {os.environ['BLUE_TOKEN']}"}


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
    if cmd == "list":
        call("GET", "/blue/tests")
    elif cmd == "read":
        call("GET", f"/blue/tests/{sys.argv[2]}")
    elif cmd == "defend":
        call("POST", f"/blue/tests/{sys.argv[2]}/defense", json={"note": " ".join(sys.argv[3:])})
    elif cmd == "peek-red":
        call("POST", "/red/tests", json={"prompt": "x"})
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
