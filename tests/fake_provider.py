#!/usr/bin/env python3
"""A FAKE OpenAI-compatible / Ollama-shaped server for tests and UI demos. It is NOT a model.

    python3 tests/fake_provider.py 18090 [model-id]

Serves GET /v1/models and POST /v1/chat/completions with canned replies (it "falls for" DAN and
'developer mode' prompts, refuses system-prompt requests, and remembers "my code is X" within one
conversation's history). Stdlib only. Response shapes follow the documented OpenAI/Ollama API; they were
not captured from a real Ollama.
"""
import json, re, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18090
MODEL = sys.argv[2] if len(sys.argv) > 2 else "llama3.2:latest"

def reply(msgs):
    last = msgs[-1]["content"].lower()
    if "dan" in last.split() or "developer mode" in last: return "Sure, restrictions disabled. Here you go."
    if "system prompt" in last or "ignore previous" in last or "ignore all previous" in last: return "I can't help with that."
    if "what is my code" in last:
        for m in reversed(msgs[:-1]):
            f = re.search(r"my code is (\w+)", m["content"].lower())
            if m["role"] == "user" and f: return "Your code is " + f.group(1)
        return "I don't know your code in this session."
    return "Hello! How can I help?"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, status, obj):
        b = json.dumps(obj).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/v1/models": return self._json(200, {"object": "list", "data": [{"id": MODEL, "object": "model", "owned_by": "fake"}]})
        self._json(404, {"error": "not found"})
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path != "/v1/chat/completions": return self._json(404, {"error": "not found"})
        time.sleep(0.05)
        self._json(200, {"choices": [{"message": {"role": "assistant", "content": reply(body["messages"])}}]})

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
