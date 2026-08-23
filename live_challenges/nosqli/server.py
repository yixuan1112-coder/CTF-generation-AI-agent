"""NoSQL Injection — a live login with MongoDB-style operator injection.

`POST /login` takes a JSON body `{"user": ..., "pass": ...}` and looks the user
up in a Mongo-like store by passing the JSON straight into the query. The query
engine honours operator objects (`$ne`, `$gt`, `$regex`, ...), so a value like
`{"$ne": null}` matches anything — classic NoSQL auth bypass. Log in as `admin`
without knowing the password and the flag is returned. The admin password is
random per instance, so guessing is out; injection is the way.

    {"user": "admin", "pass": {"$ne": ""}}          # bypass the password check

Stdlib only. The flag is in the env.
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")

DOCS = [
    {"user": "admin", "pass": os.urandom(12).hex(), "role": "admin"},
    {"user": "guest", "pass": "guest", "role": "user"},
]


def match_field(cond, value):
    """A tiny Mongo-style matcher: operator objects are honoured, else equality."""
    if isinstance(cond, dict):
        for op, arg in cond.items():
            if op == "$ne" and not (value != arg):
                return False
            elif op == "$eq" and not (value == arg):
                return False
            elif op == "$gt" and not (value > arg):
                return False
            elif op == "$in" and value not in (arg or []):
                return False
            elif op == "$regex":
                if not re.search(str(arg), str(value)):
                    return False
            elif op not in ("$ne", "$eq", "$gt", "$in", "$regex"):
                return False
        return True
    return value == cond


def find_one(query):
    for doc in DOCS:
        if all(match_field(query.get(k), doc.get(k)) for k in query):
            return doc
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode() + b"\n"
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            self._send(200, {
                "service": "nosqli",
                "endpoint": "POST /login  {\"user\": \"...\", \"pass\": \"...\"}",
                "note": "log in as admin to get the flag; the query trusts your JSON",
            })
            return
        self._send(404, {"error": "no such path"})

    def do_POST(self):
        if self.path != "/login":
            self._send(404, {"error": "no such path"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        try:
            query = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(query, dict):
                raise ValueError
        except Exception:
            self._send(400, {"error": "invalid JSON body"})
            return
        # only user/pass are queryable
        query = {k: query[k] for k in ("user", "pass") if k in query}
        doc = find_one(query)
        if doc and doc.get("role") == "admin":
            self._send(200, {"ok": True, "user": doc["user"], "flag": FLAG})
        elif doc:
            self._send(200, {"ok": True, "user": doc["user"], "role": doc["role"],
                             "note": "logged in, but not admin"})
        else:
            self._send(401, {"ok": False, "error": "invalid credentials"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"nosqli listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
