"""Blind SQLi — a live HTTP service with a boolean-blind SQL injection.

`GET /user?name=<x>` looks an account up with a query built by string
concatenation:

    SELECT id FROM users WHERE name = '<x>'

and answers only `{"exists": true}` or `{"exists": false}` — one bit. That bit is
a boolean oracle: the flag lives in a separate `secret` table, and a subquery in
the injected condition leaks it one comparison at a time. A light filter rejects
`UNION`, comment markers and whitespace runs, so echo-based and UNION shortcuts
are out — you have to extract the flag character by character. That is the point:
script the oracle.

Stdlib only (sqlite3 + http.server).
"""
import json
import os
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")

_local = threading.local()


def db():
    if not hasattr(_local, "conn"):
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.executescript(
            "CREATE TABLE users(id INTEGER, name TEXT);"
            "INSERT INTO users VALUES (1,'alice'),(2,'bob'),(3,'carol');"
            "CREATE TABLE secret(flag TEXT);"
        )
        conn.execute("INSERT INTO secret VALUES (?)", (FLAG,))
        conn.commit()
        _local.conn = conn
    return _local.conn


# A crude "WAF": block the shortcuts (UNION, comments) and any whitespace, so a
# solver must extract the flag through the boolean oracle, not read it directly.
_BLOCK = re.compile(r"union|/\*|--|\s", re.IGNORECASE)


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
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, {
                "service": "sqli",
                "hint": "GET /user?name=<name> tells you only whether the account exists.",
                "note": "the flag is in table secret(flag); the filter blocks UNION, comments, whitespace",
            })
            return
        if u.path == "/user":
            name = parse_qs(u.query).get("name", [""])[0]
            if _BLOCK.search(name):
                self._send(403, {"error": "blocked by filter"})
                return
            # the injectable query — single quotes are NOT escaped
            q = "SELECT id FROM users WHERE name = '%s'" % name
            try:
                rows = db().execute(q).fetchall()
                self._send(200, {"exists": bool(rows)})
            except sqlite3.Error as e:
                self._send(200, {"exists": False, "sqlerror": str(e)})
            return
        self._send(404, {"error": "no such path"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"sqli listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
