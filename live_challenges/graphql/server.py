"""GraphQL — a live GraphQL API with an introspectable hidden field.

The public docs only mention `me` and `users`. But GraphQL exposes its whole
schema through introspection (`__schema`), and a leftover admin field —
`secretFlag`, guarded by a check that the query carries an internal debug
header — shows up there. Enumerate the schema, discover the hidden field and how
it is gated, and query it.

A small hand-written GraphQL engine (stdlib only): it supports selection sets,
the `__schema`/`__type` introspection meta-fields, and one gate. The flag comes
from the env.

    POST /graphql   {"query": "{ __schema { queryType { fields { name } } } }"}
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")

# The schema. `secretFlag` is intentionally undocumented but fully introspectable,
# and gated behind an internal debug header rather than real authorization.
FIELDS = {
    "me": {"type": "User", "desc": "the current (anonymous) user", "hidden": False},
    "users": {"type": "[User]", "desc": "list demo users", "hidden": False},
    "secretFlag": {"type": "String",
                   "desc": "DEBUG: returns the build flag when X-Debug: 1 is set",
                   "hidden": True, "gate": "x-debug"},
}
USERS = [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}]


def introspect_schema():
    return {"queryType": {"name": "Query",
                          "fields": [{"name": n,
                                      "description": f["desc"],
                                      "type": {"name": f["type"]}}
                                     for n, f in FIELDS.items()]}}


def parse_selection(query: str):
    # crude: pull the top-level field names inside the outermost braces
    m = re.search(r"\{(.*)\}", query, re.S)
    inner = m.group(1) if m else query
    names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", inner)
    return names


def resolve(query: str, headers) -> dict:
    names = parse_selection(query)
    data, errors = {}, []
    for name in names:
        if name in ("__schema", "queryType", "fields", "name", "description",
                    "type", "id"):
            if name == "__schema":
                data["__schema"] = introspect_schema()
            continue
        if name not in FIELDS:
            errors.append(f"Cannot query field '{name}' on type 'Query'")
            continue
        f = FIELDS[name]
        if name == "me":
            data["me"] = {"id": 0, "name": "anonymous"}
        elif name == "users":
            data["users"] = USERS
        elif name == "secretFlag":
            if headers.get(f["gate"], "") == "1":
                data["secretFlag"] = FLAG
            else:
                errors.append("secretFlag requires the internal debug header (X-Debug: 1)")
    out = {"data": data}
    if errors:
        out["errors"] = [{"message": e} for e in errors]
    return out


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
                "service": "graphql",
                "endpoint": "POST /graphql {\"query\": \"...\"}",
                "docs": "public fields: me, users",
                "hint": "introspection is on — enumerate __schema for everything",
            })
            return
        self._send(404, {"error": "no such path"})

    def do_POST(self):
        if self.path != "/graphql":
            self._send(404, {"error": "no such path"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            query = str(body.get("query", ""))
        except Exception:
            self._send(400, {"errors": [{"message": "invalid JSON body"}]})
            return
        hdrs = {k.lower(): v for k, v in self.headers.items()}
        self._send(200, resolve(query, hdrs))


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"graphql listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
