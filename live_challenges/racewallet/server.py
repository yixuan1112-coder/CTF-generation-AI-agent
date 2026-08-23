"""Race Wallet — a live HTTP service with a TOCTOU double-spend flaw.

You start with 10 credits; the flag costs 100. A one-time welcome coupon adds 40.
Redeemed once, that leaves you at 50 — not enough, and a second redeem is refused
because the coupon is marked used. But `POST /redeem` checks "already used?" and
sets the used flag on opposite sides of a deliberate slow write: fire several
`/redeem` requests concurrently and each passes the check before any marks the
coupon used, stacking +40 several times. Climb past 100 that way, then `POST /buy`
the flag legitimately.

Sequential play tops out at 50 and loses. Only overlapping requests win. Line-
oriented JSON, no libraries.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")
PRICE = 100
COUPON = 40

state = {"balance": 10, "coupon_used": False, "owned": False}
# A lock guards each individual read/write so the counter never corrupts — but it
# is NOT held across the check-then-act, and that gap is the whole vulnerability.
_lock = threading.Lock()


def try_redeem():
    with _lock:
        already = state["coupon_used"]            # ---- TIME OF CHECK
    if already:
        return False, state["balance"]
    time.sleep(0.05)                              # slow write: the race window
    with _lock:                                    # ---- TIME OF USE
        state["balance"] += COUPON
        state["coupon_used"] = True
        bal = state["balance"]
    return True, bal


def try_buy():
    with _lock:
        if state["balance"] >= PRICE and not state["owned"]:
            state["balance"] -= PRICE
            state["owned"] = True
            return True, state["balance"]
        return False, state["balance"]


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
        if self.path.rstrip("/") == "":
            self._send(200, {
                "service": "racewallet",
                "balance": state["balance"],
                "price": PRICE,
                "coupon": COUPON,
                "hint": "POST /redeem for a one-time +40 coupon, then POST /buy the flag.",
            })
            return
        if self.path == "/balance":
            self._send(200, {"balance": state["balance"], "owned": state["owned"]})
            return
        self._send(404, {"error": "no such path"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            self.rfile.read(length)
        if self.path == "/redeem":
            ok, bal = try_redeem()
            self._send(200 if ok else 409,
                       {"redeemed": ok, "balance": bal,
                        **({} if ok else {"error": "coupon already used"})})
            return
        if self.path == "/buy":
            ok, bal = try_buy()
            if ok:
                self._send(200, {"purchased": True, "balance": bal, "flag": FLAG})
            else:
                self._send(402, {"purchased": False, "balance": bal,
                                 "error": "insufficient credits"})
            return
        self._send(404, {"error": "no such path"})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"racewallet listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
