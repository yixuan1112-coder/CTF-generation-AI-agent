"""The Gauntlet — a timed, multi-stage challenge-response over TCP.

Twenty stages, one connection, a tight per-stage clock. Each stage prints a line

    STAGE <i>/20 <TYPE> [args] :: <payload>

and expects exactly one answer line back before the window closes. Wrong answer or
too slow ends the run. Clear all twenty and the flag prints. Manual play is
hopeless; the stage grammar has to be reversed and answered by a script, and every
one of the stage types has to be handled — the run visits all of them.
"""
import base64
import hashlib
import os
import random
import re
import socket
import threading

FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}")
STAGES = 20
PER_STAGE_TIMEOUT = 2.0

WORDS = ["storm", "gale", "squall", "tempest", "cyclone", "gust", "zephyr", "monsoon"]


def make_stage(rng, i):
    kinds = (["REVERSE", "ROTATE", "SUMMOD"] if i < 7
             else ["HASHB64", "SORTJOIN", "SUMMOD", "REVERSE"] if i < 14
             else ["EXTRACT", "MATCH", "HASHB64", "SORTJOIN"])
    kind = rng.choice(kinds)
    if kind == "REVERSE":
        s = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rng.randint(8, 20)))
        return f"REVERSE :: {s}", s[::-1]
    if kind == "ROTATE":
        n = rng.randint(1, 25)
        s = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(8, 16)))
        ans = "".join(chr((ord(c) - 97 + n) % 26 + 97) for c in s)
        return f"ROTATE {n} :: {s}", ans
    if kind == "SUMMOD":
        m = rng.randint(7, 9999)
        xs = [rng.randint(-500, 500) for _ in range(rng.randint(4, 12))]
        return f"SUMMOD {m} :: {' '.join(map(str, xs))}", str(sum(xs) % m)
    if kind == "HASHB64":
        raw = os.urandom(rng.randint(6, 24))
        b = base64.b64encode(raw).decode()
        return f"HASHB64 :: {b}", hashlib.sha256(raw).hexdigest()
    if kind == "SORTJOIN":
        rule = rng.choice(["alpha", "rev", "len", "num"])
        sep = rng.choice([",", "-", "|"])
        if rule == "num":
            toks = [str(rng.randint(0, 9999)) for _ in range(rng.randint(4, 9))]
            ans = sep.join(sorted(toks, key=int))
        elif rule == "len":
            toks = list(dict.fromkeys(rng.sample(WORDS, rng.randint(4, len(WORDS)))))
            ans = sep.join(sorted(toks, key=len))
        else:
            toks = [rng.choice(WORDS) + str(rng.randint(0, 99)) for _ in range(rng.randint(4, 8))]
            ans = sep.join(sorted(toks, reverse=(rule == "rev")))
        return f"SORTJOIN {rule} {sep} :: {' '.join(toks)}", ans
    if kind == "EXTRACT":
        text = " ".join(rng.choice(WORDS) + str(rng.randint(0, 999)) for _ in range(rng.randint(6, 12)))
        pat = rng.choice([r"\d+", r"[a-z]+\d+", r"s[a-z]+", r"\d{2,}"])
        return f"EXTRACT {pat} :: {text}", ",".join(re.findall(pat, text))
    # MATCH: produce any string that fullmatches the regex
    atoms = []
    ans = []
    for _ in range(rng.randint(2, 4)):
        a = rng.choice(["lit", "d", "cls", "alt"])
        if a == "lit":
            lit = "".join(rng.choice("abcdef") for _ in range(rng.randint(2, 4)))
            atoms.append(re.escape(lit)); ans.append(lit)
        elif a == "d":
            n = rng.randint(2, 4); atoms.append(r"\d{" + str(n) + "}"); ans.append("7" * n)
        elif a == "cls":
            n = rng.randint(2, 3); atoms.append("[a-z]{" + str(n) + "}"); ans.append("a" * n)
        else:
            atoms.append("(storm|gale)"); ans.append("storm")
    return f"MATCH :: ^{''.join(atoms)}$", "".join(ans)


def handle(conn):
    rng = random.Random(os.urandom(8))
    try:
        conn.settimeout(PER_STAGE_TIMEOUT)
        conn.sendall(f"THE GAUNTLET :: {STAGES} stages, {PER_STAGE_TIMEOUT}s each. Answer each line.\n".encode())
        for i in range(STAGES):
            line, answer = make_stage(rng, i)
            conn.sendall(f"STAGE {i}/{STAGES} {line}\n".encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
                if len(data) > 65536:
                    return
            if data.decode(errors="replace").strip() != answer:
                conn.sendall(b"WRONG.\n")
                return
        conn.sendall(f"STORM CLEARED.\nFLAG: {FLAG}\n".encode())
    except (socket.timeout, ConnectionError, OSError):
        try:
            conn.sendall(b"TOO SLOW.\n")
        except OSError:
            pass
    finally:
        conn.close()


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    print(f"gauntlet listening on 0.0.0.0:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
