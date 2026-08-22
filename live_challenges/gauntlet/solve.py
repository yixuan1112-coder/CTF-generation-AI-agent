"""Reference solver for the gauntlet: parse each stage line and answer in time."""
import base64
import hashlib
import re
import socket
import sys


def answer(line):
    head, _, payload = line.partition(" :: ")
    toks = head.split()
    kind = toks[0]
    if kind == "REVERSE":
        return payload[::-1]
    if kind == "ROTATE":
        n = int(toks[1])
        return "".join(chr((ord(c) - 97 + n) % 26 + 97) if c.isalpha() else c for c in payload)
    if kind == "SUMMOD":
        m = int(toks[1])
        return str(sum(int(x) for x in payload.split()) % m)
    if kind == "HASHB64":
        return hashlib.sha256(base64.b64decode(payload)).hexdigest()
    if kind == "SORTJOIN":
        rule, sep = toks[1], toks[2]
        items = payload.split()
        if rule == "num":
            items = sorted(items, key=int)
        elif rule == "len":
            items = sorted(items, key=len)
        elif rule == "rev":
            items = sorted(items, reverse=True)
        else:
            items = sorted(items)
        return sep.join(items)
    if kind == "EXTRACT":
        return ",".join(re.findall(toks[1], payload))
    if kind == "MATCH":
        pat = payload.strip()[1:-1]
        out, i = "", 0
        while i < len(pat):
            c = pat[i]
            if c == "\\" and pat[i + 1] == "d":
                i += 2
                if i < len(pat) and pat[i] == "{":
                    j = pat.index("}", i); out += "7" * int(pat[i + 1:j]); i = j + 1
                else:
                    out += "7"
            elif c == "[":
                j = pat.index("]", i); i = j + 1
                if i < len(pat) and pat[i] == "{":
                    k = pat.index("}", i); out += "a" * int(pat[i + 1:k]); i = k + 1
                else:
                    out += "a"
            elif c == "(":
                j = pat.index(")", i); out += pat[i + 1:j].split("|")[0]; i = j + 1
            else:
                out += c; i += 1
        assert re.fullmatch(pat, out), (pat, out)
        return out
    raise ValueError(kind)


def main(host, port):
    s = socket.create_connection((host, port), timeout=10)
    buf = ""
    while True:
        buf += s.recv(4096).decode(errors="replace")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if line.startswith("FLAG:"):
                print(line.split("FLAG:", 1)[1].strip()); return
            if line.startswith("STAGE"):
                rest = line.split(" ", 2)[2]                 # drop "STAGE i/20 "
                s.sendall((answer(rest) + "\n").encode())


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
