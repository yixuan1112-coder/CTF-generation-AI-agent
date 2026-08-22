"""Reference solver: follow the real two-step protocol, ignore the injected noise."""
import socket
import sys


def main(host, port):
    s = socket.create_connection((host, port), timeout=15)
    s.recv(65536)                                   # banner (ignored)
    s.sendall(b"GET TOKEN\n")
    buf = b""
    while b"TOKEN " not in buf:
        buf += s.recv(4096)
    token = buf.split(b"TOKEN ", 1)[1].split(b"\n", 1)[0].strip().decode()
    s.sendall(b"REDEEM " + token[::-1].encode() + b"\n")
    buf = b""
    while b"FLAG " not in buf:
        buf += s.recv(4096)
    print(buf.split(b"FLAG ", 1)[1].split(b"\n", 1)[0].strip().decode())


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
