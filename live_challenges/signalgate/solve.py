"""Reference solver for signalgate: HELLO -> derive AUTH from the nonce -> GETFLAG."""
import socket
import struct
import sys

MAGIC = bytes([0xA7, 0x47, 0x54])


def checksum(d):
    c = 0
    for b in d:
        c ^= b
    return c


def frame(op, payload=b""):
    head = MAGIC + bytes([1, op]) + struct.pack(">H", len(payload)) + payload
    return head + bytes([checksum(head)])


def read_frame(sock):
    head = recvn(sock, 7)
    op = head[4]
    length = struct.unpack(">H", head[5:7])[0]
    body = recvn(sock, length)
    recvn(sock, 1)
    return op, body


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        buf += sock.recv(n - len(buf))
    return buf


def main(host, port):
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(frame(0x01))
    op, nonce = read_frame(s)               # 0x81 + nonce
    resp = bytes(nonce[i] ^ MAGIC[i % 3] for i in range(4))
    s.sendall(frame(0x02, resp))
    op, _ = read_frame(s)                    # expect 0x82
    assert op == 0x82, f"auth failed: {op:#x}"
    s.sendall(frame(0x10))
    op, flag = read_frame(s)                 # 0x90 + flag
    print(flag.decode())


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
