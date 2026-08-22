"""Signal Gate — a bespoke binary protocol over TCP. Blind-reverse it to the flag.

Frame:  MAGIC(3)=A7 47 54 | VERSION(1)=01 | OPCODE(1) | LEN(2 big-endian) |
        PAYLOAD(LEN) | CHECKSUM(1) = XOR of every preceding byte.

Opcodes the client may send:
  0x01 HELLO   -> server replies 0x81 with a fresh 4-byte session NONCE.
  0x02 AUTH    -> 4-byte payload; server replies 0x82 if it equals the expected
                  response for this session's nonce, else 0xEE (auth failed).
  0x10 GETFLAG -> replies 0x90 with the flag IF this session has authed, else 0xEE
                  (bad state).

The expected AUTH response is a deterministic function of the nonce. It is not a
secret algorithm — everything needed to derive it is observable by probing — but it
is not a standard one either. The flag never appears until a session HELLOs, AUTHs
correctly, then GETFLAGs.
"""
import os
import socket
import struct
import threading

MAGIC = bytes([0xA7, 0x47, 0x54])
VERSION = 1
FLAG = os.environ.get("FLAG", "flag{replace_at_deployment}").encode()
ERR_BADSTATE = 0x06
ERR_AUTH = 0x07
ERR_FRAME = 0x02


def _checksum(data: bytes) -> int:
    c = 0
    for b in data:
        c ^= b
    return c


def frame(opcode: int, payload: bytes) -> bytes:
    head = MAGIC + bytes([VERSION, opcode]) + struct.pack(">H", len(payload)) + payload
    return head + bytes([_checksum(head)])


def read_frame(conn) -> tuple[int, bytes] | None:
    head = _recvn(conn, 7)
    if not head or head[:3] != MAGIC or head[3] != VERSION:
        return None
    opcode = head[4]
    length = struct.unpack(">H", head[5:7])[0]
    body = _recvn(conn, length)
    chk = _recvn(conn, 1)
    if body is None or chk is None:
        return None
    if _checksum(head + body) != chk[0]:
        return "BADCHK", opcode
    return opcode, body


def _recvn(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def expected_response(nonce: bytes) -> bytes:
    # Not a standard transform: xor each nonce byte with the protocol MAGIC cycled
    # over it. The MAGIC is the only constant a prober already knows.
    return bytes(nonce[i] ^ MAGIC[i % len(MAGIC)] for i in range(len(nonce)))


def handle(conn, addr):
    nonce = None
    authed = False
    try:
        conn.settimeout(30)
        while True:
            r = read_frame(conn)
            if r is None:
                return
            if isinstance(r, tuple) and r[0] == "BADCHK":
                conn.sendall(frame(0xEE, bytes([ERR_FRAME])))
                continue
            opcode, body = r
            if opcode == 0x01:                       # HELLO
                nonce = os.urandom(4)
                authed = False
                conn.sendall(frame(0x81, nonce))
            elif opcode == 0x02:                     # AUTH
                if nonce is None:
                    conn.sendall(frame(0xEE, bytes([ERR_BADSTATE])))
                elif body == expected_response(nonce):
                    authed = True
                    conn.sendall(frame(0x82, b""))
                else:
                    conn.sendall(frame(0xEE, bytes([ERR_AUTH])))
            elif opcode == 0x10:                     # GETFLAG
                if authed:
                    conn.sendall(frame(0x90, FLAG))
                else:
                    conn.sendall(frame(0xEE, bytes([ERR_BADSTATE])))
            else:
                conn.sendall(frame(0xEE, bytes([ERR_FRAME])))
    except (socket.timeout, ConnectionError, OSError):
        return
    finally:
        conn.close()


def main():
    host, port = "0.0.0.0", int(os.environ.get("PORT", "9000"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    print(f"signalgate listening on {host}:{port}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
