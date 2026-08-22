"""Padding Oracle — a live AES-CBC padding-oracle service.

On connect the server sends one target ciphertext (IV || C) that encrypts the flag
under a random per-connection key, then answers CHECK queries: it decrypts the
submitted ciphertext and tells you only whether the PKCS#7 padding is valid. That
single bit of leakage is enough to decrypt the target byte by byte (Vaudenay). The
flag never leaves the box in the clear — you recover it through the oracle.

Protocol (line-oriented, ASCII):
  server -> TARGET <hex(iv||c)>
  client -> CHECK <hex(iv||c)>      server -> VALID | INVALID
The recovered plaintext of the target is the flag.
"""
import os
import socket
import threading

from Crypto.Cipher import AES

BS = 16


def pkcs7_pad(data: bytes) -> bytes:
    p = BS - (len(data) % BS)
    return data + bytes([p]) * p


def pkcs7_valid(data: bytes) -> bool:
    if not data or len(data) % BS != 0:
        return False
    p = data[-1]
    return 1 <= p <= BS and data[-p:] == bytes([p]) * p


def handle(conn):
    key = os.urandom(32)
    iv = os.urandom(BS)
    flag = os.environ.get("FLAG", "flag{replace_at_deployment}").encode()
    ct = iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pkcs7_pad(flag))
    try:
        conn.settimeout(120)
        conn.sendall(b"TARGET " + ct.hex().encode() + b"\n")
        buf = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                if line.startswith(b"CHECK "):
                    try:
                        blob = bytes.fromhex(line[6:].decode())
                    except ValueError:
                        conn.sendall(b"INVALID\n")
                        continue
                    if len(blob) < 2 * BS or len(blob) % BS != 0:
                        conn.sendall(b"INVALID\n")
                        continue
                    civ, cbody = blob[:BS], blob[BS:]
                    pt = AES.new(key, AES.MODE_CBC, civ).decrypt(cbody)
                    conn.sendall(b"VALID\n" if pkcs7_valid(pt) else b"INVALID\n")
                else:
                    conn.sendall(b"ERR\n")
    except (socket.timeout, ConnectionError, OSError):
        return
    finally:
        conn.close()


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    print(f"padoracle listening on 0.0.0.0:{port}", flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
