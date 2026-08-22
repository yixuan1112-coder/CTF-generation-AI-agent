"""Reference padding-oracle attack: recover the target plaintext one byte at a time."""
import socket
import sys

BS = 16


class Oracle:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=20)
        self.buf = b""
        self.target = bytes.fromhex(self._line().split(b" ", 1)[1].decode())

    def _line(self):
        while b"\n" not in self.buf:
            self.buf += self.s.recv(65536)
        line, self.buf = self.buf.split(b"\n", 1)
        return line.strip()

    def valid(self, blob: bytes) -> bool:
        self.s.sendall(b"CHECK " + blob.hex().encode() + b"\n")
        return self._line() == b"VALID"


def decrypt_block(o, prev, cur):
    inter = bytearray(BS)
    recovered = bytearray(BS)
    for pad in range(1, BS + 1):
        pos = BS - pad
        prefix = bytes(os.urandom(pos)) if False else bytes(pos)
        for guess in range(256):
            forged = bytearray(prefix) + bytes([guess]) + bytes(
                inter[BS - pad + 1 + k] ^ pad for k in range(pad - 1))
            if o.valid(bytes(forged) + cur):
                # guard against the false-positive where pad byte lands earlier
                if pad == 1:
                    probe = bytearray(forged)
                    probe[pos - 1] ^= 1
                    if not o.valid(bytes(probe) + cur):
                        continue
                inter[pos] = guess ^ pad
                recovered[pos] = inter[pos] ^ prev[pos]
                break
        else:
            raise RuntimeError("no valid byte found")
    return bytes(recovered)


import os  # noqa: E402


def main(host, port):
    o = Oracle(host, port)
    ct = o.target
    blocks = [ct[i:i + BS] for i in range(0, len(ct), BS)]
    out = b""
    for i in range(1, len(blocks)):
        out += decrypt_block(o, blocks[i - 1], blocks[i])
    pad = out[-1]
    print(out[:-pad].decode(errors="replace"))


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
