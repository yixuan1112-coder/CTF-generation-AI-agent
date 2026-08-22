"""Keymaster — a no-oracle serial validator.

Wrong serials get a uniform ACCESS DENIED with no per-byte feedback, and each
connection allows exactly one attempt against a fresh target, so probing buys
nothing: the serial cannot be brute-forced, it must be DERIVED. The device speaks
a provisioning protocol first — it prints many (device_id, serial) pairs from its
own factory log — and the serial is a fixed but unknown affine function of the id
over GF(2). Recover that function from the log, apply it to the target id, and
authenticate in one shot.

Protocol (line-oriented, ASCII):
  server -> PROV <id_hex> <serial_hex>     (repeated; the factory log)
  server -> TARGET <id_hex>
  client -> AUTH <serial_hex>              server -> FLAG <flag> | ACCESS DENIED
"""
import os
import secrets
import socket
import threading

N = 64                        # bits in a device id / serial (8 bytes)
EXAMPLES = 80                 # more than enough to pin a 64-input affine map


def _rows_and_const():
    rows = [secrets.randbits(N) for _ in range(N)]     # M: N rows of N bits
    const = secrets.randbits(N)                        # the fixed key (offset)
    return rows, const


def apply_map(rows, const, x):
    out = 0
    for j in range(N):
        bit = (bin(rows[j] & x).count("1") & 1) ^ ((const >> j) & 1)
        out |= bit << j
    return out


def hx(v):
    return v.to_bytes(8, "big").hex()


def handle(conn):
    rows, const = _rows_and_const()
    flag = os.environ.get("FLAG", "flag{replace_at_deployment}")
    try:
        conn.settimeout(60)
        lines = []
        for _ in range(EXAMPLES):
            did = secrets.randbits(N)
            lines.append(f"PROV {hx(did)} {hx(apply_map(rows, const, did))}")
        target = secrets.randbits(N)
        lines.append(f"TARGET {hx(target)}")
        conn.sendall(("\n".join(lines) + "\n").encode())

        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 4096:
                return
        line = buf.split(b"\n", 1)[0].strip().decode(errors="replace")
        ok = False
        if line.startswith("AUTH "):
            try:
                cand = int.from_bytes(bytes.fromhex(line[5:].strip()), "big")
                ok = cand == apply_map(rows, const, target)
            except ValueError:
                ok = False
        conn.sendall((f"FLAG {flag}\n" if ok else "ACCESS DENIED\n").encode())
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
    print(f"keymaster listening on 0.0.0.0:{port}", flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
