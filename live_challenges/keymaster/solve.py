"""Recover the affine serial map over GF(2) from the factory log, then auth once."""
import socket
import sys

N = 64


def solve_bit(examples, j):
    # unknowns: a_0..a_{N-1}, b  (N+1). Each example: XOR_i a_i*id_i XOR b = serial_j.
    rows = []
    for did, ser in examples:
        eq = did | (1 << N)                       # bit N is the constant term
        rhs = (ser >> j) & 1
        rows.append((eq, rhs))
    where = [-1] * (N + 1)
    r = 0
    R = [list(x) for x in rows]
    for col in range(N + 1):
        piv = next((i for i in range(r, len(R)) if (R[i][0] >> col) & 1), None)
        if piv is None:
            continue
        R[r], R[piv] = R[piv], R[r]
        for i in range(len(R)):
            if i != r and (R[i][0] >> col) & 1:
                R[i][0] ^= R[r][0]
                R[i][1] ^= R[r][1]
        where[col] = r
        r += 1
    sol = 0
    for col in range(N + 1):
        if where[col] != -1 and R[where[col]][1]:
            sol |= 1 << col
    return sol                                    # bits 0..N-1 = a_i, bit N = b


def main(host, port):
    s = socket.create_connection((host, port), timeout=20)
    data = b""
    while b"TARGET" not in data:
        data += s.recv(65536)
    while not data.rstrip().endswith(b">") and b"TARGET " in data and b"\n" not in data.split(b"TARGET ", 1)[1]:
        data += s.recv(65536)
    examples, target = [], None
    for line in data.decode().splitlines():
        p = line.split()
        if p and p[0] == "PROV":
            examples.append((int(p[1], 16), int(p[2], 16)))
        elif p and p[0] == "TARGET":
            target = int(p[1], 16)
    coeffs = [solve_bit(examples, j) for j in range(N)]
    serial = 0
    for j in range(N):
        a = coeffs[j] & ((1 << N) - 1)
        b = (coeffs[j] >> N) & 1
        bit = (bin(a & target).count("1") & 1) ^ b
        serial |= bit << j
    s.sendall(b"AUTH " + serial.to_bytes(8, "big").hex().encode() + b"\n")
    resp = s.recv(4096).decode(errors="replace").strip()
    print(resp.split("FLAG ", 1)[1] if resp.startswith("FLAG ") else resp)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
