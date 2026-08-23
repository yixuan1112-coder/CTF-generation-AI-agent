"""Reference solver for ecboracle: byte-at-a-time ECB with an unknown prefix.

    python3 solve.py <host> <port>

1) confirm block size 16 and ECB (a doubled block repeats in the ciphertext),
2) recover the fixed prefix length,
3) recover FLAG one byte at a time by aligning the next unknown byte at the end
   of a controlled block and matching it against a dictionary.
"""
import json
import sys
import urllib.parse
import urllib.request

BS = 16


def make_oracle(base):
    def oracle(data: bytes) -> bytes:
        q = base + "/encrypt?data=" + data.hex()
        return bytes.fromhex(json.loads(urllib.request.urlopen(q, timeout=15).read())["ct"])
    return oracle


def blocks(b):
    return [b[i:i + BS] for i in range(0, len(b), BS)]


def prefix_len(oracle):
    # find how many identical bytes we must inject before two consecutive
    # ciphertext blocks repeat; from that, derive the prefix length.
    base_len = len(oracle(b""))
    for pad in range(0, BS + 1):
        probe = bytes([0x41]) * (pad + 2 * BS)
        bs = blocks(oracle(probe))
        for i in range(len(bs) - 1):
            if bs[i] == bs[i + 1]:
                # block i is the first fully-attacker-controlled block
                return i * BS - pad
    raise RuntimeError("could not determine prefix length")


def main():
    host, port = sys.argv[1], sys.argv[2]
    oracle = make_oracle(f"http://{host}:{port}")

    plen = prefix_len(oracle)
    pad_to_block = (-plen) % BS               # bytes to push our input to a boundary
    start = plen + pad_to_block               # our controlled bytes begin at this offset

    recovered = bytearray()
    while True:
        block_index = (start + len(recovered)) // BS
        # filler so the next unknown byte is the last of block `block_index`
        fill = pad_to_block + (BS - 1 - (len(recovered) % BS))
        prefix = bytes([0x41]) * fill
        target = blocks(oracle(prefix))[block_index]
        found = None
        for guess in range(256):
            probe = prefix + bytes(recovered) + bytes([guess])
            if blocks(oracle(probe))[block_index] == target:
                found = guess
                break
        if found is None or found == 0x01:    # hit PKCS#7 padding -> done
            break
        recovered.append(found)
        if recovered.endswith(b"}") and recovered.startswith(b"flag{"):
            break

    flag = bytes(recovered).split(b"\x00")[0].decode(errors="replace")
    print(flag)


if __name__ == "__main__":
    main()
