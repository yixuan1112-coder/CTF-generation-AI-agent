"""Physical-layer decode rungs, modelled on the cases an agent evaluation showed
were hard: a synthetic RF beacon and BLE-whitened telemetry.

In that evaluation the agent demodulated a beacon's framing correctly but never
recovered the payload's final encoding, and it got a whitened sensor feed to the
right neighbourhood but not the exact transform. Both failures are the same shape:
the signal processing is doable, and the last decode step — the one that is not a
standard library call — is where it stalls. These rungs reproduce that shape.

  beacon    An on-off-keyed, Manchester-coded beacon captured to a WAV. Recovering
            the payload means demodulating the envelope, finding the sync word,
            Manchester-decoding, and then undoing a payload whitening that the flag
            prefix reveals. No off-the-shelf tool does the whole chain.

  blewhiten A run of BLE advertising packets, their payloads run through Bluetooth's
            data-whitening LFSR under an unknown channel. One packet carries the
            flag; the rest are decoys. Recovering it means re-implementing the
            whitening LFSR and finding the channel that de-whitens to a flag.

Neither writes the flag into a player artifact — it is whitened or buried in the
signal.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import random
import struct
import wave

from .identity import challenge_flag


def _spec(*, slug, title, category, challenge_type, story, vulnerability, solution,
          artifacts, solver_files, flag, seed, generation, attack_class, rank,
          max_runtime_s, flag_secret, difficulty="hard"):
    from .models import ChainStep, ChallengeSpec, Lineage, OfficialSolver
    expected = hashlib.sha256(flag.encode()).hexdigest()
    return ChallengeSpec(
        slug=slug, title=f"{title} (Gen-{generation})", category=category,
        challenge_type=challenge_type, difficulty=difficulty, story=story,
        vulnerability=vulnerability, intended_solution=solution, hints=[],
        delivery="crypto", seed=seed,
        mechanics={"attack_class": attack_class, "rank": rank},
        flag=flag, spec_id=slug,
        lineage=Lineage(archetype_id=f"signals.{attack_class}", generation=generation,
                        parent_spec_id=None, mutation_ops=[], seed=seed),
        vuln_chain=[ChainStep(step=1, primitive=f"{attack_class}_stage",
                              params={}, guard=category)],
        artifacts=artifacts,
        official_solver=OfficialSolver(entry="solver.py", files=solver_files,
                                       expected_flag_sha256=expected,
                                       max_runtime_s=max_runtime_s),
        target_solve_rate=0.03)


def _slug(kind, flag_secret, seed, generation):
    tag = hashlib.sha256(f"{kind}:{flag_secret}:{seed}:{generation}".encode()).hexdigest()[:8]
    return f"sig-{kind}-g{generation}-{tag}"


# ---------------------------------------------------------------------------
# beacon — OOK / Manchester WAV, whitened payload
# ---------------------------------------------------------------------------
BEACON_FS = 8000
BEACON_CHIP = 10               # samples per chip; a bit is two chips (Manchester)
BEACON_PREAMBLE = b"\xAA\xAA"
BEACON_WHITEN_LEN = 5

_BEACON_SOLVER = '''\
"""Decode an OOK/Manchester beacon WAV and undo its payload whitening.

Four steps, none a single library call. Take the sample envelope (absolute value)
and threshold it at half the peak to get the on/off chip stream. A bit is two
chips, Manchester-coded: (on,off) is a 1 and (off,on) is a 0, and the inter-burst
silence breaks that pattern, which ends a burst. Find the 0xAAAA sync word in the
chip stream, decode the bits after it into bytes, and drop the sync.

What is left is not printable, because the payload is whitened: XORed with a short
repeating pad. The flag begins `flag{`, so XOR the first five payload bytes with
`flag{` to recover the pad, then XOR it across the whole payload.
"""
import base64
import io
import struct
import wave

raw = base64.b64decode("".join(open("capture.wav.b64", encoding="utf-8").read().split()))
w = wave.open(io.BytesIO(raw), "rb")
n = w.getnframes()
samples = list(struct.unpack("<%dh" % n, w.readframes(n)))

CHIP = 10
env = [abs(s) for s in samples]
thr = max(env) // 2
chip_bits = []
for i in range(0, len(env) - CHIP + 1, CHIP):
    window = env[i:i + CHIP]
    chip_bits.append(1 if sum(1 for e in window if e > thr) > CHIP // 2 else 0)


def manchester_chips(databits):
    out = []
    for b in databits:
        out += [1, 0] if b else [0, 1]
    return out


pre_bits = [(b >> k) & 1 for b in b"\\xAA\\xAA" for k in range(7, -1, -1)]
pre_chips = manchester_chips(pre_bits)
off = next(o for o in range(len(chip_bits) - len(pre_chips))
           if chip_bits[o:o + len(pre_chips)] == pre_chips)

databits, j = [], off
while j + 2 <= len(chip_bits):
    a, b = chip_bits[j], chip_bits[j + 1]
    if (a, b) == (1, 0):
        databits.append(1)
    elif (a, b) == (0, 1):
        databits.append(0)
    else:
        break
    j += 2

frame = bytes(int("".join(str(x) for x in databits[k:k + 8]), 2)
              for k in range(0, len(databits) - 7, 8))
payload = frame[2:]                          # drop the 0xAAAA sync

pad = bytes(payload[i] ^ b"flag{"[i] for i in range(5))
flag = bytes(payload[i] ^ pad[i % len(pad)] for i in range(len(payload)))
end = flag.find(b"}")
print(flag[:end + 1].decode())
'''


def _beacon_manchester(databits):
    out = []
    for b in databits:
        out += [1, 0] if b else [0, 1]
    return out


def gen_beacon(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="beacon", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"beacon:{flag_secret}:{seed}:{generation}")

    pad = bytes(rng.randrange(256) for _ in range(BEACON_WHITEN_LEN))
    fb = flag.encode()
    whitened = bytes(fb[i] ^ pad[i % len(pad)] for i in range(len(fb)))
    frame = BEACON_PREAMBLE + whitened
    databits = [(byte >> k) & 1 for byte in frame for k in range(7, -1, -1)]
    chips = _beacon_manchester(databits)

    samples = []
    for _ in range(3):                       # three repeated bursts with gaps
        for c in chips:
            amp = 12000 if c else 0
            for _ in range(BEACON_CHIP):
                samples.append(amp + rng.randint(-180, 180))
        samples += [rng.randint(-180, 180) for _ in range(BEACON_CHIP * 8)]

    buf = io.BytesIO()
    w = wave.open(buf, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(BEACON_FS)
    w.writeframes(b"".join(struct.pack("<h", max(-32000, min(32000, s))) for s in samples))
    w.close()
    encoded = base64.b64encode(buf.getvalue()).decode()

    artifacts = {
        "capture.wav.b64": "\n".join(encoded[i:i + 76]
                                     for i in range(0, len(encoded), 76)) + "\n",
        "README.md": (
            "# Beacon capture\n\n"
            "`capture.wav.b64` is a base64-wrapped WAV: an 8 kHz recording of a "
            "short-range beacon that keys a carrier on and off. The beacon repeats "
            "its burst a few times with silent gaps between. Recover the message it "
            "transmits — it is a flag of the usual `flag{...}` form.\n"),
    }
    return _spec(
        slug=_slug("beacon", flag_secret, seed, generation),
        title="Beacon Capture", category="forensics",
        challenge_type="ook-manchester-whitened",
        story=("A short-range beacon was recorded off the air to a WAV. It keys a "
               "carrier on and off and repeats its burst. The message is in the "
               "signal, not in any header."),
        vulnerability=("the flag rides an OOK/Manchester burst under a repeating whitening pad "
                       "that the known flag prefix recovers — a full demod-then-dewhiten chain"),
        solution=["threshold the envelope to on/off chips at half the peak",
                  "Manchester-decode: (on,off)=1, (off,on)=0, silence ends a burst",
                  "find the 0xAAAA sync word and pack the following bits to bytes",
                  "recover the whitening pad from the flag{ prefix and XOR it out"],
        artifacts=artifacts,
        solver_files={"solver.py": _BEACON_SOLVER},
        flag=flag, seed=seed, generation=generation, attack_class="beacon",
        rank=14, max_runtime_s=120, flag_secret=flag_secret)


# ---------------------------------------------------------------------------
# blewhiten — BLE data-whitening LFSR under an unknown channel
# ---------------------------------------------------------------------------
BLE_DECOYS = 30

_BLE_SOLVER = '''\
"""Find the flag in a run of BLE advertising packets by de-whitening them.

Bluetooth LE whitens every packet's PDU with a 7-bit LFSR (polynomial x^7 + x^4 +
1) seeded from the channel index, and whitening is its own inverse. The capture
does not record the channel, and only one packet is the flag; the rest are decoys.

So re-implement the whitening LFSR, and for each packet try every channel 0..39,
de-whiten, and keep the result that starts with `flag{`. The LFSR seed is the seven
bits [1, c5, c4, c3, c2, c1, c0]; each step emits the top bit, feeds it back into
the bottom, and taps position 4.
"""
import json


def whiten(data, channel):
    lfsr = [1] + [(channel >> i) & 1 for i in range(5, -1, -1)]
    out = bytearray()
    for byte in data:
        b = 0
        for bit in range(8):
            o = lfsr[6]
            b |= (((byte >> bit) & 1) ^ o) << bit
            lfsr = [o] + lfsr[0:6]
            lfsr[4] ^= o
        out.append(b)
    return bytes(out)


packets = [bytes.fromhex(p) for p in json.load(open("capture.json", encoding="utf-8"))["packets"]]
for pkt in packets:
    for ch in range(40):
        cand = whiten(pkt, ch)
        if cand.startswith(b"flag{") and cand.rstrip(b"\\x00").endswith(b"}"):
            print(cand.rstrip(b"\\x00").decode())
            raise SystemExit
raise AssertionError("no packet de-whitens to a flag")
'''


def _ble_whiten(data, channel):
    lfsr = [1] + [(channel >> i) & 1 for i in range(5, -1, -1)]
    out = bytearray()
    for byte in data:
        b = 0
        for bit in range(8):
            o = lfsr[6]
            b |= (((byte >> bit) & 1) ^ o) << bit
            lfsr = [o] + lfsr[0:6]
            lfsr[4] ^= o
        out.append(b)
    return bytes(out)


def gen_blewhiten(seed, generation, **kw):
    flag_secret = kw.get("flag_secret", "")
    flag = challenge_flag(kind="blewhiten", seed=seed, generation=generation,
                          secret=flag_secret)
    rng = random.Random(f"blewhiten:{flag_secret}:{seed}:{generation}")

    channel = rng.randrange(0, 40)
    plain = flag.encode()
    flag_pkt = _ble_whiten(plain, channel)          # whitening is its own inverse
    packets = [flag_pkt]
    for _ in range(BLE_DECOYS):
        packets.append(bytes(rng.randrange(256) for _ in range(len(plain))))
    rng.shuffle(packets)

    artifacts = {
        "capture.json": json.dumps({
            "link": "BLE advertising channel capture",
            "note": "PDU payloads as transmitted; the capture did not record the channel",
            "packets": [p.hex() for p in packets],
        }, indent=1) + "\n",
        "README.md": (
            "# BLE advertising capture\n\n"
            "`capture.json` holds a run of Bluetooth LE advertising packet payloads "
            "as they went out on the air. The capturing radio did not log which "
            "channel each used. One packet carries a flag; the others are noise.\n\n"
            "Recover the flag (`flag{...}`). Knowing how BLE prepares an advertising "
            "PDU for the air is the way in.\n"),
    }
    return _spec(
        slug=_slug("blewhiten", flag_secret, seed, generation),
        title="BLE Advertising Capture", category="forensics",
        challenge_type="ble-whitening-unknown-channel",
        story=("A run of BLE advertising packets was captured off the air without the "
               "channel each was sent on. One of them carries a flag, the rest are "
               "unrelated traffic."),
        vulnerability=("BLE data whitening is a channel-seeded LFSR and its own inverse; the "
                       "channel is a 40-value search the flag prefix resolves"),
        solution=["re-implement BLE's x^7+x^4+1 whitening LFSR",
                  "for each packet and each channel 0..39, de-whiten",
                  "keep the result that starts with flag{",
                  "that packet's de-whitened payload is the flag"],
        artifacts=artifacts,
        solver_files={"solver.py": _BLE_SOLVER},
        flag=flag, seed=seed, generation=generation, attack_class="blewhiten",
        rank=11, max_runtime_s=60, flag_secret=flag_secret, difficulty="medium")


SIGNALS_BUILDERS = [gen_beacon, gen_blewhiten]
